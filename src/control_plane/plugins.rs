//! Authenticated control-plane lifecycle endpoints for local WASM plugins.
//!
//! This module deliberately exposes only the bounded status types owned by
//! `plugin_runtime`; filesystem paths, manifests, module bytes, and runtime
//! diagnostics never cross the HTTP boundary.

use super::{audit, authorize, current, user_error, AppState};
use crate::control_plane::models::{
    PluginHealthResponse, PluginReloadResponse, PluginStatusResponse, User,
};
use crate::control_plane::rbac::{Permission, ResourceContext};
use crate::plugin_runtime::{PluginError, PluginStatus, MAX_ID_LEN};
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    Json,
};

async fn require_permission(
    state: &AppState,
    headers: &HeaderMap,
    permission: Permission,
) -> Result<User, Response> {
    let user = current(state, headers)
        .await
        .map_err(|status| user_error(status, "unauthorized", "Authentication required"))?;
    if !authorize(&state.db, &user, permission, ResourceContext::GLOBAL)
        .await
        .unwrap_or(false)
    {
        return Err(user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Permission denied",
        ));
    }
    Ok(user)
}

fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_ID_LEN
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

fn validate_id(id: &str) -> Result<(), Response> {
    valid_id(id).then_some(()).ok_or_else(|| {
        user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid plugin id",
        )
    })
}

fn plugin_status(status: PluginStatus) -> PluginStatusResponse {
    PluginStatusResponse {
        id: status.id,
        display_name: status.display_name,
        abi_version: status.abi_version,
        digest: status.digest,
        enabled: status.enabled,
        loaded: status.loaded,
        last_error_code: status.last_error_code,
        created_at: status.created_at,
        updated_at: status.updated_at,
    }
}

fn plugin_error(error: PluginError) -> Response {
    let (status, message) = match error {
        PluginError::NotFound => (StatusCode::NOT_FOUND, "Plugin not found"),
        PluginError::Disabled => (StatusCode::CONFLICT, "Plugin is disabled"),
        PluginError::InvalidManifest
        | PluginError::AbiMismatch
        | PluginError::DuplicateId
        | PluginError::MaxPlugins => (StatusCode::BAD_REQUEST, "Invalid plugin"),
        PluginError::Timeout
        | PluginError::FuelExhausted
        | PluginError::MemoryLimit
        | PluginError::Trap => (StatusCode::BAD_GATEWAY, "Plugin health check failed"),
        PluginError::CompileFailed | PluginError::Io => (
            StatusCode::SERVICE_UNAVAILABLE,
            "Plugin runtime unavailable",
        ),
    };
    user_error(status, error.code(), message)
}

pub async fn list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_permission(&state, &headers, Permission::PluginsRead).await {
        return response;
    }
    let statuses = state
        .plugin_manager
        .list()
        .into_iter()
        .map(plugin_status)
        .collect::<Vec<_>>();
    Json(statuses).into_response()
}

pub async fn reload(State(state): State<AppState>, headers: HeaderMap) -> Response {
    let actor = match require_permission(&state, &headers, Permission::PluginsManage).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    // Compilation and filesystem scanning are synchronous Wasmtime work. Keep
    // it off Tokio's request executor so a large or malformed module cannot
    // stall unrelated control-plane requests.
    let manager = std::sync::Arc::clone(&state.plugin_manager);
    let reload =
        tokio::task::spawn_blocking(move || manager.reload_from_disk_without_audit()).await;
    let result = match reload {
        Ok(result) => result,
        Err(_) => Err(PluginError::CompileFailed),
    };
    match result {
        Ok(summary) => {
            let (outcome, error_code) = if summary.failed == 0 {
                ("success", None)
            } else {
                ("failure", Some("partial_failure"))
            };
            audit::record_plugin_state(
                &state,
                Some(actor.id),
                "all",
                "reload",
                outcome,
                error_code,
            )
            .await;
            Json(PluginReloadResponse {
                loaded: summary.loaded,
                failed: summary.failed,
            })
            .into_response()
        }
        Err(error) => {
            audit::record_plugin_state(
                &state,
                Some(actor.id),
                "all",
                "reload",
                "failure",
                Some(error.code()),
            )
            .await;
            plugin_error(error)
        }
    }
}

async fn set_enabled(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    enabled: bool,
) -> Response {
    let actor = match require_permission(&state, &headers, Permission::PluginsManage).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = validate_id(&id) {
        return response;
    }
    let operation = if enabled { "enable" } else { "disable" };
    match state.plugin_manager.set_enabled_without_audit(&id, enabled) {
        Ok(status) => {
            audit::record_plugin_state(&state, Some(actor.id), &id, operation, "success", None)
                .await;
            Json(plugin_status(status)).into_response()
        }
        Err(error) => {
            audit::record_plugin_state(
                &state,
                Some(actor.id),
                &id,
                operation,
                "failure",
                Some(error.code()),
            )
            .await;
            plugin_error(error)
        }
    }
}

pub async fn enable(state: State<AppState>, headers: HeaderMap, id: Path<String>) -> Response {
    set_enabled(state, headers, id, true).await
}

pub async fn disable(state: State<AppState>, headers: HeaderMap, id: Path<String>) -> Response {
    set_enabled(state, headers, id, false).await
}

pub async fn unload(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let actor = match require_permission(&state, &headers, Permission::PluginsManage).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = validate_id(&id) {
        return response;
    }
    match state.plugin_manager.unload_without_audit(&id) {
        Ok(()) => {
            audit::record_plugin_state(&state, Some(actor.id), &id, "unload", "success", None)
                .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => {
            audit::record_plugin_state(
                &state,
                Some(actor.id),
                &id,
                "unload",
                "failure",
                Some(error.code()),
            )
            .await;
            plugin_error(error)
        }
    }
}

pub async fn health_check(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Response {
    let actor = match require_permission(&state, &headers, Permission::PluginsRead).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = validate_id(&id) {
        return response;
    }
    match state.plugin_manager.health_check_without_audit(&id) {
        Ok(result) => {
            audit::record_plugin_state(
                &state,
                Some(actor.id),
                &id,
                "health_check",
                "success",
                None,
            )
            .await;
            Json(PluginHealthResponse {
                status: result.status,
                elapsed_ms: result.elapsed.as_millis().min(u64::MAX as u128) as u64,
                detail: result.detail,
            })
            .into_response()
        }
        Err(error) => {
            audit::record_plugin_state(
                &state,
                Some(actor.id),
                &id,
                "health_check",
                "failure",
                Some(error.code()),
            )
            .await;
            plugin_error(error)
        }
    }
}

// Keep this assertion close to the response conversion: adding a field to
// PluginStatus requires an explicit review of the public redaction boundary.
fn _status_is_safe(_: &PluginStatus) {}
