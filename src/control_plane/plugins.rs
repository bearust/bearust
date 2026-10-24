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
        trust_status: status.trust_status,
    }
}

fn plugin_error(error: PluginError) -> Response {
    let (status, message) = match error {
        PluginError::NotFound => (StatusCode::NOT_FOUND, "Plugin not found"),
        PluginError::Disabled => (StatusCode::CONFLICT, "Plugin is disabled"),
        PluginError::InvalidManifest
        | PluginError::AbiMismatch
        | PluginError::DuplicateId
        | PluginError::MaxPlugins
        | PluginError::SignatureRequired
        | PluginError::MalformedSignature
        | PluginError::InvalidSignature
        | PluginError::KeyMismatch
        | PluginError::KeyRevoked => (StatusCode::BAD_REQUEST, "Invalid plugin"),
        PluginError::Timeout
        | PluginError::FuelExhausted
        | PluginError::MemoryLimit
        | PluginError::Trap => (StatusCode::BAD_GATEWAY, "Plugin health check failed"),
        PluginError::CompileFailed | PluginError::Io | PluginError::TrustStoreUnavailable => (
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

#[derive(serde::Serialize)]
struct RegistryListing {
    index_signed: bool,
    entries: Vec<RegistryListingEntry>,
}

#[derive(serde::Serialize)]
struct RegistryListingEntry {
    id: String,
    display_name: String,
    description: String,
    version: String,
    signed: bool,
    installed_version: Option<String>,
    update_available: bool,
}

/// Index URL and pinned key from `[plugins]`, falling back to the default
/// community index.
fn registry_source(state: &AppState) -> (String, Option<String>) {
    let config = state.plugin_manager.config();
    (
        config
            .registry_url
            .clone()
            .filter(|url| !url.trim().is_empty())
            .unwrap_or_else(|| crate::plugin_registry::DEFAULT_PLUGIN_REGISTRY_URL.to_owned()),
        config.registry_public_key.clone(),
    )
}

fn registry_error(error: crate::plugin_registry::RegistryError) -> Response {
    use crate::plugin_registry::RegistryError;
    let (status, code) = match &error {
        RegistryError::NotFound(_) => (StatusCode::NOT_FOUND, "not_found"),
        RegistryError::AlreadyInstalled(_) => (StatusCode::CONFLICT, "conflict"),
        RegistryError::Revoked(_) => (StatusCode::CONFLICT, "revoked"),
        RegistryError::IndexSignature(_) => (StatusCode::BAD_GATEWAY, "registry_untrusted"),
        RegistryError::ChecksumMismatch
        | RegistryError::MalformedArchive(_)
        | RegistryError::ManifestIdMismatch { .. }
        | RegistryError::SignerKeyMismatch(_) => {
            (StatusCode::BAD_GATEWAY, "registry_package_invalid")
        }
        RegistryError::Io(_) => (StatusCode::SERVICE_UNAVAILABLE, "io_error"),
        RegistryError::Fetch(_) | RegistryError::Parse(_) | RegistryError::ResponseTooLarge => {
            (StatusCode::BAD_GATEWAY, "registry_unavailable")
        }
    };
    // Registry-provided text never reaches the client; codes are stable.
    user_error(status, code, "Plugin registry request failed")
}

fn fetch_index(
    url: &str,
    key: Option<&str>,
) -> Result<
    (
        reqwest::blocking::Client,
        crate::plugin_registry::VerifiedIndex,
    ),
    crate::plugin_registry::RegistryError,
> {
    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| crate::plugin_registry::RegistryError::Fetch(e.to_string()))?;
    let verified = crate::plugin_registry::RegistryIndex::fetch_verified(&client, url, key)?;
    Ok((client, verified))
}

/// `GET /api/plugins/registry?q=`: browse the registry with install state.
pub async fn registry(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Query(query): axum::extract::Query<std::collections::HashMap<String, String>>,
) -> Response {
    if let Err(response) = require_permission(&state, &headers, Permission::PluginsRead).await {
        return response;
    }
    let (url, key) = registry_source(&state);
    let directory = state.plugin_manager.config().directory.clone();
    let search = query.get("q").cloned().unwrap_or_default();
    let listing = tokio::task::spawn_blocking(move || {
        let (_, verified) = fetch_index(&url, key.as_deref())?;
        let _ = crate::plugin_registry::persist_revocations(&directory, &verified);
        let entries = verified
            .index
            .search(&search)
            .into_iter()
            .take(200)
            .map(|entry| {
                let installed = crate::plugin_registry::installed_record(&directory, &entry.id)
                    .map(|record| record.version);
                RegistryListingEntry {
                    update_available: installed
                        .as_deref()
                        .is_some_and(|v| crate::plugin_registry::version_newer(&entry.version, v)),
                    installed_version: installed,
                    id: entry.id.clone(),
                    display_name: entry.display_name.chars().take(200).collect(),
                    description: entry.description.chars().take(500).collect(),
                    version: entry.version.chars().take(64).collect(),
                    signed: entry.signer_public_key.is_some(),
                }
            })
            .collect();
        Ok::<_, crate::plugin_registry::RegistryError>(RegistryListing {
            index_signed: verified.signed,
            entries,
        })
    })
    .await;
    match listing {
        Ok(Ok(listing)) => Json(listing).into_response(),
        Ok(Err(error)) => registry_error(error),
        Err(_) => user_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "registry_unavailable",
            "Plugin registry request failed",
        ),
    }
}

#[derive(serde::Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct InstallRequest {
    /// Replace an installed plugin (upgrade or reinstall).
    #[serde(default)]
    force: bool,
}

/// `POST /api/plugins/registry/{id}/install`: install or upgrade from the
/// registry, then reload plugins (trust pinning happens on that reload).
pub async fn registry_install(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    let actor = match require_permission(&state, &headers, Permission::PluginsManage).await {
        Ok(actor) => actor,
        Err(response) => return response,
    };
    if let Err(response) = validate_id(&id) {
        return response;
    }
    let request = if body.iter().all(u8::is_ascii_whitespace) {
        InstallRequest::default()
    } else {
        match serde_json::from_slice::<InstallRequest>(&body) {
            Ok(request) => request,
            Err(_) => {
                return user_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_input",
                    "Invalid install request",
                )
            }
        }
    };
    let force = request.force;
    let (url, key) = registry_source(&state);
    let directory = state.plugin_manager.config().directory.clone();
    let install_id = id.clone();
    let installed = tokio::task::spawn_blocking(move || {
        let (client, verified) = fetch_index(&url, key.as_deref())?;
        crate::plugin_registry::persist_revocations(&directory, &verified)?;
        let prepared = crate::plugin_registry::prepare_install(&client, &verified, &install_id)?;
        crate::plugin_registry::write_install(&directory, &prepared, force)
    })
    .await;
    let record = match installed {
        Ok(Ok(record)) => record,
        Ok(Err(error)) => {
            audit::record_plugin_state(
                &state,
                Some(actor.id),
                &id,
                "registry_install",
                "failure",
                Some("registry_error"),
            )
            .await;
            return registry_error(error);
        }
        Err(_) => {
            return user_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "registry_unavailable",
                "Plugin registry request failed",
            )
        }
    };
    audit::record_plugin_state(
        &state,
        Some(actor.id),
        &id,
        "registry_install",
        "success",
        None,
    )
    .await;
    let manager = std::sync::Arc::clone(&state.plugin_manager);
    let _ = tokio::task::spawn_blocking(move || manager.reload_from_disk_without_audit()).await;
    state.realtime.publish("plugins.changed");
    Json(serde_json::json!({
        "id": record.id,
        "version": record.version,
        "signed": record.signer.is_some(),
        "index_signed": record.index_signed,
        "plugin": state.plugin_manager.list().into_iter().find(|p| p.id == id).map(plugin_status),
    }))
    .into_response()
}
