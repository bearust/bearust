//! Machine access for a managing control plane (for example Bearust Cloud).
//!
//! * API tokens: `Authorization: Bearer brt_…`, stored as a hash, acting as
//!   the user who created them and narrowed by scope. Tokens can never manage
//!   tokens, users, roles, setup, sign-in, or plugins.
//! * Desired state: `PUT /api/desired-state` replaces the whole routing
//!   document (pools and routes) in one validated runtime swap, guarded by a
//!   strictly increasing generation so a delayed push cannot roll back a node.
//!   The same document carries managed certificates and HTTP-01 challenges
//!   (see `managed_certs`).

use super::models::{
    ApiTokenScope, CreateApiTokenRequest, CreatedApiToken, DesiredStateRequest, DesiredStateStatus,
    ErrorEnvelope,
};
use super::rbac::{authorize, Permission, ResourceContext};
use super::{audit, auth, commit_runtime_config, current, repository, user_error, AppState};
use axum::{
    body::Body,
    extract::{Path, State},
    http::{header, HeaderMap, Method, Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
    Json,
};
use std::sync::OnceLock;
use tokio::sync::Mutex;
use uuid::Uuid;

/// Prefix of pools and routes materialized from dashboard proxy hosts. The
/// desired-state document must not touch them.
const PROXY_HOST_PREFIX: &str = "proxy-host-";
const TOKEN_PREFIX: &str = "brt_";

/// Bearer token from `Authorization`, only when it looks like an API token.
pub(crate) fn bearer(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let token = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))?
        .trim();
    token.starts_with(TOKEN_PREFIX).then_some(token)
}

fn has_session_cookie(headers: &HeaderMap) -> bool {
    auth::cookie(headers).is_some()
}

/// Paths a token may never reach, whatever its scope.
fn token_forbidden_path(method: &Method, path: &str) -> bool {
    const ALWAYS: [&str; 6] = [
        "/api/api-tokens",
        "/api/users",
        "/api/roles",
        "/api/setup",
        "/api/auth",
        "/api/sso",
    ];
    if ALWAYS
        .iter()
        .any(|prefix| path == *prefix || path.starts_with(&format!("{prefix}/")))
    {
        return true;
    }
    // Installing or enabling plugins runs code on the node.
    (path == "/api/plugins" || path.starts_with("/api/plugins/")) && is_mutating(method)
}

fn is_mutating(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Enforce API token validity and scope before any handler runs. Requests
/// with a session cookie are left to the cookie flow.
pub(crate) async fn api_token_guard(
    State(state): State<AppState>,
    request: Request<Body>,
    next: Next,
) -> Response {
    let headers = request.headers();
    if has_session_cookie(headers) || !request.uri().path().starts_with("/api/") {
        return next.run(request).await;
    }
    let Some(token) = bearer(headers) else {
        return next.run(request).await;
    };
    let scope = match repository::find_user_by_api_token(&state.db, &auth::token_hash(token)).await
    {
        Ok(Some((_, scope))) => scope,
        Ok(None) => {
            return user_error(
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "API token is invalid or revoked",
            )
        }
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Unable to verify API token",
            )
        }
    };
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    if token_forbidden_path(&method, &path) {
        return user_error(
            StatusCode::FORBIDDEN,
            "token_forbidden",
            "API tokens cannot use this endpoint",
        );
    }
    if scope == ApiTokenScope::Read && is_mutating(&method) {
        return user_error(
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "This API token is read-only",
        );
    }
    next.run(request).await
}

/// Token management requires a browser session of a system administrator,
/// so a leaked token cannot mint more tokens.
async fn require_token_admin(s: &AppState, h: &HeaderMap) -> Result<super::models::User, Response> {
    if !has_session_cookie(h) {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    }
    let user = current(s, h).await.map_err(IntoResponse::into_response)?;
    if !authorize(
        &s.db,
        &user,
        Permission::SystemSettingsManage,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(s, Some(user.id), "authorization_denied", "ApiTokens").await;
        return Err(user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Administrator access required",
        ));
    }
    Ok(user)
}

pub(crate) async fn list_api_tokens(State(s): State<AppState>, h: HeaderMap) -> Response {
    if let Err(response) = require_token_admin(&s, &h).await {
        return response;
    }
    match repository::list_api_tokens(&s.db).await {
        Ok(tokens) => Json(tokens).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to list API tokens",
        ),
    }
}

pub(crate) async fn create_api_token(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(request): Json<CreateApiTokenRequest>,
) -> Response {
    let user = match require_token_admin(&s, &h).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let name = request.name.trim();
    if name.is_empty() || name.chars().count() > 120 {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_name",
            "Token name must be 1-120 characters",
        );
    }
    let secret = format!(
        "{TOKEN_PREFIX}{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    );
    match repository::create_api_token(
        &s.db,
        user.id,
        name,
        request.scope,
        &auth::token_hash(&secret),
    )
    .await
    {
        Ok(token) => {
            audit::record_state(
                &s,
                Some(user.id),
                "api_token_created",
                &format!("token_id={};scope={}", token.id, token.scope.as_str()),
            )
            .await;
            (StatusCode::CREATED, Json(CreatedApiToken { token, secret })).into_response()
        }
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to create API token",
        ),
    }
}

pub(crate) async fn revoke_api_token(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let user = match require_token_admin(&s, &h).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    match repository::revoke_api_token(&s.db, id).await {
        Ok(true) => {
            audit::record_state(
                &s,
                Some(user.id),
                "api_token_revoked",
                &format!("token_id={id}"),
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(false) => user_error(StatusCode::NOT_FOUND, "not_found", "API token not found"),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to revoke API token",
        ),
    }
}

async fn require_proxy_permission(
    s: &AppState,
    h: &HeaderMap,
    permission: Permission,
) -> Result<super::models::User, Response> {
    let user = current(s, h).await.map_err(IntoResponse::into_response)?;
    if !authorize(&s.db, &user, permission, ResourceContext::GLOBAL)
        .await
        .unwrap_or(false)
    {
        audit::record_state(s, Some(user.id), "authorization_denied", "DesiredState").await;
        return Err(StatusCode::FORBIDDEN.into_response());
    }
    Ok(user)
}

pub(crate) async fn get_desired_state(State(s): State<AppState>, h: HeaderMap) -> Response {
    if let Err(response) = require_proxy_permission(&s, &h, Permission::ProxyHostsRead).await {
        return response;
    }
    match repository::get_desired_state(&s.db).await {
        Ok(status) => Json(status).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to read desired state",
        ),
    }
}

/// Per-host usage counters for the hosts of the desired state (routes not
/// materialized from dashboard proxy hosts). Read scope is enough; the boot
/// id lets the poller detect counter resets.
pub(crate) async fn get_usage(State(s): State<AppState>, h: HeaderMap) -> Response {
    if let Err(response) = require_proxy_permission(&s, &h, Permission::ProxyHostsRead).await {
        return response;
    }
    let Some(runtime) = s.runtime.as_ref() else {
        return user_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
            "The live data-plane runtime is not attached",
        );
    };
    let snapshot = runtime.load();
    let hosts = desired_state_hosts(&snapshot.config().routes);
    Json(crate::metering::global().report(hosts)).into_response()
}

fn desired_state_hosts(routes: &[crate::config::RouteConfig]) -> impl Iterator<Item = &str> {
    routes
        .iter()
        .filter(|route| !route.name.starts_with(PROXY_HOST_PREFIX))
        .map(|route| route.host.as_str())
}

/// Serializes desired-state applies on this node so the generation check and
/// the runtime swap cannot interleave.
fn apply_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

pub(crate) async fn put_desired_state(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(request): Json<DesiredStateRequest>,
) -> Response {
    let user = match require_proxy_permission(&s, &h, Permission::ProxyHostsWrite).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(runtime) = s.runtime.as_ref() else {
        return user_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "runtime_unavailable",
            "The live data-plane runtime is not attached",
        );
    };
    if request.generation < 1 {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_generation",
            "Generation must be a positive integer",
        );
    }
    if request
        .pools
        .iter()
        .map(|pool| pool.name.as_str())
        .chain(request.routes.iter().map(|route| route.name.as_str()))
        .any(|name| name.starts_with(PROXY_HOST_PREFIX))
    {
        return user_error(
            StatusCode::BAD_REQUEST,
            "reserved_name",
            "Pool and route names starting with proxy-host- are reserved for dashboard proxy hosts",
        );
    }

    let _guard = apply_lock().lock().await;
    let stored = match repository::get_desired_state(&s.db).await {
        Ok(status) => status,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Unable to read desired state",
            )
        }
    };
    if request.generation <= stored.generation {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({
                "code": "stale_generation",
                "message": "A newer or equal generation is already applied",
                "generation": stored.generation,
            })),
        )
            .into_response();
    }

    let previous = runtime.load().config().clone();
    let mut next = previous.clone();
    next.upstream_pools = previous
        .upstream_pools
        .iter()
        .filter(|pool| pool.name.starts_with(PROXY_HOST_PREFIX))
        .cloned()
        .chain(request.pools.iter().cloned())
        .collect();
    next.routes = previous
        .routes
        .iter()
        .filter(|route| route.name.starts_with(PROXY_HOST_PREFIX))
        .cloned()
        .chain(request.routes.iter().cloned())
        .collect();
    if let Err(error) = next.validate() {
        audit::record_state(
            &s,
            Some(user.id),
            "desired_state_update_denied",
            "reason=invalid_config",
        )
        .await;
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorEnvelope {
                code: "invalid_desired_state".into(),
                message: error.to_string(),
            }),
        )
            .into_response();
    }
    if let Err(message) =
        super::managed_certs::validate(&request.certificates, &request.acme_challenges)
    {
        audit::record_state(
            &s,
            Some(user.id),
            "desired_state_update_denied",
            "reason=invalid_certificates",
        )
        .await;
        return user_error(StatusCode::BAD_REQUEST, "invalid_desired_state", &message);
    }
    // Certificates first, so new routes are served with their certificate
    // from the first request.
    if let Err(message) = super::managed_certs::apply_certificates(&s, &request.certificates).await
    {
        tracing::warn!(event = "desired_state_certificates_failed", error = %message);
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "certificate_store_error",
            "Unable to store managed certificates",
        );
    }
    if let Err(message) = super::managed_certs::apply_challenges(&s, &request.acme_challenges) {
        return user_error(StatusCode::BAD_REQUEST, "invalid_desired_state", &message);
    }
    if let Err(response) = commit_runtime_config(&s, &user, &next, "desired_state").await {
        return response;
    }
    let applied_at = chrono::Utc::now().to_rfc3339();
    if repository::set_desired_state_generation(&s.db, request.generation, &applied_at)
        .await
        .is_err()
    {
        // The config is live; the caller retries with the same generation,
        // which re-applies the identical document.
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Configuration applied but its generation could not be recorded",
        );
    }
    audit::record_state(
        &s,
        Some(user.id),
        "desired_state_applied",
        &format!(
            "generation={};pool_count={};route_count={};certificate_count={};challenge_count={}",
            request.generation,
            request.pools.len(),
            request.routes.len(),
            request.certificates.len(),
            request.acme_challenges.len()
        ),
    )
    .await;
    Json(DesiredStateStatus {
        generation: request.generation,
        applied_at: Some(applied_at),
    })
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_only_accepts_api_tokens() {
        let mut headers = HeaderMap::new();
        headers.insert(header::AUTHORIZATION, "Bearer brt_abc".parse().unwrap());
        assert_eq!(bearer(&headers), Some("brt_abc"));
        headers.insert(header::AUTHORIZATION, "Bearer eyJhbGciOi".parse().unwrap());
        assert_eq!(bearer(&headers), None);
        headers.insert(header::AUTHORIZATION, "Basic brt_abc".parse().unwrap());
        assert_eq!(bearer(&headers), None);
    }

    #[test]
    fn tokens_cannot_reach_identity_or_plugin_management() {
        for path in [
            "/api/api-tokens",
            "/api/api-tokens/5",
            "/api/users",
            "/api/roles/2",
            "/api/setup/initialize",
            "/api/auth/me",
        ] {
            assert!(token_forbidden_path(&Method::GET, path), "{path}");
        }
        assert!(token_forbidden_path(&Method::POST, "/api/plugins"));
        assert!(!token_forbidden_path(&Method::GET, "/api/plugins"));
        assert!(!token_forbidden_path(&Method::PUT, "/api/desired-state"));
        assert!(!token_forbidden_path(&Method::GET, "/api/usersettings"));
    }
}
