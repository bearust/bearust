pub mod audit;
pub mod auth;
pub mod models;
pub mod rbac;
pub mod repository;
pub mod realtime;
use crate::acme::{AcmeEnvironment, AcmeManager, LetsEncryptClient};
use crate::certificates::{
    AcmeService as CertificateAcmeService, AcmeServiceError as CertificateAcmeError,
    CertificateStore,
};
use crate::secrets::SecretStore;
use async_trait::async_trait;
use axum::{
    extract::DefaultBodyLimit,
    extract::{rejection::{JsonRejection, PathRejection}, Multipart, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response, sse::{Event, KeepAlive, Sse}},
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::stream::unfold;
use std::convert::Infallible;
use models::*;
use rbac::{authorize, Permission, ResourceContext, Role};
use std::sync::Arc;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use tower_http::services::ServeDir;
use uuid::Uuid;

#[derive(Clone)]
pub struct AppState {
    pub db: repository::DbPool,
    pub certificates: Arc<CertificateStore>,
    pub reloader: Arc<dyn ConfigReloader>,
    pub setup_token: Arc<str>,
    pub auth_attempts: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
    pub secrets: SecretStore,
    pub acme: Arc<dyn AcmeService>,
    pub realtime: Arc<realtime::RealtimeHub>,
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeServiceError {
    #[error("ACME operation is busy")]
    Busy,
    #[error("ACME operation failed")]
    Failed,
}
#[derive(Clone, Debug)]
pub struct AcmeJob {
    pub job_id: String,
    pub certificate_id: i64,
}
#[async_trait]
pub trait AcmeService: Send + Sync {
    async fn issue(
        &self,
        request: AcmeRequest,
        cloudflare_token: Option<Vec<u8>>,
        certificate_id: i64,
    ) -> Result<AcmeJob, AcmeServiceError>;
    async fn renew(&self, certificate_id: i64) -> Result<AcmeJob, AcmeServiceError>;
}
pub struct NoopAcmeService;
#[async_trait]
impl AcmeService for NoopAcmeService {
    async fn issue(
        &self,
        _: AcmeRequest,
        _: Option<Vec<u8>>,
        certificate_id: i64,
    ) -> Result<AcmeJob, AcmeServiceError> {
        Ok(AcmeJob {
            job_id: Uuid::new_v4().to_string(),
            certificate_id,
        })
    }
    async fn renew(&self, certificate_id: i64) -> Result<AcmeJob, AcmeServiceError> {
        Ok(AcmeJob {
            job_id: Uuid::new_v4().to_string(),
            certificate_id,
        })
    }
}

/// Adapter exposing the certificate lifecycle service to control-plane
/// handlers.  The lifecycle service owns persistence, locking, issuance and
/// activation; this thin adapter only translates the control-plane job
/// envelope and error type.
pub struct CertificateAcmeAdapter {
    service: Arc<CertificateAcmeService>,
}

impl CertificateAcmeAdapter {
    pub fn new(service: Arc<CertificateAcmeService>) -> Self {
        Self { service }
    }
}

#[async_trait]
impl AcmeService for CertificateAcmeAdapter {
    async fn issue(
        &self,
        request: AcmeRequest,
        cloudflare_token: Option<Vec<u8>>,
        _certificate_id: i64,
    ) -> Result<AcmeJob, AcmeServiceError> {
        // The certificate service creates the durable certificate record only
        // after material has been validated.  Control-plane callers receive
        // its resulting id in the job envelope.
        let status = self
            .service
            .issue(0, request, cloudflare_token)
            .await
            .map_err(map_acme_error)?;
        Ok(AcmeJob {
            job_id: Uuid::new_v4().to_string(),
            certificate_id: status.certificate_id,
        })
    }

    async fn renew(&self, certificate_id: i64) -> Result<AcmeJob, AcmeServiceError> {
        let status = self
            .service
            .renew(None, certificate_id)
            .await
            .map_err(map_acme_error)?;
        Ok(AcmeJob {
            job_id: Uuid::new_v4().to_string(),
            certificate_id: status.certificate_id,
        })
    }
}

fn map_acme_error(error: CertificateAcmeError) -> AcmeServiceError {
    match error {
        CertificateAcmeError::Busy => AcmeServiceError::Busy,
        _ => AcmeServiceError::Failed,
    }
}
#[derive(Debug, thiserror::Error)]
pub enum ReloadError {
    #[error("reload failed: {0}")]
    Failed(String),
}
#[async_trait]
pub trait ConfigReloader: Send + Sync {
    async fn apply(&self, desired: DesiredConfig) -> Result<(), ReloadError>;
    async fn apply_certificate_change(&self, _certificate_id: i64) -> Result<(), ReloadError> {
        Ok(())
    }
}
pub struct NoopReloader;
#[async_trait]
impl ConfigReloader for NoopReloader {
    async fn apply(&self, _: DesiredConfig) -> Result<(), ReloadError> {
        Ok(())
    }
}
pub async fn build_state(
    database_url: &str,
    certificate_root: &std::path::Path,
    setup_token: impl Into<Arc<str>>,
) -> Result<AppState, sqlx::Error> {
    if let Some(path) = database_url.strip_prefix("sqlite://") {
        if let Some(parent) = std::path::Path::new(path).parent() {
            std::fs::create_dir_all(parent).map_err(sqlx::Error::Io)?;
        }
    }
    let db = repository::connect(database_url).await?;
    repository::migrate(&db).await?;
    let certificates = CertificateStore::new(certificate_root)
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let certificates = Arc::new(certificates);
    let secrets = SecretStore::open(&certificate_root.join("secrets"))
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let reloader: Arc<dyn ConfigReloader> = Arc::new(NoopReloader);
    // The production control-plane path uses the real ACME client.  The
    // client is lazy with respect to network calls, so startup remains
    // deterministic even when the CA is unavailable; issuance errors are
    // surfaced through the authenticated API.
    let client = LetsEncryptClient::new(
        AcmeEnvironment::Production,
        secrets.clone(),
        reqwest::Client::new(),
    )
    .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let manager = AcmeManager::with_transport(certificates.as_ref().clone(), Arc::new(client));
    let certificate_acme = Arc::new(CertificateAcmeService::new(
        db.clone(),
        certificates.clone(),
        Arc::new(manager),
        reloader.clone(),
        secrets.clone(),
    ));
    let realtime = Arc::new(realtime::RealtimeHub::new(256));
    certificate_acme.attach_realtime(realtime.clone());
    Ok(AppState {
        db,
        certificates,
        reloader,
        setup_token: setup_token.into(),
        auth_attempts: Arc::new(Mutex::new(HashMap::new())),
        secrets,
        acme: Arc::new(CertificateAcmeAdapter::new(certificate_acme)),
        realtime,
    })
}

/// Construct control-plane state with an explicitly configured ACME service.
/// `build_state` remains deterministic for tests and embedded users; the
/// production bootstrap can create a certificate service and pass it here.
pub async fn build_state_with_acme(
    database_url: &str,
    certificate_root: &std::path::Path,
    setup_token: impl Into<Arc<str>>,
    certificate_acme: Arc<CertificateAcmeService>,
) -> Result<AppState, sqlx::Error> {
    let mut state = build_state(database_url, certificate_root, setup_token).await?;
    certificate_acme.attach_realtime(state.realtime.clone());
    state.acme = Arc::new(CertificateAcmeAdapter::new(certificate_acme));
    Ok(state)
}

pub async fn allow_auth_attempt(state: &AppState, key: &str) -> bool {
    let mut attempts = state.auth_attempts.lock().await;
    let entry = attempts
        .entry(key.to_owned())
        .or_insert((Instant::now(), 0));
    if entry.0.elapsed() > Duration::from_secs(900) {
        *entry = (Instant::now(), 0);
    }
    entry.1 += 1;
    entry.1 <= 10
}
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/api/health", get(health))
        .route("/api/setup/status", get(setup_status))
        .route("/api/setup/initialize", post(setup_initialize))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/auth/me", get(me))
        .route("/api/events", get(events))
        .route("/api/audit-logs", get(list_audit_logs))
        .route("/api/users", get(list_users).post(create_user))
        .route("/api/users/{id}", axum::routing::patch(update_user).delete(delete_user))
        .route("/api/roles", get(list_roles).post(create_role))
        .route("/api/roles/{id}", get(get_role).patch(update_role).delete(delete_role))
        .route("/api/users/{id}/sessions/revoke", post(revoke_user_sessions))
        .route("/api/proxy-hosts", get(list_hosts).post(create_host))
        .route(
            "/api/proxy-hosts/{id}",
            get(get_host).patch(update_host).delete(remove_host),
        )
        .route(
            "/api/certificates",
            get(list_certificates).post(upload_certificate),
        )
        .route(
            "/api/certificates/{id}/activate",
            post(activate_certificate),
        )
        .route("/api/certificates/acme", post(issue_acme))
        .route("/api/certificates/{id}/renew", post(renew_acme))
        .route("/api/certificates/{id}/status", get(acme_status))
        .layer(DefaultBodyLimit::max(3 * 1024 * 1024))
        .with_state(state)
        .fallback_service(ServeDir::new("/usr/share/bearust/frontend"))
}

fn user_error(status: StatusCode, code: &str, message: &str) -> axum::response::Response {
    (
        status,
        Json(ErrorEnvelope { code: code.into(), message: message.into() }),
    ).into_response()
}

fn user_audit(target: Option<i64>, reason: &str) -> String {
    match target {
        Some(id) => format!("target_user_id={id};reason={reason}"),
        None => format!("target=redacted;reason={reason}"),
    }
}

async fn role_slug_exists(s: &AppState, role: &str) -> Result<bool, sqlx::Error> {
    Ok(Role::parse(role).is_some() || repository::role_by_slug(&s.db, role).await?.is_some())
}

async fn require_user_admin(s: &AppState, h: &HeaderMap) -> Result<User, axum::response::Response> {
    let user = current(s, h).await.map_err(|status| status.into_response())?;
    if !authorize(&s.db, &user, Permission::UsersManage, ResourceContext::GLOBAL).await.unwrap_or(false) {
        audit::record_state(&s, Some(user.id), "user_mutation_denied", &user_audit(None, "authorization")).await;
        return Err(user_error(StatusCode::FORBIDDEN, "forbidden", "Administrator access required"));
    }
    Ok(user)
}

async fn list_users(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    if let Err(response) = require_user_admin(&s, &h).await { return response; }
    match repository::list_users(&s.db).await {
        Ok(users) => Json(users).into_response(),
        Err(_) => user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable"),
    }
}

fn role_audit(role: &RoleDetail, before: Option<&[String]>, after: Option<&[String]>) -> String {
    serde_json::json!({"role_id": role.id, "slug": role.slug, "before": before.map(|x| x.to_vec()), "after": after.map(|x| x.to_vec()), "scopes": role.scopes}).to_string()
}

fn role_scope_audit(role: &RoleDetail) -> String {
    let read_assignments = role.scopes.iter().find(|scope| scope.permission == "proxy_hosts.read").map_or(0, |scope| scope.proxy_host_ids.len());
    let write_assignments = role.scopes.iter().find(|scope| scope.permission == "proxy_hosts.write").map_or(0, |scope| scope.proxy_host_ids.len());
    serde_json::json!({"role_id": role.id, "read_assignments": read_assignments, "write_assignments": write_assignments}).to_string()
}

fn role_scope_error(error: &sqlx::Error) -> Option<StatusCode> {
    let message = error.to_string().to_ascii_lowercase();
    (message.contains("invalid role scope") || message.contains("duplicate") || message.contains("unknown proxy host") || message.contains("invalid permission")).then_some(StatusCode::BAD_REQUEST)
}

async fn require_role_admin(s: &AppState, h: &HeaderMap) -> Result<User, axum::response::Response> {
    let user = current(s, h).await.map_err(|status| user_error(status, "unauthorized", "Authentication required"))?;
    if !authorize(&s.db, &user, Permission::RolesManage, ResourceContext::GLOBAL).await.unwrap_or(false) {
        audit::record_state(&s, Some(user.id), "role_mutation_denied", "authorization").await;
        return Err(user_error(StatusCode::FORBIDDEN, "forbidden", "Administrator access required"));
    }
    Ok(user)
}

fn normalize_role_slug(raw: &str) -> Option<String> {
    let slug = raw.trim().to_ascii_lowercase().chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '-' }).collect::<String>();
    let slug = slug.split('-').filter(|part| !part.is_empty()).collect::<Vec<_>>().join("-");
    (!slug.is_empty() && slug.len() <= 64).then_some(slug)
}

fn validate_role_input(name: &str, permissions: &[String]) -> Result<(), ()> {
    if name.trim().is_empty() || permissions.iter().any(|key| !matches!(key.as_str(), "proxy_hosts.read" | "proxy_hosts.write" | "certificates.read" | "certificates.write" | "users.manage" | "roles.manage" | "audit_logs.read" | "audit_logs.export" | "system.settings.manage" | "sessions.revoke")) { return Err(()); }
    Ok(())
}

async fn list_roles(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    let _actor = match require_role_admin(&s, &h).await { Ok(u) => u, Err(response) => return response };
    match repository::list_roles(&s.db).await { Ok(roles) => Json(roles).into_response(), Err(_) => user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable") }
}

async fn get_role(State(s): State<AppState>, h: HeaderMap, path: Result<Path<i64>, PathRejection>) -> impl IntoResponse {
    let _actor = match require_role_admin(&s, &h).await { Ok(u) => u, Err(response) => return response };
    let Path(id) = match path { Ok(path) => path, Err(_) => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role id") };
    match repository::get_role(&s.db, id).await { Ok(Some(role)) => Json(role).into_response(), Ok(None) => user_error(StatusCode::NOT_FOUND, "not_found", "Role not found"), Err(_) => user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable") }
}

async fn create_role(State(s): State<AppState>, h: HeaderMap, input: Result<Json<RoleCreate>, JsonRejection>) -> impl IntoResponse {
    let actor = match require_role_admin(&s, &h).await { Ok(u) => u, Err(response) => return response };
    let input = match input { Ok(Json(input)) => input, Err(_) => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", "reason=invalid_input").await; return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role request"); } };
    let Some(slug) = normalize_role_slug(&input.slug) else { audit::record_state(&s, Some(actor.id), "role_mutation_denied", "reason=invalid_slug").await; return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role slug"); };
    if validate_role_input(&input.name, &input.permissions).is_err() { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &format!("slug={slug};reason=invalid_input")).await; return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role name or permission"); }
    let keys = input.permissions.iter().map(String::as_str).collect::<Vec<_>>();
    let role = match repository::insert_role_with_permissions_and_scopes(&s.db, &slug, input.name.trim(), input.description.trim(), &keys, &input.scopes).await { Ok(role) => role, Err(error) if error.to_string().to_ascii_lowercase().contains("unique") => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &format!("slug={slug};reason=duplicate")).await; return user_error(StatusCode::CONFLICT, "conflict", "Role slug already exists") }, Err(error) if role_scope_error(&error).is_some() => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &format!("slug={slug};reason=invalid_scope")).await; return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role scope") }, Err(_) => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &format!("slug={slug};reason=database_error")).await; return user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable") } };
    let details = role_audit(&role, None, Some(&role.permissions));
    audit::record_state(&s, Some(actor.id), "role_created", &details).await;
    audit::record_state(&s, Some(actor.id), "role_permissions_changed", &details).await;
    if !role.scopes.is_empty() { audit::record_state(&s, Some(actor.id), "role_scopes_changed", &role_scope_audit(&role)).await; }
    s.realtime.publish("roles.changed");
    (StatusCode::CREATED, Json(role)).into_response()
}

async fn update_role(State(s): State<AppState>, h: HeaderMap, path: Result<Path<i64>, PathRejection>, input: Result<Json<RolePatch>, JsonRejection>) -> impl IntoResponse {
    let actor = match require_role_admin(&s, &h).await { Ok(u) => u, Err(response) => return response };
    let Path(id) = match path { Ok(path) => path, Err(_) => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", "reason=invalid_input").await; return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role id"); } };
    let Some(before) = (match repository::get_role(&s.db, id).await { Ok(role) => role, Err(_) => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &format!("role_id={id};reason=database_error")).await; return user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable"); } }) else { audit::record_state(&s, Some(actor.id), &"role_mutation_denied", &format!("role_id={id};reason=not_found")).await; return user_error(StatusCode::NOT_FOUND, "not_found", "Role not found"); };
    if before.system_managed { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &role_audit(&before, None, None)).await; return user_error(StatusCode::CONFLICT, "conflict", "Built-in roles cannot be mutated"); }
    let input = match input { Ok(Json(input)) => input, Err(_) => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &role_audit(&before, None, None)).await; return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role request"); } };
    if input.name.as_deref().is_some_and(|name| name.trim().is_empty()) || input.permissions.as_ref().is_some_and(|permissions| validate_role_input("valid", permissions).is_err()) { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &role_audit(&before, None, None)).await; return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role update"); }
    let keys = input.permissions.as_ref().map(|permissions| permissions.iter().map(String::as_str).collect::<Vec<_>>());
    let updated = match repository::update_role_with_permissions_and_scopes(&s.db, id, input.name.as_deref().map(str::trim), input.description.as_deref().map(str::trim), keys.as_deref(), input.scopes.as_deref()).await { Ok(Some(role)) => role, Ok(None) => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &format!("role_id={id};reason=not_found")).await; return user_error(StatusCode::NOT_FOUND, "not_found", "Role not found") }, Err(error) if role_scope_error(&error).is_some() => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &role_audit(&before, None, None)).await; return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role scope") }, Err(_) => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &role_audit(&before, None, None)).await; return user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable") } };
    let details = role_audit(&updated, Some(&before.permissions), Some(&updated.permissions));
    audit::record_state(&s, Some(actor.id), "role_updated", &details).await;
    if input.permissions.is_some() { audit::record_state(&s, Some(actor.id), "role_permissions_changed", &details).await; }
    if input.scopes.is_some() { audit::record_state(&s, Some(actor.id), "role_scopes_changed", &role_scope_audit(&updated)).await; }
    s.realtime.publish("roles.changed");
    if input.permissions.is_some() { s.realtime.publish("sessions.changed"); }
    Json(updated).into_response()
}

async fn delete_role(State(s): State<AppState>, h: HeaderMap, path: Result<Path<i64>, PathRejection>) -> impl IntoResponse {
    let actor = match require_role_admin(&s, &h).await { Ok(u) => u, Err(response) => return response };
    let Path(id) = match path { Ok(path) => path, Err(_) => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", "reason=invalid_input").await; return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role id"); } };
    let Some(role) = (match repository::get_role(&s.db, id).await { Ok(role) => role, Err(_) => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &format!("role_id={id};reason=database_error")).await; return user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable"); } }) else { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &format!("role_id={id};reason=not_found")).await; return user_error(StatusCode::NOT_FOUND, "not_found", "Role not found"); };
    if role.system_managed { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &role_audit(&role, None, None)).await; return user_error(StatusCode::CONFLICT, "conflict", "Built-in roles cannot be deleted"); }
    match repository::delete_role(&s.db, id).await { Ok(1) => { audit::record_state(&s, Some(actor.id), "role_deleted", &role_audit(&role, Some(&role.permissions), None)).await; s.realtime.publish("roles.changed"); StatusCode::NO_CONTENT.into_response() }, Ok(count) if count == 0 || count > 1 => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &role_audit(&role, None, None)).await; user_error(StatusCode::NOT_FOUND, "not_found", "Role not found") }, Ok(_) => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &role_audit(&role, None, None)).await; user_error(StatusCode::NOT_FOUND, "not_found", "Role not found") }, Err(error) if error.to_string().contains("assigned") => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &role_audit(&role, Some(&role.permissions), None)).await; user_error(StatusCode::CONFLICT, "conflict", "Role is assigned to users") }, Err(_) => { audit::record_state(&s, Some(actor.id), "role_mutation_denied", &role_audit(&role, Some(&role.permissions), None)).await; user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable") } }
}


async fn create_user(
    State(s): State<AppState>, h: HeaderMap, Json(input): Json<UserCreate>,
) -> impl IntoResponse {
    let actor = match require_user_admin(&s, &h).await { Ok(u) => u, Err(response) => return response };
    let email = input.email.trim().to_ascii_lowercase();
    let role = input.role.trim();
    if !email.contains('@') || input.password.len() < 12 || !role_slug_exists(&s, role).await.unwrap_or(false) {
        audit::record_state(&s, Some(actor.id), "user_create_denied", &user_audit(None, "invalid_input")).await;
        return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Valid email, role, and password of at least 12 characters required");
    }
    let hash = match auth::hash_password(&input.password) {
        Ok(hash) => hash,
        Err(_) => { audit::record_state(&s, Some(actor.id), "user_create_failed", &user_audit(None, "hashing_error")).await; return user_error(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", "Unable to create user"); }
    };
    match repository::insert_user(&s.db, &email, &hash, role).await {
        Ok(user) => {
            audit::record_state(&s, Some(actor.id), "user_created", &user_audit(Some(user.id), "success")).await;
            s.realtime.publish("users.changed");
            (StatusCode::CREATED, Json(user)).into_response()
        }
        Err(error) if error.to_string().to_ascii_lowercase().contains("unique") => {
            audit::record_state(&s, Some(actor.id), "user_create_denied", &user_audit(None, "duplicate_email")).await;
            user_error(StatusCode::CONFLICT, "duplicate_email", "Email already exists")
        }
        Err(_) => { audit::record_state(&s, Some(actor.id), "user_create_failed", &user_audit(None, "database_error")).await; user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable") },
    }
}

async fn update_user(
    State(s): State<AppState>, h: HeaderMap, Path(id): Path<i64>, Json(input): Json<UserPatch>,
) -> impl IntoResponse {
    let actor = match require_user_admin(&s, &h).await { Ok(u) => u, Err(response) => return response };
    let target_exists = repository::list_users(&s.db).await.ok().is_some_and(|users| users.into_iter().any(|u| u.id == id));
    if !target_exists {
        audit::record_state(&s, Some(actor.id), "user_update_denied", &user_audit(Some(id), "not_found")).await;
        return user_error(StatusCode::NOT_FOUND, "not_found", "User not found");
    }
    if input.role.is_none() && input.disabled.is_none() {
        audit::record_state(&s, Some(actor.id), "user_update_denied", &user_audit(Some(id), "invalid_input")).await;
        return user_error(StatusCode::BAD_REQUEST, "invalid_input", "At least one field is required");
    }
    if actor.id == id && input.disabled == Some(true) {
        audit::record_state(&s, Some(actor.id), "user_update_denied", &user_audit(Some(id), "self_disable")).await;
        return user_error(StatusCode::FORBIDDEN, "self_mutation", "You cannot disable your own account");
    }
    if let Some(role) = input.role.as_deref() {
        if !role_slug_exists(&s, role.trim()).await.unwrap_or(false) {
            audit::record_state(&s, Some(actor.id), "user_update_denied", &user_audit(Some(id), "invalid_role")).await;
            return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role");
        }
    }
    let role = input.role.as_deref().map(str::trim);
    let updated = match repository::update_user(&s.db, id, role, input.disabled).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            audit::record_state(&s, Some(actor.id), "user_update_denied", &user_audit(Some(id), "not_found")).await;
            return user_error(StatusCode::NOT_FOUND, "not_found", "User not found");
        }
        Err(error) if error.to_string().contains("last active") => {
            audit::record_state(&s, Some(actor.id), "user_update_denied", &user_audit(Some(id), "last_admin")).await;
            return user_error(StatusCode::CONFLICT, "last_admin", "Cannot remove the last active administrator");
        }
        Err(_) => { audit::record_state(&s, Some(actor.id), "user_update_failed", &user_audit(Some(id), "database_error")).await; return user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable"); },
    };
    let detail = if input.disabled == Some(true) { "user_disabled" } else { "user_updated" };
    audit::record_state(&s, Some(actor.id), detail, &user_audit(Some(id), "success")).await;
    s.realtime.publish("users.changed");
    if input.role.is_some() || input.disabled.is_some() { s.realtime.publish("sessions.changed"); }
    Json(updated).into_response()
}

async fn revoke_user_sessions(
    State(s): State<AppState>,
    h: HeaderMap,
    path: Result<Path<i64>, PathRejection>,
) -> impl IntoResponse {
    let actor = match current(&s, &h).await {
        Ok(user) => user,
        Err(status) => return status.into_response(),
    };
    if !authorize(&s.db, &actor, Permission::SessionsRevoke, ResourceContext::GLOBAL).await.unwrap_or(false) {
        audit::record_state(&s, Some(actor.id), "session_revoke_denied", "reason=authorization").await;
        return user_error(StatusCode::FORBIDDEN, "forbidden", "Administrator access required");
    }
    let Path(id) = match path {
        Ok(path) => path,
        Err(_) => {
            audit::record_state(&s, Some(actor.id), "session_revoke_denied", "reason=invalid_input").await;
            return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid user id");
        }
    };
    if actor.id == id {
        audit::record_state(&s, Some(actor.id), "session_revoke_denied", &user_audit(Some(id), "self_target")).await;
        return user_error(StatusCode::FORBIDDEN, "self_mutation", "You cannot revoke your own sessions");
    }
    let target_exists = match repository::list_users(&s.db).await {
        Ok(users) => users.into_iter().any(|user| user.id == id),
        Err(_) => {
            audit::record_state(&s, Some(actor.id), "session_revoke_denied", &user_audit(Some(id), "database_error")).await;
            return user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable");
        }
    };
    if !target_exists {
        audit::record_state(&s, Some(actor.id), "session_revoke_denied", &user_audit(Some(id), "not_found")).await;
        return user_error(StatusCode::NOT_FOUND, "not_found", "User not found");
    }
    match repository::revoke_user_sessions(&s.db, id).await {
        Ok(revoked) => {
            audit::record_state(&s, Some(actor.id), "sessions_revoked", &format!("target_user_id={id};count={revoked}")).await;
            s.realtime.publish("sessions.changed");
            Json(SessionsRevokeResponse { revoked }).into_response()
        }
        Err(_) => {
            audit::record_state(&s, Some(actor.id), "session_revoke_denied", &user_audit(Some(id), "database_error")).await;
            user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable")
        }
    }
}

async fn delete_user(State(s): State<AppState>, h: HeaderMap, Path(id): Path<i64>) -> impl IntoResponse {
    let actor = match require_user_admin(&s, &h).await { Ok(u) => u, Err(response) => return response };
    if actor.id == id {
        audit::record_state(&s, Some(actor.id), "user_delete_denied", &user_audit(Some(id), "self_delete")).await;
        return user_error(StatusCode::FORBIDDEN, "self_mutation", "You cannot delete your own account");
    }
    match repository::delete_user(&s.db, id).await {
        Ok(0) => { audit::record_state(&s, Some(actor.id), "user_delete_denied", &user_audit(Some(id), "not_found")).await; user_error(StatusCode::NOT_FOUND, "not_found", "User not found") }
        Ok(_) => { audit::record_state(&s, Some(actor.id), "user_deleted", &user_audit(Some(id), "success")).await; s.realtime.publish("users.changed"); StatusCode::NO_CONTENT.into_response() }
        Err(error) if error.to_string().contains("last active") => {
            audit::record_state(&s, Some(actor.id), "user_delete_denied", &user_audit(Some(id), "last_admin")).await;
            user_error(StatusCode::CONFLICT, "last_admin", "Cannot remove the last active administrator")
        }
        Err(_) => { audit::record_state(&s, Some(actor.id), "user_delete_failed", &user_audit(Some(id), "database_error")).await; user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable") },
    }
}

fn acme_error(status: StatusCode, code: &str, message: &str) -> axum::response::Response {
    (
        status,
        Json(ErrorEnvelope {
            code: code.into(),
            message: message.into(),
        }),
    )
        .into_response()
}
async fn issue_acme(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(input): Json<AcmeIssueRequest>,
) -> impl IntoResponse {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return c.into_response(),
    };
    if !authorize(&s.db, &user, Permission::CertificatesWrite, ResourceContext::GLOBAL).await.unwrap_or(false) {
        audit::record_state(&s, Some(user.id), "authorization_denied", "acme_issue").await;
        return StatusCode::FORBIDDEN.into_response();
    }
    let req = match input.request().normalized() {
        Ok(r) => r,
        Err(e) => {
            let code = if e.contains("wildcard") || e.contains("hostname") {
                "invalid_hostname"
            } else {
                "invalid_hostname"
            };
            audit::record_state(&s, Some(user.id), "acme_issue_failed", code).await;
            return acme_error(StatusCode::BAD_REQUEST, code, "Invalid ACME hostname");
        }
    };
    if matches!(&req.challenge, AcmeChallenge::Http01)
        && req.hostnames.iter().any(|x| x.starts_with("*."))
    {
        audit::record_state(&s, Some(user.id), "acme_issue_failed", "unsupported_challenge").await;
        return acme_error(
            StatusCode::BAD_REQUEST,
            "unsupported_challenge",
            "Challenge does not support this hostname",
        );
    }
    let mut token_bytes = input.cloudflare_token.map(String::into_bytes);
    let result = s.acme.issue(req, token_bytes.clone(), 0).await;
    if let Some(bytes) = token_bytes.as_mut() {
        bytes.fill(0);
    }
    match result {
        Ok(job) => {
            audit::record_state(
                &s,
                Some(user.id),
                "acme_issue_accepted",
                "certificate_job_created",
            )
            .await;
            s.realtime.publish("certificates.changed");
            (
                StatusCode::ACCEPTED,
                Json(AcmeJobResponse {
                    job_id: job.job_id,
                    certificate_id: job.certificate_id,
                }),
            )
                .into_response()
        }
        Err(AcmeServiceError::Busy) => {
            audit::record_state(&s, Some(user.id), "acme_issue_failed", "busy").await;
            acme_error(StatusCode::CONFLICT, "acme_busy", "An ACME operation is already running")
        }
        Err(_) => {
            audit::record_state(&s, Some(user.id), "acme_issue_failed", "service_error").await;
            acme_error(StatusCode::BAD_GATEWAY, "acme_failed", "ACME operation failed")
        }
    }
}
async fn renew_acme(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return c.into_response(),
    };
    if !authorize(&s.db, &user, Permission::CertificatesWrite, ResourceContext::GLOBAL).await.unwrap_or(false) {
        audit::record_state(&s, Some(user.id), "authorization_denied", "CertificatesWrite").await;
        return StatusCode::FORBIDDEN.into_response();
    }
    if repository::get_acme_status(&s.db, id)
        .await
        .ok()
        .flatten()
        .is_none()
    {
        audit::record_state(&s, Some(user.id), "acme_renew_failed", "not_found").await;
        return acme_error(StatusCode::NOT_FOUND, "not_found", "Certificate not found");
    }
    match s.acme.renew(id).await {
        Ok(job) => {
            audit::record_state(
                &s,
                Some(user.id),
                "acme_renew_accepted",
                "certificate_job_created",
            )
            .await;
            s.realtime.publish("certificates.changed");
            (
                StatusCode::ACCEPTED,
                Json(AcmeJobResponse {
                    job_id: job.job_id,
                    certificate_id: job.certificate_id,
                }),
            )
                .into_response()
        }
        Err(AcmeServiceError::Busy) => {
            audit::record_state(&s, Some(user.id), "acme_renew_failed", "busy").await;
            acme_error(StatusCode::CONFLICT, "acme_busy", "An ACME operation is already running")
        }
        Err(_) => {
            audit::record_state(&s, Some(user.id), "acme_renew_failed", "service_error").await;
            acme_error(StatusCode::BAD_GATEWAY, "acme_failed", "ACME operation failed")
        }
    }
}
async fn acme_status(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return c.into_response(),
    };
    if !authorize(&s.db, &user, Permission::CertificatesRead, ResourceContext::GLOBAL).await.unwrap_or(false) {
        audit::record_state(&s, Some(user.id), "authorization_denied", "CertificatesRead").await;
        return StatusCode::FORBIDDEN.into_response();
    }
    match repository::get_acme_status(&s.db, id).await {
        Ok(Some(status)) => Json(status).into_response(),
        Ok(None) => acme_error(StatusCode::NOT_FOUND, "not_found", "Certificate not found"),
        Err(_) => acme_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "acme_failed",
            "Status unavailable",
        ),
    }
}
async fn health() -> Json<serde_json::Value> {
    Json(serde_json::json!({"status":"ok"}))
}
async fn setup_status(State(s): State<AppState>) -> impl IntoResponse {
    match repository::user_count(&s.db).await {
        Ok(n) => Json(serde_json::json!({"initialized":n>0})).into_response(),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorEnvelope {
                code: "database_error".into(),
                message: "Database unavailable".into(),
            }),
        )
            .into_response(),
    }
}
async fn setup_initialize(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(req): Json<SetupRequest>,
) -> impl IntoResponse {
    let key = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    if !allow_auth_attempt(&s, key).await {
        return StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    if req.setup_token != s.setup_token.as_ref() {
        audit::record_state(&s, None, "setup_failed", "invalid_token").await;
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorEnvelope {
                code: "invalid_setup_token".into(),
                message: "Invalid setup token".into(),
            }),
        )
            .into_response();
    }
    let email = req.email.trim().to_ascii_lowercase();
    if req.password.len() < 12 || !email.contains('@') {
        return (
            StatusCode::BAD_REQUEST,
            Json(ErrorEnvelope {
                code: "invalid_input".into(),
                message: "Valid email and password of at least 12 characters required".into(),
            }),
        )
            .into_response();
    }
    let hash = match auth::hash_password(&req.password) {
        Ok(x) => x,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    match repository::insert_initial_admin(&s.db, &email, &hash).await {
        Ok(Some(u)) => {
            audit::record_state(&s, Some(u.id), "setup_completed", "admin_created").await;
            (StatusCode::CREATED, Json(u)).into_response()
        }
        Ok(None) => (
            StatusCode::CONFLICT,
            Json(ErrorEnvelope {
                code: "already_initialized".into(),
                message: "Setup has already completed".into(),
            }),
        )
            .into_response(),
        Err(_) => user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable"),
    }
}
async fn current(s: &AppState, h: &HeaderMap) -> Result<User, StatusCode> {
    let t = auth::cookie(h).ok_or(StatusCode::UNAUTHORIZED)?;
    repository::find_user_by_session(&s.db, &auth::token_hash(t))
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .ok_or(StatusCode::UNAUTHORIZED)
}

async fn events(State(s): State<AppState>, h: HeaderMap) -> Response {
    if current(&s, &h).await.is_err() {
        return user_error(StatusCode::UNAUTHORIZED, "unauthorized", "Authentication required");
    }

    // Authentication is checked before subscribing.  Last-Event-ID is
    // intentionally ignored: the process-local hub does not provide replay.
    let receiver = s.realtime.subscribe();
    // Keep the stream authenticated for its entire lifetime.  The first tick
    // is consumed before constructing the stream because `interval` otherwise
    // fires immediately; subsequent ticks revalidate the same session without
    // interfering with broadcast delivery.
    let mut revalidation = tokio::time::interval(Duration::from_secs(15));
    revalidation.tick().await;
    revalidation.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let stream = unfold((receiver, true, s, h, revalidation), |(mut receiver, ready, state, headers, mut revalidation)| async move {
        if ready {
            let event = Event::default().event("ready").data("{}");
            return Some((Ok::<Event, Infallible>(event), (receiver, false, state, headers, revalidation)));
        }
        tokio::select! {
            next = receiver.recv() => {
                let next = match next {
                    Ok(value) => Event::default()
                        .id(value.id.to_string())
                        .event(value.kind.clone())
                        .json_data(value)
                        .unwrap_or_else(|_| Event::default().event("reconnect").data("{}")),
                    Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {
                        Event::default().event("reconnect").data(r#"{"reason":"lagged"}"#)
                    }
                    Err(tokio::sync::broadcast::error::RecvError::Closed) => return None,
                };
                Some((Ok::<Event, Infallible>(next), (receiver, false, state, headers, revalidation)))
            }
            _ = revalidation.tick() => {
                if current(&state, &headers).await.is_err() {
                    return None;
                }
                Some((Ok::<Event, Infallible>(Event::default().comment("heartbeat")), (receiver, false, state, headers, revalidation)))
            }
        }
    });
    let mut response = Sse::new(stream)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(15)).text("heartbeat"))
        .into_response();
    response.headers_mut().insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-cache, no-transform"),
    );
    response
}
async fn me(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    match current(&s, &h).await {
        Ok(u) => Json(u).into_response(),
        Err(c) => c.into_response(),
    }
}

async fn list_audit_logs(
    State(s): State<AppState>,
    h: HeaderMap,
    Query(params): Query<AuditLogParams>,
) -> impl IntoResponse {
    let user = match current(&s, &h).await {
        Ok(user) => user,
        Err(status) => return status.into_response(),
    };
    // Audit history is intentionally available to the three known roles only.
    // Do not treat malformed/unknown persisted roles as a viewer: that would
    // turn a corrupt account record into an authorization bypass.
    if !authorize(&s.db, &user, Permission::AuditLogsRead, ResourceContext::GLOBAL).await.unwrap_or(false) {
        audit::record_state(&s, Some(user.id), "authorization_denied", "AuditLogsRead").await;
        return StatusCode::FORBIDDEN.into_response();
    }

    let page = match params.page.as_deref().unwrap_or("1").parse::<u32>() {
        Ok(value) if value >= 1 => value,
        _ => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid page"),
    };
    let page_size = match params.page_size.as_deref().unwrap_or("25").parse::<u32>() {
        Ok(value) if (1..=100).contains(&value) => value,
        _ => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid page size"),
    };
    let actor_id = match params.actor_id.as_deref() {
        None | Some("") => None,
        Some(value) => match value.parse::<i64>() {
            Ok(value) if value >= 0 => Some(value),
            _ => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid actor id"),
        },
    };
    let from = match params.from.as_deref().filter(|value| !value.is_empty()) {
        Some(value) => match normalize_audit_timestamp(value) {
            Ok(value) => Some(value),
            Err(_) => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid timestamp"),
        },
        None => None,
    };
    let to = match params.to.as_deref().filter(|value| !value.is_empty()) {
        Some(value) => match normalize_audit_timestamp(value) {
            Ok(value) => Some(value),
            Err(_) => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid timestamp"),
        },
        None => None,
    };
    let query = AuditLogQuery {
        event: params.event.filter(|value| !value.is_empty()),
        actor_id,
        from,
        to,
        q: params.q.filter(|value| !value.is_empty()),
        page,
        page_size,
    };
    match repository::list_audit_logs(&s.db, &query).await {
        Ok(page) => Json(page).into_response(),
        Err(_) => user_error(StatusCode::INTERNAL_SERVER_ERROR, "database_error", "Database unavailable"),
    }
}

/// Normalize RFC3339 query bounds to the UTC representation persisted in
/// SQLite. Text comparisons are lexical, so retaining a caller's offset
/// (e.g. `+02:00`) would compare different instants incorrectly.
fn normalize_audit_timestamp(value: &str) -> Result<String, chrono::ParseError> {
    DateTime::parse_from_rfc3339(value).map(|parsed| {
        parsed
            .with_timezone(&Utc)
            .to_rfc3339_opts(SecondsFormat::AutoSi, true)
    })
}
async fn list_hosts(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    let user = match current(&s, &h).await { Ok(u) => u, Err(c) => return c.into_response() };
    let global_read = authorize(&s.db, &user, Permission::ProxyHostsRead, ResourceContext::GLOBAL).await.unwrap_or(false);
    let scoped_read = repository::user_has_scoped_permission(&s.db, user.id, Permission::ProxyHostsRead.key()).await.unwrap_or(false);
    if !global_read && !scoped_read {
        audit::record_state(&s, Some(user.id), "authorization_denied", "ProxyHostsRead").await;
        return StatusCode::FORBIDDEN.into_response();
    }
    match repository::list_hosts_for_user(&s.db, user.id).await {
        Ok(x) => Json(x).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_host(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let user = match current(&s, &h).await { Ok(u) => u, Err(c) => return c.into_response() };
    if !authorize(&s.db, &user, Permission::ProxyHostsRead, ResourceContext::ProxyHost(id)).await.unwrap_or(false) {
        audit::record_state(&s, Some(user.id), "authorization_denied", r#"{"resource_type":"proxy_host","resource_id":"[REDACTED]"}"#).await;
        return StatusCode::NOT_FOUND.into_response();
    }
    match repository::get_host(&s.db, id).await {
        Ok(Some(host)) => Json(host).into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
async fn create_host(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(req): Json<ProxyHostRequest>,
) -> impl IntoResponse {
    let u = match current(&s, &h).await {
        Ok(x) => x,
        Err(c) => return c.into_response(),
    };
    if !authorize(&s.db, &u, Permission::ProxyHostsWrite, ResourceContext::GLOBAL).await.unwrap_or(false) {
        audit::record_state(&s, Some(u.id), "authorization_denied", "ProxyHostsWrite").await;
        return StatusCode::FORBIDDEN.into_response();
    }
    if req.name.trim().is_empty()
        || req.domain.trim().is_empty()
        || req.upstream_host.trim().is_empty()
        || req.upstream_port == 0
    {
        audit::record_state(&s, Some(u.id), "proxy_host_create_denied", "reason=invalid_input").await;
        return StatusCode::BAD_REQUEST.into_response();
    }
    let host = ProxyHost {
        id: 0,
        name: req.name,
        domain: req.domain.to_ascii_lowercase(),
        upstream_host: req.upstream_host,
        upstream_port: req.upstream_port,
        tls_mode: req.tls_mode,
        certificate_id: req.certificate_id,
        enabled: req.enabled,
    };
    match repository::insert_host(&s.db, &host).await {
        Ok(x) => {
            let desired = DesiredConfig {
                proxy_hosts: repository::list_hosts(&s.db).await.unwrap_or_default(),
            };
            if s.reloader.apply(desired).await.is_err() {
                let _ = repository::delete_host(&s.db, x.id).await;
                audit::record_state(&s, Some(u.id), "proxy_host_create_failed", "reason=reload_failed").await;
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorEnvelope {
                        code: "reload_failed".into(),
                        message: "Proxy host was not activated".into(),
                    }),
                )
                    .into_response();
            }
            audit::record_state(&s, Some(u.id), "proxy_host_created", "configuration_changed").await;
            s.realtime.publish("proxy_hosts.changed");
            (StatusCode::CREATED, Json(x)).into_response()
        }
        Err(_) => {
            audit::record_state(&s, Some(u.id), "proxy_host_create_denied", "reason=duplicate_domain").await;
            (
                StatusCode::CONFLICT,
                Json(ErrorEnvelope {
                    code: "duplicate_domain".into(),
                    message: "Domain already exists".into(),
                }),
            )
                .into_response()
        }
    }
}
async fn update_host(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(req): Json<ProxyHostRequest>,
) -> impl IntoResponse {
    let u = match current(&s, &h).await {
        Ok(x) => x,
        Err(c) => return c.into_response(),
    };
    if !authorize(&s.db, &u, Permission::ProxyHostsWrite, ResourceContext::ProxyHost(id)).await.unwrap_or(false) {
        audit::record_state(&s, Some(u.id), "authorization_denied", r#"{"resource_type":"proxy_host","resource_id":"[REDACTED]"}"#).await;
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(previous) = repository::get_host(&s.db, id).await.ok().flatten() else {
        audit::record_state(&s, Some(u.id), "proxy_host_update_denied", "reason=not_found").await;
        return StatusCode::NOT_FOUND.into_response();
    };
    if req.name.trim().is_empty()
        || req.domain.trim().is_empty()
        || req.upstream_host.trim().is_empty()
        || req.upstream_port == 0
    {
        audit::record_state(&s, Some(u.id), "proxy_host_update_denied", "reason=invalid_input").await;
        return StatusCode::BAD_REQUEST.into_response();
    }
    let next = ProxyHost {
        id,
        name: req.name,
        domain: req.domain.to_ascii_lowercase(),
        upstream_host: req.upstream_host,
        upstream_port: req.upstream_port,
        tls_mode: req.tls_mode,
        certificate_id: req.certificate_id,
        enabled: req.enabled,
    };
    if repository::update_host(&s.db, id, &next).await.is_err() {
        audit::record_state(&s, Some(u.id), "proxy_host_update_failed", "reason=database_error").await;
        return StatusCode::CONFLICT.into_response();
    }
    let desired = DesiredConfig {
        proxy_hosts: repository::list_hosts(&s.db).await.unwrap_or_default(),
    };
    if s.reloader.apply(desired).await.is_err() {
        let _ = repository::update_host(&s.db, id, &previous).await;
        audit::record_state(&s, Some(u.id), "proxy_host_update_failed", "reason=reload_failed").await;
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorEnvelope {
                code: "reload_failed".into(),
                message: "Proxy host update was not activated".into(),
            }),
        )
            .into_response();
    }
    audit::record_state(
        &s,
        Some(u.id),
        "proxy_host_updated",
        "configuration_changed",
    )
    .await;
    s.realtime.publish("proxy_hosts.changed");
    Json(next).into_response()
}

async fn remove_host(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let u = match current(&s, &h).await {
        Ok(x) => x,
        Err(c) => return c.into_response(),
    };
    if !authorize(&s.db, &u, Permission::ProxyHostsWrite, ResourceContext::ProxyHost(id)).await.unwrap_or(false) {
        audit::record_state(&s, Some(u.id), "authorization_denied", r#"{"resource_type":"proxy_host","resource_id":"[REDACTED]"}"#).await;
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(previous) = repository::get_host(&s.db, id).await.ok().flatten() else {
        audit::record_state(&s, Some(u.id), "proxy_host_delete_denied", "reason=not_found").await;
        return StatusCode::NOT_FOUND.into_response();
    };
    let scope_rows = match repository::host_scope_rows(&s.db, id).await {
        Ok(rows) => rows,
        Err(_) => {
            audit::record_state(&s, Some(u.id), "proxy_host_delete_failed", "reason=database_error").await;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    if repository::delete_host_and_scopes(&s.db, id).await.is_err() {
        audit::record_state(&s, Some(u.id), "proxy_host_delete_failed", "reason=database_error").await;
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let desired = DesiredConfig {
        proxy_hosts: repository::list_hosts(&s.db).await.unwrap_or_default(),
    };
    if s.reloader.apply(desired).await.is_err() {
        let host_restore = repository::insert_host(&s.db, &previous).await;
        let scopes_restore = repository::restore_host_scopes(&s.db, id, &scope_rows).await;
        let config_restore = repository::list_hosts(&s.db).await
            .map(|hosts| DesiredConfig { proxy_hosts: hosts })
            .map_err(|_| ());
        let reload_restore = match config_restore {
            Ok(config) => s.reloader.apply(config).await.map_err(|_| ()),
            Err(_) => Err(()),
        };
        let rollback_ok = host_restore.is_ok() && scopes_restore.is_ok() && reload_restore.is_ok();
        audit::record_state(&s, Some(u.id), "proxy_host_delete_failed", if rollback_ok { "reason=reload_failed" } else { "reason=rollback_failed" }).await;
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorEnvelope {
                code: "reload_failed".into(),
                message: "Proxy host deletion was not activated".into(),
            }),
        )
            .into_response();
    }
    audit::record_state(
        &s,
        Some(u.id),
        "proxy_host_deleted",
        "configuration_changed",
    )
    .await;
    s.realtime.publish("proxy_hosts.changed");
    StatusCode::NO_CONTENT.into_response()
}
async fn upload_certificate(
    State(s): State<AppState>,
    h: HeaderMap,
    mut multipart: Multipart,
) -> impl IntoResponse {
    let u = match current(&s, &h).await {
        Ok(x) => x,
        Err(c) => return c.into_response(),
    };
    if !authorize(&s.db, &u, Permission::CertificatesWrite, ResourceContext::GLOBAL).await.unwrap_or(false) {
        audit::record_state(&s, Some(u.id), "authorization_denied", "CertificatesWrite").await;
        return StatusCode::FORBIDDEN.into_response();
    }
    let mut total = 0usize;
    let mut name = None;
    let mut cert = None;
    let mut key = None;
    while let Ok(Some(field)) = multipart.next_field().await {
        let field_name = field.name().unwrap_or("").to_string();
        let bytes = match field.bytes().await {
            Ok(b) => b,
            Err(_) => { audit::record_state(&s, Some(u.id), "certificate_upload_denied", "reason=invalid_multipart").await; return StatusCode::BAD_REQUEST.into_response(); }
        };
        total += bytes.len();
        if total > 3 * 1024 * 1024 {
            audit::record_state(&s, Some(u.id), "certificate_upload_denied", "reason=payload_too_large").await;
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
        if bytes.len() > 1024 * 1024 {
            audit::record_state(&s, Some(u.id), "certificate_upload_denied", "reason=field_too_large").await;
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
        match field_name.as_str() {
            "name" => name = String::from_utf8(bytes.to_vec()).ok(),
            "certificate" => cert = Some(bytes),
            "key" => key = Some(bytes),
            _ => {}
        }
    }
    let (Some(name), Some(cert), Some(key)) = (name, cert, key) else {
        audit::record_state(&s, Some(u.id), "certificate_upload_denied", "reason=missing_fields").await;
        return StatusCode::BAD_REQUEST.into_response();
    };
    match s.certificates.import_custom(&name, &cert, &key) {
        Ok(record) => {
            match repository::insert_certificate(&s.db,&record.name,"custom",&serde_json::to_string(&record.covered_hostnames).unwrap_or_default(),&record.expiry,&record.certificate_path.to_string_lossy(),&record.key_path.to_string_lossy()).await{Ok(id)=>{ audit::record_state(&s, Some(u.id), "certificate_uploaded", &format!("certificate_id={id}")).await; s.realtime.publish("certificates.changed"); (StatusCode::CREATED,Json(serde_json::json!({"id":id,"name":record.name,"source":"custom","covered_hostnames":record.covered_hostnames,"expiry":record.expiry}))).into_response() },Err(_)=>{ audit::record_state(&s, Some(u.id), "certificate_upload_failed", "reason=database_error").await; StatusCode::CONFLICT.into_response() }}
        }
        Err(_) => { audit::record_state(&s, Some(u.id), "certificate_upload_denied", "reason=invalid_certificate").await; StatusCode::BAD_REQUEST.into_response() },
    }
}

async fn list_certificates(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return c.into_response(),
    };
    if !authorize(&s.db, &user, Permission::CertificatesRead, ResourceContext::GLOBAL).await.unwrap_or(false) {
        audit::record_state(&s, Some(user.id), "authorization_denied", "CertificatesRead").await;
        return StatusCode::FORBIDDEN.into_response();
    }
    match repository::list_certificates(&s.db).await {
        Ok(c) => Json(c).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn activate_certificate(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return c.into_response(),
    };
    if !authorize(&s.db, &user, Permission::CertificatesWrite, ResourceContext::GLOBAL).await.unwrap_or(false) {
        audit::record_state(&s, Some(user.id), "authorization_denied", "CertificatesWrite").await;
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some((name, cert_path, key_path)) = repository::certificate_paths(&s.db, id)
        .await
        .ok()
        .flatten()
    else {
        audit::record_state(&s, Some(user.id), "certificate_activation_denied", "reason=not_found").await;
        return StatusCode::NOT_FOUND.into_response();
    };
    if CertificateStore::validate_material_paths(
        std::path::Path::new(&cert_path),
        std::path::Path::new(&key_path),
    )
    .is_err()
    {
        audit::record_state(&s, Some(user.id), "certificate_activation_denied", "reason=invalid_material").await;
        return StatusCode::BAD_REQUEST.into_response();
    }
    let previous_id = match repository::active_certificate_id(&s.db).await {
        Ok(value) => value,
        Err(_) => { audit::record_state(&s, Some(user.id), "certificate_activation_failed", "reason=database_error").await; return StatusCode::INTERNAL_SERVER_ERROR.into_response(); }
    };
    let previous_name = match previous_id {
        Some(previous_id) => repository::certificate_name(&s.db, previous_id)
            .await
            .ok()
            .flatten(),
        None => None,
    };
    if s.certificates.activate(&name).is_err()
        || repository::set_active_certificate(&s.db, Some(id))
            .await
            .map(|changed| changed != 1)
            .unwrap_or(true)
    {
        let _ = restore_certificate_activation(&s, previous_id, previous_name.as_deref()).await;
        audit::record_state(&s, Some(user.id), "certificate_activation_failed", "reason=activation_failed").await;
        return StatusCode::BAD_REQUEST.into_response();
    }
    if s.reloader.apply_certificate_change(id).await.is_err() {
        let _ = restore_certificate_activation(&s, previous_id, previous_name.as_deref()).await;
        audit::record_state(
            &s,
            Some(user.id),
            "certificate_activation_failed",
            &format!("certificate_id={id};reason=reload_failed"),
        )
        .await;
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorEnvelope {
                code: "reload_failed".into(),
                message: "Certificate activation was not applied".into(),
            }),
        )
            .into_response();
    }
    audit::record_state(
        &s,
        Some(user.id),
        "certificate_activated",
        &format!("certificate_id={id}"),
    )
    .await;
    s.realtime.publish("certificates.changed");
    StatusCode::NO_CONTENT.into_response()
}

async fn restore_certificate_activation(
    state: &AppState,
    previous_id: Option<i64>,
    previous_name: Option<&str>,
) -> Result<(), ()> {
    repository::set_active_certificate(&state.db, previous_id)
        .await
        .map_err(|_| ())?;
    match previous_name {
        Some(name) => state
            .certificates
            .activate(name)
            .map(|_| ())
            .map_err(|_| ()),
        None => state.certificates.clear_active().map_err(|_| ()),
    }
}
