pub mod audit;
pub mod auth;
pub mod models;
pub mod rbac;
pub mod repository;
use crate::certificates::CertificateStore;
use crate::secrets::SecretStore;
use async_trait::async_trait;
use axum::{
    extract::DefaultBodyLimit,
    extract::{Multipart, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use models::*;
use rbac::{allowed, Permission, Role};
use std::sync::Arc;
use std::{
    collections::HashMap,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;
use uuid::Uuid;
use tower_http::services::ServeDir;

#[derive(Clone)]
pub struct AppState {
    pub db: sqlx::SqlitePool,
    pub certificates: Arc<CertificateStore>,
    pub reloader: Arc<dyn ConfigReloader>,
    pub setup_token: Arc<str>,
    pub auth_attempts: Arc<Mutex<HashMap<String, (Instant, u32)>>>,
    pub secrets: SecretStore,
    pub acme: Arc<dyn AcmeService>,
}

#[derive(Debug, thiserror::Error)]
pub enum AcmeServiceError { #[error("ACME operation is busy")] Busy, #[error("ACME operation failed")] Failed }
#[derive(Clone, Debug)]
pub struct AcmeJob { pub job_id: String, pub certificate_id: i64 }
#[async_trait]
pub trait AcmeService: Send + Sync {
    async fn issue(&self, request: AcmeRequest, cloudflare_token: Option<Vec<u8>>, certificate_id: i64) -> Result<AcmeJob, AcmeServiceError>;
    async fn renew(&self, certificate_id: i64) -> Result<AcmeJob, AcmeServiceError>;
}
pub struct NoopAcmeService;
#[async_trait]
impl AcmeService for NoopAcmeService {
    async fn issue(&self, _: AcmeRequest, _: Option<Vec<u8>>, certificate_id: i64) -> Result<AcmeJob, AcmeServiceError> { Ok(AcmeJob { job_id: Uuid::new_v4().to_string(), certificate_id }) }
    async fn renew(&self, certificate_id: i64) -> Result<AcmeJob, AcmeServiceError> { Ok(AcmeJob { job_id: Uuid::new_v4().to_string(), certificate_id }) }
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
    let secrets = SecretStore::open(&certificate_root.join("secrets")).map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    Ok(AppState {
        db,
        certificates: Arc::new(certificates),
        reloader: Arc::new(NoopReloader),
        setup_token: setup_token.into(),
        auth_attempts: Arc::new(Mutex::new(HashMap::new())),
        secrets,
        acme: Arc::new(NoopAcmeService),
    })
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

fn acme_error(status: StatusCode, code: &str, message: &str) -> axum::response::Response {
    (status, Json(ErrorEnvelope { code: code.into(), message: message.into() })).into_response()
}
async fn issue_acme(State(s): State<AppState>, h: HeaderMap, Json(input): Json<AcmeIssueRequest>) -> impl IntoResponse {
    let user = match current(&s, &h).await { Ok(u) => u, Err(c) => return c.into_response() };
    if !allowed(Role::parse(&user.role).unwrap_or(Role::Viewer), Permission::CertificatesWrite) { audit::record(&s.db, Some(user.id), "authorization_denied", "acme_issue").await; return StatusCode::FORBIDDEN.into_response(); }
    let req = match input.request().normalized() { Ok(r) => r, Err(e) => { let code = if e.contains("wildcard") || e.contains("hostname") { "invalid_hostname" } else { "invalid_hostname" }; audit::record(&s.db, Some(user.id), "acme_issue_failed", code).await; return acme_error(StatusCode::BAD_REQUEST, code, "Invalid ACME hostname"); } };
    if matches!(req.challenge, AcmeChallenge::Http01) && req.hostnames.iter().any(|x| x.starts_with("*.")) { return acme_error(StatusCode::BAD_REQUEST, "unsupported_challenge", "Challenge does not support this hostname"); }
    let name = req.hostnames.first().cloned().unwrap_or_else(|| "acme-certificate".into());
    let hosts = serde_json::to_string(&req.hostnames).unwrap_or_else(|_| "[]".into());
    let id = match repository::insert_certificate(&s.db, &name, "letsencrypt", &hosts, "", "", "").await { Ok(id) => id, Err(_) => { return acme_error(StatusCode::CONFLICT, "acme_busy", "An ACME operation is already running"); } };
    if repository::insert_acme_certificate(&s.db, id, &req).await.is_err() { return acme_error(StatusCode::CONFLICT, "acme_busy", "An ACME operation is already running"); }
    let mut token_bytes = input.cloudflare_token.map(String::into_bytes);
    if let Some(bytes) = token_bytes.as_ref() { if s.secrets.put(&format!("cloudflare-{id}"), bytes).is_err() { return acme_error(StatusCode::INTERNAL_SERVER_ERROR, "acme_failed", "ACME credentials could not be stored"); } }
    let result = s.acme.issue(req, token_bytes.clone(), id).await;
    if let Some(bytes) = token_bytes.as_mut() { bytes.fill(0); }
    match result { Ok(job) => { audit::record(&s.db, Some(user.id), "acme_issue_accepted", "certificate_job_created").await; (StatusCode::ACCEPTED, Json(AcmeJobResponse { job_id: job.job_id, certificate_id: job.certificate_id })).into_response() }, Err(AcmeServiceError::Busy) => acme_error(StatusCode::CONFLICT, "acme_busy", "An ACME operation is already running"), Err(_) => acme_error(StatusCode::BAD_GATEWAY, "acme_failed", "ACME operation failed") }
}
async fn renew_acme(State(s): State<AppState>, h: HeaderMap, Path(id): Path<i64>) -> impl IntoResponse {
    let user = match current(&s, &h).await { Ok(u) => u, Err(c) => return c.into_response() };
    if !allowed(Role::parse(&user.role).unwrap_or(Role::Viewer), Permission::CertificatesWrite) { return StatusCode::FORBIDDEN.into_response(); }
    if repository::get_acme_status(&s.db, id).await.ok().flatten().is_none() { return acme_error(StatusCode::NOT_FOUND, "not_found", "Certificate not found"); }
    match s.acme.renew(id).await { Ok(job) => { audit::record(&s.db, Some(user.id), "acme_renew_accepted", "certificate_job_created").await; (StatusCode::ACCEPTED, Json(AcmeJobResponse { job_id: job.job_id, certificate_id: job.certificate_id })).into_response() }, Err(AcmeServiceError::Busy) => acme_error(StatusCode::CONFLICT, "acme_busy", "An ACME operation is already running"), Err(_) => acme_error(StatusCode::BAD_GATEWAY, "acme_failed", "ACME operation failed") }
}
async fn acme_status(State(s): State<AppState>, h: HeaderMap, Path(id): Path<i64>) -> impl IntoResponse {
    let user = match current(&s, &h).await { Ok(u) => u, Err(c) => return c.into_response() };
    if !allowed(Role::parse(&user.role).unwrap_or(Role::Viewer), Permission::CertificatesRead) { return StatusCode::FORBIDDEN.into_response(); }
    match repository::get_acme_status(&s.db, id).await { Ok(Some(status)) => Json(status).into_response(), Ok(None) => acme_error(StatusCode::NOT_FOUND, "not_found", "Certificate not found"), Err(_) => acme_error(StatusCode::INTERNAL_SERVER_ERROR, "acme_failed", "Status unavailable") }
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
        audit::record(&s.db, None, "setup_failed", "invalid_token").await;
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorEnvelope {
                code: "invalid_setup_token".into(),
                message: "Invalid setup token".into(),
            }),
        )
            .into_response();
    }
    if repository::user_count(&s.db).await.ok() != Some(0) {
        return (
            StatusCode::CONFLICT,
            Json(ErrorEnvelope {
                code: "already_initialized".into(),
                message: "Setup has already completed".into(),
            }),
        )
            .into_response();
    }
    if req.password.len() < 12 || !req.email.contains('@') {
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
    match repository::insert_user(&s.db, &req.email, &hash, "admin").await {
        Ok(u) => {
            audit::record(&s.db, Some(u.id), "setup_completed", "admin_created").await;
            (StatusCode::CREATED, Json(u)).into_response()
        }
        Err(_) => (
            StatusCode::CONFLICT,
            Json(ErrorEnvelope {
                code: "already_initialized".into(),
                message: "Setup has already completed".into(),
            }),
        )
            .into_response(),
    }
}
async fn current(s: &AppState, h: &HeaderMap) -> Result<User, StatusCode> {
    let t = auth::cookie(h).ok_or(StatusCode::UNAUTHORIZED)?;
    repository::find_user_by_session(&s.db, &auth::token_hash(t))
        .await
        .map_err(|_| StatusCode::UNAUTHORIZED)?
        .ok_or(StatusCode::UNAUTHORIZED)
}
async fn me(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    match current(&s, &h).await {
        Ok(u) => Json(u).into_response(),
        Err(c) => c.into_response(),
    }
}
async fn list_hosts(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    if current(&s, &h).await.is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    match repository::list_hosts(&s.db).await {
        Ok(x) => Json(x).into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

async fn get_host(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    if current(&s, &h).await.is_err() {
        return StatusCode::UNAUTHORIZED.into_response();
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
    if !allowed(
        Role::parse(&u.role).unwrap_or(Role::Viewer),
        Permission::ProxyHostsWrite,
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }
    if req.name.trim().is_empty()
        || req.domain.trim().is_empty()
        || req.upstream_host.trim().is_empty()
        || req.upstream_port == 0
    {
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
                return (
                    StatusCode::BAD_GATEWAY,
                    Json(ErrorEnvelope {
                        code: "reload_failed".into(),
                        message: "Proxy host was not activated".into(),
                    }),
                )
                    .into_response();
            }
            (StatusCode::CREATED, Json(x)).into_response()
        }
        Err(_) => (
            StatusCode::CONFLICT,
            Json(ErrorEnvelope {
                code: "duplicate_domain".into(),
                message: "Domain already exists".into(),
            }),
        )
            .into_response(),
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
    if !allowed(
        Role::parse(&u.role).unwrap_or(Role::Viewer),
        Permission::ProxyHostsWrite,
    ) {
        audit::record(
            &s.db,
            Some(u.id),
            "authorization_denied",
            "proxy_host_update",
        )
        .await;
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(previous) = repository::get_host(&s.db, id).await.ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if req.name.trim().is_empty()
        || req.domain.trim().is_empty()
        || req.upstream_host.trim().is_empty()
        || req.upstream_port == 0
    {
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
        return StatusCode::CONFLICT.into_response();
    }
    let desired = DesiredConfig {
        proxy_hosts: repository::list_hosts(&s.db).await.unwrap_or_default(),
    };
    if s.reloader.apply(desired).await.is_err() {
        let _ = repository::update_host(&s.db, id, &previous).await;
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorEnvelope {
                code: "reload_failed".into(),
                message: "Proxy host update was not activated".into(),
            }),
        )
            .into_response();
    }
    audit::record(
        &s.db,
        Some(u.id),
        "proxy_host_updated",
        "configuration_changed",
    )
    .await;
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
    if !allowed(
        Role::parse(&u.role).unwrap_or(Role::Viewer),
        Permission::ProxyHostsWrite,
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(previous) = repository::get_host(&s.db, id).await.ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if repository::delete_host(&s.db, id).await.is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let desired = DesiredConfig {
        proxy_hosts: repository::list_hosts(&s.db).await.unwrap_or_default(),
    };
    if s.reloader.apply(desired).await.is_err() {
        let _ = repository::insert_host(&s.db, &previous).await;
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorEnvelope {
                code: "reload_failed".into(),
                message: "Proxy host deletion was not activated".into(),
            }),
        )
            .into_response();
    }
    audit::record(
        &s.db,
        Some(u.id),
        "proxy_host_deleted",
        "configuration_changed",
    )
    .await;
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
    if !allowed(
        Role::parse(&u.role).unwrap_or(Role::Viewer),
        Permission::CertificatesWrite,
    ) {
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
            Err(_) => return StatusCode::BAD_REQUEST.into_response(),
        };
        total += bytes.len();
        if total > 3 * 1024 * 1024 {
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
        if bytes.len() > 1024 * 1024 {
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
        return StatusCode::BAD_REQUEST.into_response();
    };
    match s.certificates.import_custom(&name, &cert, &key) {
        Ok(record) => {
            match repository::insert_certificate(&s.db,&record.name,"custom",&serde_json::to_string(&record.covered_hostnames).unwrap_or_default(),&record.expiry,&record.certificate_path.to_string_lossy(),&record.key_path.to_string_lossy()).await{Ok(id)=>(StatusCode::CREATED,Json(serde_json::json!({"id":id,"name":record.name,"source":"custom","covered_hostnames":record.covered_hostnames,"expiry":record.expiry}))).into_response(),Err(_)=>StatusCode::CONFLICT.into_response()}
        }
        Err(_) => StatusCode::BAD_REQUEST.into_response(),
    }
}

async fn list_certificates(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return c.into_response(),
    };
    if !allowed(
        Role::parse(&user.role).unwrap_or(Role::Viewer),
        Permission::CertificatesRead,
    ) {
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
    if !allowed(
        Role::parse(&user.role).unwrap_or(Role::Viewer),
        Permission::CertificatesWrite,
    ) {
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some(name) = repository::certificate_name(&s.db, id).await.ok().flatten() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if s.certificates.activate(&name).is_err() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    match repository::activate_certificate(&s.db, id).await {
        Ok(1) => {
            audit::record(
                &s.db,
                Some(user.id),
                "certificate_activated",
                "metadata_only",
            )
            .await;
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(_) => StatusCode::NOT_FOUND.into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
