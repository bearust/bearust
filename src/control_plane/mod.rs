#![allow(
    clippy::result_large_err,
    clippy::collapsible_if,
    clippy::possible_missing_else
)]
pub mod audit;
pub mod auth;
pub mod locale;
pub mod models;
pub mod rbac;
pub mod realtime;
pub mod repository;
use crate::acme::{AcmeEnvironment, AcmeManager, LetsEncryptClient};
use crate::analytics::{AnalyticsCollector, AnalyticsFilter};
use crate::analytics_prometheus::PrometheusConfig;
use crate::bot_challenge::{unix_now, ChallengeService};
use crate::bot_protection::{
    BotConfig, BotMode, BotRule, MAX_FIELD_BYTES, MAX_RULES, MAX_TRUSTED_RULES,
};
use crate::bot_store::BotStore;
use crate::certificates::{
    AcmeService as CertificateAcmeService, AcmeServiceError as CertificateAcmeError,
    CertificateStore,
};
use crate::cluster_command::{
    committed_event_kind, ClusterWriteError, CommandActor, CommitReceipt, ConfigCommandGateway,
};
use crate::cluster_raft::ConfigCommand;
use crate::rate_limit_store::RateLimiterStore;
use crate::secrets::SecretStore;
use crate::waf_store::WafStore;
use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::DefaultBodyLimit,
    extract::{
        rejection::{JsonRejection, PathRejection},
        Multipart, Path, Query, RawQuery, State,
    },
    http::{HeaderMap, StatusCode},
    response::{
        sse::{Event, KeepAlive, Sse},
        IntoResponse, Response,
    },
    routing::{get, post},
    Json, Router,
};
use chrono::{DateTime, SecondsFormat, Utc};
use futures_util::stream::unfold;
use models::*;
use rbac::{authorize, Permission, ResourceContext, Role};
use serde::Deserialize;
use std::convert::Infallible;
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
    pub waf: Arc<WafStore>,
    pub bot: Arc<BotStore>,
    pub challenges: Arc<ChallengeService>,
    /// Shared live limiter state used by both control-plane updates and the
    /// Pingora proxy worker.
    pub rate_limiter: Arc<RateLimiterStore>,
    pub analytics: Arc<AnalyticsCollector>,
    pub baseline: Arc<crate::baseline::BaselineCollector>,
    pub anomaly: Arc<crate::anomaly::AnomalyDetector>,
    pub adaptive_tuning: Arc<crate::adaptive_tuning::AdaptiveTuningEngine>,
    pub cluster: Arc<crate::cluster::ClusterService>,
    pub config_gateway: Option<ConfigCommandGateway>,
    pub prometheus: PrometheusConfig,
}

impl AppState {
    pub fn with_cluster(mut self, cluster: Arc<crate::cluster::ClusterService>) -> Self {
        self.cluster = cluster;
        self
    }

    pub fn with_config_gateway(mut self, gateway: ConfigCommandGateway) -> Self {
        self.config_gateway = Some(gateway);
        self
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BotConfigPatch {
    mode: Option<String>,
    threshold: Option<u16>,
    ttl_seconds: Option<u64>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BotCrawlerInput {
    user_agent: String,
    domain: String,
    #[serde(default = "default_true")]
    enabled: bool,
}
fn default_true() -> bool {
    true
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BotToml {
    version: u32,
    mode: Option<String>,
    threshold: Option<u16>,
    ttl_seconds: Option<u64>,
    #[serde(default)]
    trusted_crawlers: Vec<BotTomlCrawler>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BotTomlCrawler {
    user_agent: String,
    domain: String,
    #[serde(default = "default_true")]
    enabled: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WafConfigPatch {
    mode: WafMode,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RateLimitConfigPatch {
    enabled: Option<bool>,
    action: Option<crate::rate_limit::RateLimitAction>,
    capacity: Option<u32>,
    refill_per_second: Option<f64>,
    key_scope: Option<crate::rate_limit::RateLimitKeyScope>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WafRuleCreate {
    name: String,
    category: String,
    severity: String,
    #[serde(default)]
    action: WafAction,
    matcher: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WafRulePatch {
    name: Option<String>,
    category: Option<String>,
    severity: Option<String>,
    enabled: Option<bool>,
    action: Option<WafAction>,
    matcher: Option<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WafToml {
    version: u32,
    mode: Option<WafMode>,
    #[serde(default)]
    rules: Vec<WafTomlRule>,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct WafTomlRule {
    name: String,
    category: String,
    severity: String,
    #[serde(default)]
    action: WafAction,
    field: String,
    pattern: Option<String>,
    builtin: Option<String>,
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
    let waf = Arc::new(WafStore::load(&db).await.map_err(sqlx::Error::Protocol)?);
    let bot = Arc::new(BotStore::load(&db).await.map_err(sqlx::Error::Protocol)?);
    let certificates = CertificateStore::new(certificate_root)
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let certificates = Arc::new(certificates);
    let secrets = SecretStore::open(&certificate_root.join("secrets"))
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let challenges = Arc::new(
        ChallengeService::new(&secrets).map_err(|e| sqlx::Error::Protocol(e.to_string()))?,
    );
    let rate_limiter = Arc::new(RateLimiterStore::new(
        100_000,
        std::time::Duration::from_secs(900),
    ));
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
    waf.configure_audit_sink(db.clone(), realtime.clone());
    bot.configure_audit_sink(db.clone(), realtime.clone());
    certificate_acme.attach_realtime(realtime.clone());
    let emergency_disabled = repository::get_emergency_disabled(&db)
        .await
        .unwrap_or(false);
    let adaptive_tuning = Arc::new(crate::adaptive_tuning::AdaptiveTuningEngine::default());
    adaptive_tuning.set_emergency_disabled(emergency_disabled);

    if let Ok(host_configs) = repository::list_host_rate_limit_configs(&db).await {
        for (host_id, cfg) in host_configs {
            rate_limiter.set_host_policy(
                host_id,
                crate::rate_limit::RateLimitPolicy {
                    enabled: cfg.enabled,
                    action: cfg.action,
                    capacity: cfg.capacity,
                    refill_per_second: cfg.refill_per_second,
                    key_scope: cfg.key_scope,
                },
            );
        }
    }

    Ok(AppState {
        db,
        certificates,
        reloader,
        setup_token: setup_token.into(),
        auth_attempts: Arc::new(Mutex::new(HashMap::new())),
        secrets,
        acme: Arc::new(CertificateAcmeAdapter::new(certificate_acme)),
        realtime,
        waf,
        bot,
        challenges,
        rate_limiter,
        analytics: Arc::new(AnalyticsCollector::default()),
        baseline: Arc::new(crate::baseline::BaselineCollector::default()),
        anomaly: Arc::new(crate::anomaly::AnomalyDetector::default()),
        adaptive_tuning,
        cluster: Arc::new(crate::cluster::ClusterService::new(
            &crate::config::ClusterConfig::default(),
        )),
        config_gateway: None,
        prometheus: PrometheusConfig::default(),
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
    router_with_metrics(state, true)
}

/// Construct the control-plane router, optionally mounting the Prometheus
/// endpoint. When Prometheus uses a dedicated listener this must be `false`
/// so the control listener does not expose a second metrics surface.
pub fn router_with_metrics(state: AppState, include_metrics: bool) -> Router {
    let app = Router::new()
        .route("/api/health", get(health))
        .route("/api/setup/status", get(setup_status))
        .route("/api/setup/initialize", post(setup_initialize))
        .route("/api/auth/login", post(auth::login))
        .route("/api/auth/logout", post(auth::logout))
        .route("/api/auth/me", get(me))
        .route(
            "/api/auth/me/preferences",
            axum::routing::patch(update_preferences),
        )
        .route(
            "/api/bot/challenge",
            post(issue_bot_challenge).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route(
            "/api/bot/challenge/verify",
            post(verify_bot_challenge).layer(DefaultBodyLimit::max(16 * 1024)),
        )
        .route("/api/events", get(events))
        .route("/api/analytics/summary", get(analytics_summary))
        .route("/api/analytics/timeseries", get(analytics_timeseries))
        .route("/api/analytics/baseline", get(analytics_baseline))
        .route("/api/analytics/anomalies", get(list_anomalies))
        .route(
            "/api/analytics/anomalies/{id}/ack",
            post(acknowledge_anomaly),
        )
        .route(
            "/api/adaptive-tuning/policy/{host_id}",
            get(get_tuning_policy).put(update_tuning_policy),
        )
        .route(
            "/api/adaptive-tuning/recommendations",
            get(list_recommendations),
        )
        .route(
            "/api/adaptive-tuning/recommendations/{id}/apply",
            post(apply_recommendation),
        )
        .route(
            "/api/adaptive-tuning/recommendations/{id}/rollback",
            post(rollback_recommendation),
        )
        .route(
            "/api/adaptive-tuning/emergency-disable",
            post(emergency_disable_tuning),
        )
        .route(
            "/api/waf/config",
            get(get_waf_config).patch(update_waf_config),
        )
        .route(
            "/api/rate-limit/config",
            get(get_rate_limit_config).patch(update_rate_limit_config),
        )
        .route("/api/waf/rules", get(list_waf_rules).post(create_waf_rule))
        .route(
            "/api/waf/rules/{id}",
            axum::routing::patch(update_waf_rule).delete(delete_waf_rule),
        )
        .route("/api/waf/rules/import", post(import_waf_rules))
        .route("/api/waf/rules/export", get(export_waf_rules))
        .route(
            "/api/bot/config",
            get(get_bot_config).patch(update_bot_config),
        )
        .route(
            "/api/bot/trusted-crawlers",
            get(list_bot_crawlers).post(create_bot_crawler),
        )
        .route(
            "/api/bot/trusted-crawlers/{id}",
            axum::routing::patch(update_bot_crawler).delete(delete_bot_crawler),
        )
        .route("/api/bot/config/import", post(import_bot_config))
        .route("/api/bot/config/export", get(export_bot_config))
        .route("/api/audit-logs", get(list_audit_logs))
        .route("/api/users", get(list_users).post(create_user))
        .route(
            "/api/users/{id}",
            axum::routing::patch(update_user).delete(delete_user),
        )
        .route("/api/roles", get(list_roles).post(create_role))
        .route(
            "/api/roles/{id}",
            get(get_role).patch(update_role).delete(delete_role),
        )
        .route(
            "/api/users/{id}/sessions/revoke",
            post(revoke_user_sessions),
        )
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
        .route("/api/cluster/status", get(get_cluster_status))
        .route("/api/certificates/{id}/renew", post(renew_acme))
        .route("/api/certificates/{id}/status", get(acme_status));
    let app = if include_metrics {
        app.route("/metrics", get(prometheus_metrics))
    } else {
        app
    };
    app.layer(DefaultBodyLimit::max(3 * 1024 * 1024))
        .with_state(state)
        .fallback_service(ServeDir::new("/usr/share/bearust/frontend"))
}

/// Router for a dedicated Prometheus listener. Keep this surface limited to
/// the metrics endpoint so a separate bind never exposes the control plane or
/// frontend assets.
pub fn prometheus_router(state: AppState) -> Router {
    Router::new()
        .route("/metrics", get(prometheus_metrics))
        .with_state(state)
}

async fn prometheus_metrics(State(s): State<AppState>, h: HeaderMap) -> Response {
    if !s.prometheus.enabled {
        return StatusCode::NOT_FOUND.into_response();
    }
    if s.prometheus.require_auth {
        if current(&s, &h).await.is_err() {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }
    match crate::analytics_prometheus::render(&s.analytics.snapshot(), &s.prometheus) {
        Ok(body) => (
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; version=0.0.4",
            )],
            body,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeInput {
    fingerprint: String,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ChallengeVerifyInput {
    token: String,
    fingerprint: String,
    solution: String,
}
async fn issue_bot_challenge(
    State(s): State<AppState>,
    Json(input): Json<ChallengeInput>,
) -> impl IntoResponse {
    if input.fingerprint.is_empty()
        || input.fingerprint.len() > crate::bot_challenge::MAX_FINGERPRINT_BYTES
    {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid challenge",
        );
    }
    let challenge = match s
        .challenges
        .issue_challenge(&input.fingerprint, unix_now())
        .await
    {
        Ok(value) => value,
        Err(_) => {
            return user_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "challenge_failed",
                "Challenge unavailable",
            )
        }
    };
    (
        [(axum::http::header::CACHE_CONTROL, "no-store")],
        Json(challenge),
    )
        .into_response()
}
async fn verify_bot_challenge(
    State(s): State<AppState>,
    Json(input): Json<ChallengeVerifyInput>,
) -> impl IntoResponse {
    let result = s
        .challenges
        .verify_solution(
            &input.token,
            &input.fingerprint,
            &input.solution,
            unix_now(),
        )
        .await;
    if result.is_err() {
        return user_error(
            StatusCode::BAD_REQUEST,
            "challenge_failed",
            "Challenge verification failed",
        );
    }
    let clearance = match s.challenges.issue_clearance(&input.fingerprint, unix_now()) {
        Ok(token) => token,
        Err(_) => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "challenge_failed",
                "Challenge verification failed",
            )
        }
    };
    let cookie = format!(
        "bearust_bot_clear={}; Max-Age=300; Path=/; Secure; HttpOnly; SameSite=Strict",
        clearance
    );
    (
        [
            (axum::http::header::SET_COOKIE, cookie),
            (axum::http::header::CACHE_CONTROL, "no-store".to_string()),
        ],
        Json(serde_json::json!({"ok":true})),
    )
        .into_response()
}

async fn require_bot_admin(s: &AppState, h: &HeaderMap) -> Result<User, Response> {
    let user = current(s, h)
        .await
        .map_err(|status| user_error(status, "unauthorized", "Authentication required"))?;
    if !authorize(
        &s.db,
        &user,
        Permission::BotProtectionManage,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(s, Some(user.id), "bot_mutation_denied", "authorization").await;
        return Err(user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Administrator access required",
        ));
    }
    Ok(user)
}

fn bot_mode(value: &str) -> Option<BotMode> {
    match value {
        "monitor" | "monitor-only" => Some(BotMode::Monitor),
        "challenge" => Some(BotMode::Challenge),
        "block" => Some(BotMode::Block),
        _ => None,
    }
}
fn bot_record(config: &BotConfig) -> BotConfigRecord {
    BotConfigRecord {
        mode: match config.mode {
            BotMode::Monitor => "monitor",
            BotMode::Challenge => "challenge",
            BotMode::Block => "block",
        }
        .into(),
        threshold: config.threshold,
        ttl_seconds: config.ttl_seconds,
        updated_at: Utc::now().to_rfc3339(),
    }
}
fn bot_rule_record(id: i64, rule: BotRule) -> BotRuleRecord {
    BotRuleRecord {
        id,
        category: rule.category,
        weight: rule.weight,
        trusted_user_agent: rule.trusted_user_agent,
        trusted_domain: rule.trusted_domain,
        enabled: rule.enabled,
    }
}
async fn get_bot_config(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    if let Err(r) = require_bot_admin(&s, &h).await {
        return r;
    }
    match repository::get_bot_config(&s.db).await {
        Ok(c) => Json(bot_record(&c)).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}
async fn update_bot_config(
    State(s): State<AppState>,
    h: HeaderMap,
    input: Result<Json<BotConfigPatch>, JsonRejection>,
) -> impl IntoResponse {
    let actor = match require_bot_admin(&s, &h).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let Json(input) = match input {
        Ok(v) => v,
        Err(_) => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid bot configuration",
            )
        }
    };
    let mut config = match repository::get_bot_config(&s.db).await {
        Ok(c) => c,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    };
    let previous = config.clone();
    if let Some(mode) = input.mode {
        config.mode = match bot_mode(&mode) {
            Some(v) => v,
            None => {
                return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid bot mode")
            }
        };
    }
    if let Some(v) = input.threshold {
        config.threshold = v;
    }
    if let Some(v) = input.ttl_seconds {
        config.ttl_seconds = v;
    }
    if repository::update_bot_config(&s.db, &config).await.is_err() {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid bot configuration",
        );
    }
    if s.bot.reload(&s.db).await.is_err() {
        let _ = repository::update_bot_config(&s.db, &previous).await;
        let _ = s.bot.reload(&s.db).await;
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid bot configuration",
        );
    }
    audit::record_state(
        &s,
        Some(actor.id),
        "bot_config_updated",
        &format!(
            "mode={};threshold={};ttl_seconds={}",
            bot_record(&config).mode,
            config.threshold,
            config.ttl_seconds
        ),
    )
    .await;
    s.realtime.publish("bot.changed");
    Json(bot_record(&config)).into_response()
}
async fn list_bot_crawlers(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    if let Err(r) = require_bot_admin(&s, &h).await {
        return r;
    }
    match repository::list_bot_rule_records(&s.db).await {
        Ok(rules) => Json(
            rules
                .into_iter()
                .filter(|(_, r)| r.category == "trusted_crawler")
                .map(|(id, r)| bot_rule_record(id, r))
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}
async fn create_bot_crawler(
    State(s): State<AppState>,
    h: HeaderMap,
    input: Result<Json<BotCrawlerInput>, JsonRejection>,
) -> impl IntoResponse {
    let actor = match require_bot_admin(&s, &h).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let Json(i) = match input {
        Ok(v) => v,
        Err(_) => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid trusted crawler",
            )
        }
    };
    let rule = BotRule::trusted_crawler(i.user_agent, i.domain);
    let rule = BotRule {
        enabled: i.enabled,
        ..rule
    };
    let id = match repository::insert_bot_rule(&s.db, &rule).await {
        Ok(id) => id,
        Err(_) => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid trusted crawler",
            )
        }
    };
    if s.bot.reload(&s.db).await.is_err() {
        let _ = repository::delete_bot_rule(&s.db, id).await;
        let _ = s.bot.reload(&s.db).await;
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to reload bot policy",
        );
    };
    audit::record_state(
        &s,
        Some(actor.id),
        "bot_trusted_crawler_created",
        &format!("rule_id={id}"),
    )
    .await;
    s.realtime.publish("bot.changed");
    (StatusCode::CREATED, Json(bot_rule_record(id, rule))).into_response()
}
async fn update_bot_crawler(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    input: Result<Json<BotCrawlerInput>, JsonRejection>,
) -> impl IntoResponse {
    let actor = match require_bot_admin(&s, &h).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let previous = match repository::list_bot_rule_records(&s.db).await {
        Ok(v) => v
            .into_iter()
            .find(|(rule_id, r)| *rule_id == id && r.category == "trusted_crawler"),
        Err(_) => None,
    };
    let Some((_, old)) = previous else {
        return user_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Trusted crawler not found",
        );
    };
    let Json(i) = match input {
        Ok(v) => v,
        Err(_) => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid trusted crawler",
            )
        }
    };
    let rule = BotRule {
        enabled: i.enabled,
        ..BotRule::trusted_crawler(i.user_agent, i.domain)
    };
    if repository::update_bot_rule(&s.db, id, &rule)
        .await
        .unwrap_or(0)
        != 1
    {
        return user_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Trusted crawler not found",
        );
    };
    if s.bot.reload(&s.db).await.is_err() {
        let _ = repository::update_bot_rule(&s.db, id, &old).await;
        let _ = s.bot.reload(&s.db).await;
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to reload bot policy",
        );
    };
    audit::record_state(
        &s,
        Some(actor.id),
        "bot_trusted_crawler_updated",
        &format!("rule_id={id}"),
    )
    .await;
    s.realtime.publish("bot.changed");
    Json(bot_rule_record(id, rule)).into_response()
}
async fn delete_bot_crawler(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let actor = match require_bot_admin(&s, &h).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let previous = match repository::list_bot_rule_records(&s.db).await {
        Ok(v) => v
            .into_iter()
            .find(|(rule_id, r)| *rule_id == id && r.category == "trusted_crawler"),
        Err(_) => None,
    };
    let Some((_, rule)) = previous else {
        return user_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Trusted crawler not found",
        );
    };
    if repository::delete_bot_rule(&s.db, id).await.unwrap_or(0) != 1 {
        return user_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Trusted crawler not found",
        );
    };
    if s.bot.reload(&s.db).await.is_err() {
        let _ = repository::restore_bot_rule(&s.db, id, &rule).await;
        let _ = s.bot.reload(&s.db).await;
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to reload bot policy",
        );
    };
    audit::record_state(
        &s,
        Some(actor.id),
        "bot_trusted_crawler_deleted",
        &format!("rule_id={id}"),
    )
    .await;
    s.realtime.publish("bot.changed");
    StatusCode::NO_CONTENT.into_response()
}
async fn import_bot_config(
    State(s): State<AppState>,
    h: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let actor = match require_bot_admin(&s, &h).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    const MAX_BOT_TOML_BYTES: usize = 64 * 1024;
    if body.len() > MAX_BOT_TOML_BYTES {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Bot TOML is too large",
        );
    }
    let doc = match String::from_utf8(body.to_vec())
        .ok()
        .and_then(|t| toml::from_str::<BotToml>(&t).ok())
    {
        Some(v) if v.version == 1 => v,
        _ => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid bot TOML"),
    };
    if doc.trusted_crawlers.len() > MAX_TRUSTED_RULES || doc.trusted_crawlers.len() > MAX_RULES {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Too many trusted crawlers",
        );
    }
    let mut config = match repository::get_bot_config(&s.db).await {
        Ok(v) => v,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    };
    let previous = match repository::list_bot_rules(&s.db).await {
        Ok(v) => v,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    };
    let previous_config = config.clone();
    if let Some(m) = doc.mode {
        config.mode = match bot_mode(&m) {
            Some(v) => v,
            None => {
                return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid bot mode")
            }
        };
    }
    if let Some(v) = doc.threshold {
        config.threshold = v;
    }
    if let Some(v) = doc.ttl_seconds {
        config.ttl_seconds = v;
    }
    for c in &doc.trusted_crawlers {
        if c.user_agent.len() > MAX_FIELD_BYTES
            || c.domain.len() > MAX_FIELD_BYTES
            || c.user_agent.trim().is_empty()
            || c.domain.trim().is_empty()
        {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid trusted crawler",
            );
        }
    }
    let rules = doc
        .trusted_crawlers
        .into_iter()
        .map(|c| BotRule {
            enabled: c.enabled,
            ..BotRule::trusted_crawler(c.user_agent, c.domain)
        })
        .collect::<Vec<_>>();
    if repository::replace_bot_policy(&s.db, &config, &rules)
        .await
        .is_err()
    {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Unable to import bot policy",
        );
    }
    if s.bot.reload(&s.db).await.is_err() {
        let _ = repository::replace_bot_policy(&s.db, &previous_config, &previous).await;
        let _ = s.bot.reload(&s.db).await;
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to reload bot policy",
        );
    }
    audit::record_state(&s, Some(actor.id), "bot_config_imported", "redacted").await;
    s.realtime.publish("bot.changed");
    StatusCode::OK.into_response()
}
async fn export_bot_config(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    if let Err(r) = require_bot_admin(&s, &h).await {
        return r;
    }
    let c = match repository::get_bot_config(&s.db).await {
        Ok(v) => v,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    };
    let rules = match repository::list_bot_rules(&s.db).await {
        Ok(v) => v,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    };
    let mut out = format!(
        "version = 1\nmode = '{}'\nthreshold = {}\nttl_seconds = {}\n",
        bot_record(&c).mode,
        c.threshold,
        c.ttl_seconds
    );
    for r in rules
        .into_iter()
        .filter(|r| r.category == "trusted_crawler")
    {
        let ua = r.trusted_user_agent.unwrap_or_default().replace('\'', "''");
        let domain = r.trusted_domain.unwrap_or_default().replace('\'', "''");
        out.push_str(&format!(
            "\n[[trusted_crawlers]]\nuser_agent = '{}'\ndomain = '{}'\nenabled = {}\n",
            ua, domain, r.enabled
        ));
    }
    (
        [(axum::http::header::CONTENT_TYPE, "application/toml")],
        out,
    )
        .into_response()
}

async fn get_waf_config(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    if let Err(response) = require_role_admin(&s, &h).await {
        return response;
    }
    match repository::get_waf_config(&s.db).await {
        Ok(config) => Json(config).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}
async fn require_rate_limit_admin(s: &AppState, h: &HeaderMap) -> Result<User, Response> {
    let user = current(s, h)
        .await
        .map_err(|status| user_error(status, "unauthorized", "Authentication required"))?;
    if !authorize(
        &s.db,
        &user,
        Permission::SystemSettingsManage,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(
            s,
            Some(user.id),
            "rate_limit_mutation_denied",
            "authorization",
        )
        .await;
        return Err(user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Administrator access required",
        ));
    }
    Ok(user)
}
async fn get_rate_limit_config(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    if let Err(r) = require_rate_limit_admin(&s, &h).await {
        return r;
    }
    match repository::get_rate_limit_config(&s.db).await {
        Ok(c) => Json(c).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}
async fn update_rate_limit_config(
    State(s): State<AppState>,
    h: HeaderMap,
    input: Result<Json<RateLimitConfigPatch>, JsonRejection>,
) -> impl IntoResponse {
    let actor = match require_rate_limit_admin(&s, &h).await {
        Ok(u) => u,
        Err(r) => return r,
    };
    let Json(i) = match input {
        Ok(v) => v,
        Err(_) => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid rate-limit configuration",
            )
        }
    };
    let mut c = match repository::get_rate_limit_config(&s.db).await {
        Ok(v) => v,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    };
    if let Some(v) = i.enabled {
        c.enabled = v;
    }
    if let Some(v) = i.action {
        c.action = v;
    }
    if let Some(v) = i.capacity {
        c.capacity = v;
    }
    if let Some(v) = i.refill_per_second {
        c.refill_per_second = v;
    }
    if let Some(v) = i.key_scope {
        c.key_scope = v;
    }
    if repository::update_rate_limit_config(&s.db, &c)
        .await
        .is_err()
    {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid rate-limit configuration",
        );
    }
    s.rate_limiter
        .set_policy(crate::rate_limit::RateLimitPolicy {
            enabled: c.enabled,
            action: c.action,
            capacity: c.capacity,
            refill_per_second: c.refill_per_second,
            key_scope: c.key_scope,
        });
    audit::record_state(
        &s,
        Some(actor.id),
        "rate_limit_config_updated",
        "policy_changed",
    )
    .await;
    s.realtime.publish("rate_limit.changed");
    match repository::get_rate_limit_config(&s.db).await {
        Ok(v) => Json(v).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

async fn update_waf_config(
    State(s): State<AppState>,
    h: HeaderMap,
    input: Result<Json<WafConfigPatch>, JsonRejection>,
) -> impl IntoResponse {
    let actor = match require_role_admin(&s, &h).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Json(input) = match input {
        Ok(value) => value,
        Err(_) => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid WAF configuration",
            )
        }
    };
    if repository::update_waf_mode(&s.db, input.mode)
        .await
        .is_err()
        || s.waf.reload(&s.db).await.is_err()
    {
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to update WAF configuration",
        );
    }
    audit::record_state(&s, Some(actor.id), "waf_config_updated", "mode_changed").await;
    s.realtime.publish("waf.changed");
    Json(repository::get_waf_config(&s.db).await.unwrap()).into_response()
}

async fn list_waf_rules(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    if let Err(response) = require_role_admin(&s, &h).await {
        return response;
    }
    match repository::list_waf_rules(&s.db).await {
        Ok(rules) => Json(rules).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

fn validate_waf_rule(rule: &WafRule) -> Result<(), ()> {
    crate::waf::compile_snapshot(
        WafConfig {
            mode: WafMode::MonitorOnly,
            updated_at: String::new(),
        },
        vec![rule.clone()],
    )
    .map(|_| ())
    .map_err(|_| ())
}

async fn create_waf_rule(
    State(s): State<AppState>,
    h: HeaderMap,
    input: Result<Json<WafRuleCreate>, JsonRejection>,
) -> impl IntoResponse {
    let actor = match require_role_admin(&s, &h).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Json(input) = match input {
        Ok(value) => value,
        Err(_) => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid WAF rule"),
    };
    if input.name.trim().is_empty()
        || input.name.len() > 128
        || input.category.len() > 64
        || input.severity.len() > 16
    {
        return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid WAF rule");
    }
    let rule = WafRule {
        id: 0,
        name: input.name.trim().into(),
        source: "custom".into(),
        category: input.category,
        severity: input.severity,
        enabled: true,
        action: input.action,
        matcher_json: input.matcher.to_string(),
        created_at: String::new(),
        updated_at: String::new(),
    };
    if validate_waf_rule(&rule).is_err() {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid matcher definition",
        );
    }
    let id = match repository::insert_waf_rule(&s.db, &rule).await {
        Ok(id) => id,
        Err(_) => {
            return user_error(
                StatusCode::CONFLICT,
                "conflict",
                "Unable to create WAF rule",
            )
        }
    };
    if s.waf.reload(&s.db).await.is_err() {
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to reload WAF rules",
        );
    }
    audit::record_state(
        &s,
        Some(actor.id),
        "waf_rule_created",
        &format!("rule_id={id};category={}", rule.category),
    )
    .await;
    s.realtime.publish("waf.changed");
    (
        StatusCode::CREATED,
        Json(
            repository::list_waf_rules(&s.db)
                .await
                .unwrap()
                .into_iter()
                .find(|item| item.id == id)
                .unwrap(),
        ),
    )
        .into_response()
}

async fn update_waf_rule(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    input: Result<Json<WafRulePatch>, JsonRejection>,
) -> impl IntoResponse {
    let actor = match require_role_admin(&s, &h).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Json(input) = match input {
        Ok(value) => value,
        Err(_) => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid WAF rule"),
    };
    let Some(mut rule) = repository::list_waf_rules(&s.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|item| item.id == id)
    else {
        return user_error(StatusCode::NOT_FOUND, "not_found", "WAF rule not found");
    };
    if rule.source != "custom" {
        return user_error(
            StatusCode::CONFLICT,
            "conflict",
            "Built-in WAF rules cannot be changed",
        );
    }
    if let Some(name) = input.name {
        rule.name = name;
    }
    if let Some(category) = input.category {
        rule.category = category;
    }
    if let Some(severity) = input.severity {
        rule.severity = severity;
    }
    if let Some(enabled) = input.enabled {
        rule.enabled = enabled;
    }
    if let Some(action) = input.action {
        rule.action = action;
    }
    if let Some(matcher) = input.matcher {
        rule.matcher_json = matcher.to_string();
    }
    if validate_waf_rule(&rule).is_err()
        || repository::update_waf_rule(&s.db, id, &rule)
            .await
            .unwrap_or(0)
            != 1
    {
        return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid WAF rule");
    }
    if s.waf.reload(&s.db).await.is_err() {
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to reload WAF rules",
        );
    }
    audit::record_state(
        &s,
        Some(actor.id),
        "waf_rule_updated",
        &format!("rule_id={id};category={}", rule.category),
    )
    .await;
    s.realtime.publish("waf.changed");
    Json(rule).into_response()
}

async fn delete_waf_rule(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let actor = match require_role_admin(&s, &h).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Some(rule) = repository::list_waf_rules(&s.db)
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|item| item.id == id)
    else {
        return user_error(StatusCode::NOT_FOUND, "not_found", "WAF rule not found");
    };
    if rule.source != "custom" {
        return user_error(
            StatusCode::CONFLICT,
            "conflict",
            "Built-in WAF rules cannot be deleted",
        );
    }
    if repository::delete_waf_rule(&s.db, id).await.unwrap_or(0) != 1 {
        return user_error(StatusCode::NOT_FOUND, "not_found", "WAF rule not found");
    }
    let _ = s.waf.reload(&s.db).await;
    audit::record_state(
        &s,
        Some(actor.id),
        "waf_rule_deleted",
        &format!("rule_id={id};category={}", rule.category),
    )
    .await;
    s.realtime.publish("waf.changed");
    StatusCode::NO_CONTENT.into_response()
}

async fn import_waf_rules(
    State(s): State<AppState>,
    h: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    let actor = match require_role_admin(&s, &h).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let document: WafToml = match String::from_utf8(body.to_vec())
        .ok()
        .and_then(|text| toml::from_str::<WafToml>(&text).ok())
    {
        Some(value) if value.version == 1 => value,
        _ => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid WAF TOML"),
    };
    let mut rules = Vec::new();
    for item in document.rules {
        let matcher = serde_json::json!({"field": item.field, "pattern": item.pattern, "builtin": item.builtin});
        let rule = WafRule {
            id: 0,
            name: item.name,
            source: "custom".into(),
            category: item.category,
            severity: item.severity,
            enabled: true,
            action: item.action,
            matcher_json: matcher.to_string(),
            created_at: String::new(),
            updated_at: String::new(),
        };
        if validate_waf_rule(&rule).is_err() {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid WAF matcher",
            );
        }
        rules.push(rule);
    }
    for rule in &rules {
        if repository::insert_waf_rule(&s.db, rule).await.is_err() {
            return user_error(
                StatusCode::CONFLICT,
                "conflict",
                "Unable to import WAF rules",
            );
        }
    }
    if let Some(mode) = document.mode {
        let _ = repository::update_waf_mode(&s.db, mode).await;
    }
    if s.waf.reload(&s.db).await.is_err() {
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to reload WAF rules",
        );
    }
    audit::record_state(
        &s,
        Some(actor.id),
        "waf_rules_imported",
        &format!("count={}", rules.len()),
    )
    .await;
    s.realtime.publish("waf.changed");
    StatusCode::OK.into_response()
}

async fn export_waf_rules(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    if let Err(response) = require_role_admin(&s, &h).await {
        return response;
    }
    let config = match repository::get_waf_config(&s.db).await {
        Ok(value) => value,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    };
    let rules = match repository::list_waf_rules(&s.db).await {
        Ok(value) => value,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    };
    let mut output = format!(
        "version = 1\nmode = '{}'\n",
        serde_json::to_string(&config.mode)
            .unwrap()
            .trim_matches('"')
    );
    for rule in rules.into_iter().filter(|rule| rule.source == "custom") {
        if let Ok(matcher) = serde_json::from_str::<serde_json::Value>(&rule.matcher_json) {
            output.push_str(&format!("\n[[rules]]\nname = '{}'\ncategory = '{}'\nseverity = '{}'\naction = '{}'\nfield = '{}'\n", rule.name.replace('\'', "''"), rule.category, rule.severity, serde_json::to_string(&rule.action).unwrap().trim_matches('"'), matcher["field"].as_str().unwrap_or("any")));
            if let Some(pattern) = matcher["pattern"].as_str() {
                output.push_str(&format!("pattern = '{}'\n", pattern.replace('\'', "''")));
            }
        }
    }
    (
        [(axum::http::header::CONTENT_TYPE, "application/toml")],
        output,
    )
        .into_response()
}

fn user_error(status: StatusCode, code: &str, message: &str) -> axum::response::Response {
    (
        status,
        Json(ErrorEnvelope {
            code: code.into(),
            message: message.into(),
        }),
    )
        .into_response()
}

enum ConfigSubmissionError {
    Cluster(ClusterWriteError),
    LocalApplyPending(CommitReceipt),
    Database,
}

fn command_actor(user: &User) -> CommandActor {
    CommandActor {
        user_id: user.id,
        email: user.email.clone(),
        role: user.role.clone(),
    }
}

async fn submit_config_command(
    state: &AppState,
    command: ConfigCommand,
    actor: &User,
) -> Result<CommitReceipt, ConfigSubmissionError> {
    submit_config_command_as(state, command, command_actor(actor)).await
}

async fn submit_config_command_as(
    state: &AppState,
    command: ConfigCommand,
    actor: CommandActor,
) -> Result<CommitReceipt, ConfigSubmissionError> {
    if let Some(gateway) = &state.config_gateway {
        return match gateway
            .submit_with_standalone_fallback(command, actor)
            .await
        {
            Ok(receipt) => Ok(receipt),
            Err(ClusterWriteError::LocalApplyPending { receipt }) => {
                Err(ConfigSubmissionError::LocalApplyPending(receipt))
            }
            Err(error) => Err(ConfigSubmissionError::Cluster(error)),
        };
    }

    if !state.cluster.is_single_node() {
        return Err(ConfigSubmissionError::Cluster(
            ClusterWriteError::ClusterUnavailable,
        ));
    }

    let result = repository::apply_raft_command(&state.db, &command)
        .await
        .map_err(|_| ConfigSubmissionError::Database)?;
    match result {
        crate::cluster_raft::CommandResult::Applied
        | crate::cluster_raft::CommandResult::Duplicate => {}
        crate::cluster_raft::CommandResult::DuplicateDomain => {
            return Err(ConfigSubmissionError::Cluster(
                ClusterWriteError::DuplicateDomain,
            ))
        }
        crate::cluster_raft::CommandResult::IdCollision => {
            return Err(ConfigSubmissionError::Cluster(
                ClusterWriteError::IdCollision,
            ))
        }
        crate::cluster_raft::CommandResult::NotFound => {
            return Err(ConfigSubmissionError::Cluster(ClusterWriteError::NotFound))
        }
    }
    Ok(CommitReceipt {
        command_id: command.command_id(),
        leader_id: 0,
        commit_index: 0,
    })
}

async fn submit_config_command_leader_only_as(
    state: &AppState,
    command: ConfigCommand,
    actor: CommandActor,
) -> Result<CommitReceipt, ConfigSubmissionError> {
    if let Some(gateway) = &state.config_gateway {
        return match gateway
            .submit_leader_only_with_standalone_fallback(command, actor)
            .await
        {
            Ok(receipt) => Ok(receipt),
            Err(ClusterWriteError::LocalApplyPending { receipt }) => {
                Err(ConfigSubmissionError::LocalApplyPending(receipt))
            }
            Err(error) => Err(ConfigSubmissionError::Cluster(error)),
        };
    }
    if !state.cluster.is_single_node() {
        return Err(ConfigSubmissionError::Cluster(
            ClusterWriteError::ClusterUnavailable,
        ));
    }

    let result = repository::apply_raft_command(&state.db, &command)
        .await
        .map_err(|_| ConfigSubmissionError::Database)?;
    if !matches!(
        result,
        crate::cluster_raft::CommandResult::Applied | crate::cluster_raft::CommandResult::Duplicate
    ) {
        return Err(ConfigSubmissionError::Cluster(match result {
            crate::cluster_raft::CommandResult::DuplicateDomain => {
                ClusterWriteError::DuplicateDomain
            }
            crate::cluster_raft::CommandResult::IdCollision => ClusterWriteError::IdCollision,
            crate::cluster_raft::CommandResult::NotFound => ClusterWriteError::NotFound,
            crate::cluster_raft::CommandResult::Applied
            | crate::cluster_raft::CommandResult::Duplicate => unreachable!(),
        }));
    }
    Ok(CommitReceipt {
        command_id: command.command_id(),
        leader_id: 0,
        commit_index: 0,
    })
}

fn cluster_write_response(error: ClusterWriteError) -> Response {
    match error {
        ClusterWriteError::LeaderUnknown => user_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster_leader_unknown",
            "Cluster leader is unavailable",
        ),
        ClusterWriteError::QuorumUnavailable => user_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster_quorum_unavailable",
            "Cluster quorum is unavailable",
        ),
        ClusterWriteError::ClusterUnavailable => user_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster_unavailable",
            "Cluster configuration gateway is unavailable",
        ),
        ClusterWriteError::CommitOutcomeUnknown => user_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "cluster_commit_outcome_unknown",
            "Configuration commit outcome is unknown",
        ),
        ClusterWriteError::ForwardTimeout => user_error(
            StatusCode::GATEWAY_TIMEOUT,
            "cluster_forward_timeout",
            "Cluster write forwarding timed out",
        ),
        ClusterWriteError::LocalApplyPending { .. } => user_error(
            StatusCode::ACCEPTED,
            "local_apply_pending",
            "Configuration committed but local application is pending",
        ),
        ClusterWriteError::ForwardAuthentication => user_error(
            StatusCode::FORBIDDEN,
            "cluster_forward_authentication",
            "Cluster write authorization failed",
        ),
        ClusterWriteError::InvalidCommand | ClusterWriteError::NotReplicatedCommand => user_error(
            StatusCode::BAD_REQUEST,
            "invalid_command",
            "Configuration command is invalid",
        ),
        ClusterWriteError::DuplicateDomain => user_error(
            StatusCode::CONFLICT,
            "duplicate_domain",
            "Domain already exists",
        ),
        ClusterWriteError::IdCollision => user_error(
            StatusCode::CONFLICT,
            "id_collision",
            "Proxy host identifier already exists",
        ),
        ClusterWriteError::NotFound => {
            user_error(StatusCode::NOT_FOUND, "not_found", "Proxy host not found")
        }
    }
}

fn publish_committed_command(state: &AppState, command: &ConfigCommand, receipt: &CommitReceipt) {
    if let Some(kind) = committed_event_kind(command) {
        state.realtime.publish_committed(kind, receipt);
    }
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
    let user = current(s, h)
        .await
        .map_err(|status| status.into_response())?;
    if !authorize(
        &s.db,
        &user,
        Permission::UsersManage,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(
            s,
            Some(user.id),
            "user_mutation_denied",
            &user_audit(None, "authorization"),
        )
        .await;
        return Err(user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Administrator access required",
        ));
    }
    Ok(user)
}

async fn list_users(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    if let Err(response) = require_user_admin(&s, &h).await {
        return response;
    }
    match repository::list_users(&s.db).await {
        Ok(users) => Json(users).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

fn role_audit(role: &RoleDetail, before: Option<&[String]>, after: Option<&[String]>) -> String {
    serde_json::json!({"role_id": role.id, "slug": role.slug, "before": before.map(|x| x.to_vec()), "after": after.map(|x| x.to_vec()), "scopes": role.scopes}).to_string()
}

fn role_scope_audit(role: &RoleDetail) -> String {
    let read_assignments = role
        .scopes
        .iter()
        .find(|scope| scope.permission == "proxy_hosts.read")
        .map_or(0, |scope| scope.proxy_host_ids.len());
    let write_assignments = role
        .scopes
        .iter()
        .find(|scope| scope.permission == "proxy_hosts.write")
        .map_or(0, |scope| scope.proxy_host_ids.len());
    serde_json::json!({"role_id": role.id, "read_assignments": read_assignments, "write_assignments": write_assignments}).to_string()
}

fn role_scope_error(error: &sqlx::Error) -> Option<StatusCode> {
    let message = error.to_string().to_ascii_lowercase();
    (message.contains("invalid role scope")
        || message.contains("duplicate")
        || message.contains("unknown proxy host")
        || message.contains("invalid permission"))
    .then_some(StatusCode::BAD_REQUEST)
}

async fn require_role_admin(s: &AppState, h: &HeaderMap) -> Result<User, axum::response::Response> {
    let user = current(s, h)
        .await
        .map_err(|status| user_error(status, "unauthorized", "Authentication required"))?;
    if !authorize(
        &s.db,
        &user,
        Permission::RolesManage,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(s, Some(user.id), "role_mutation_denied", "authorization").await;
        return Err(user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Administrator access required",
        ));
    }
    Ok(user)
}

fn normalize_role_slug(raw: &str) -> Option<String> {
    let slug = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>();
    let slug = slug
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    (!slug.is_empty() && slug.len() <= 64).then_some(slug)
}

fn validate_role_input(name: &str, permissions: &[String]) -> Result<(), ()> {
    if name.trim().is_empty()
        || permissions.iter().any(|key| {
            !matches!(
                key.as_str(),
                "proxy_hosts.read"
                    | "proxy_hosts.write"
                    | "certificates.read"
                    | "certificates.write"
                    | "users.manage"
                    | "roles.manage"
                    | "audit_logs.read"
                    | "audit_logs.export"
                    | "system.settings.manage"
                    | "sessions.revoke"
                    | "bot_protection.manage"
            )
        })
    {
        return Err(());
    }
    Ok(())
}

async fn list_roles(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    let _actor = match require_role_admin(&s, &h).await {
        Ok(u) => u,
        Err(response) => return response,
    };
    match repository::list_roles(&s.db).await {
        Ok(roles) => Json(roles).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

async fn get_role(
    State(s): State<AppState>,
    h: HeaderMap,
    path: Result<Path<i64>, PathRejection>,
) -> impl IntoResponse {
    let _actor = match require_role_admin(&s, &h).await {
        Ok(u) => u,
        Err(response) => return response,
    };
    let Path(id) = match path {
        Ok(path) => path,
        Err(_) => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role id"),
    };
    match repository::get_role(&s.db, id).await {
        Ok(Some(role)) => Json(role).into_response(),
        Ok(None) => user_error(StatusCode::NOT_FOUND, "not_found", "Role not found"),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

async fn create_role(
    State(s): State<AppState>,
    h: HeaderMap,
    input: Result<Json<RoleCreate>, JsonRejection>,
) -> impl IntoResponse {
    let actor = match require_role_admin(&s, &h).await {
        Ok(u) => u,
        Err(response) => return response,
    };
    let input = match input {
        Ok(Json(input)) => input,
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                "reason=invalid_input",
            )
            .await;
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid role request",
            );
        }
    };
    let Some(slug) = normalize_role_slug(&input.slug) else {
        audit::record_state(
            &s,
            Some(actor.id),
            "role_mutation_denied",
            "reason=invalid_slug",
        )
        .await;
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid role slug",
        );
    };
    if validate_role_input(&input.name, &input.permissions).is_err() {
        audit::record_state(
            &s,
            Some(actor.id),
            "role_mutation_denied",
            &format!("slug={slug};reason=invalid_input"),
        )
        .await;
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid role name or permission",
        );
    }
    let keys = input
        .permissions
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let role = match repository::insert_role_with_permissions_and_scopes(
        &s.db,
        &slug,
        input.name.trim(),
        input.description.trim(),
        &keys,
        &input.scopes,
    )
    .await
    {
        Ok(role) => role,
        Err(error) if error.to_string().to_ascii_lowercase().contains("unique") => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &format!("slug={slug};reason=duplicate"),
            )
            .await;
            return user_error(StatusCode::CONFLICT, "conflict", "Role slug already exists");
        }
        Err(error) if role_scope_error(&error).is_some() => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &format!("slug={slug};reason=invalid_scope"),
            )
            .await;
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid role scope",
            );
        }
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &format!("slug={slug};reason=database_error"),
            )
            .await;
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            );
        }
    };
    let details = role_audit(&role, None, Some(&role.permissions));
    audit::record_state(&s, Some(actor.id), "role_created", &details).await;
    audit::record_state(&s, Some(actor.id), "role_permissions_changed", &details).await;
    if !role.scopes.is_empty() {
        audit::record_state(
            &s,
            Some(actor.id),
            "role_scopes_changed",
            &role_scope_audit(&role),
        )
        .await;
    }
    s.realtime.publish("roles.changed");
    (StatusCode::CREATED, Json(role)).into_response()
}

async fn update_role(
    State(s): State<AppState>,
    h: HeaderMap,
    path: Result<Path<i64>, PathRejection>,
    input: Result<Json<RolePatch>, JsonRejection>,
) -> impl IntoResponse {
    let actor = match require_role_admin(&s, &h).await {
        Ok(u) => u,
        Err(response) => return response,
    };
    let Path(id) = match path {
        Ok(path) => path,
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                "reason=invalid_input",
            )
            .await;
            return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role id");
        }
    };
    let Some(before) = (match repository::get_role(&s.db, id).await {
        Ok(role) => role,
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &format!("role_id={id};reason=database_error"),
            )
            .await;
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            );
        }
    }) else {
        audit::record_state(
            &s,
            Some(actor.id),
            "role_mutation_denied",
            &format!("role_id={id};reason=not_found"),
        )
        .await;
        return user_error(StatusCode::NOT_FOUND, "not_found", "Role not found");
    };
    if before.system_managed {
        audit::record_state(
            &s,
            Some(actor.id),
            "role_mutation_denied",
            &role_audit(&before, None, None),
        )
        .await;
        return user_error(
            StatusCode::CONFLICT,
            "conflict",
            "Built-in roles cannot be mutated",
        );
    }
    let input = match input {
        Ok(Json(input)) => input,
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &role_audit(&before, None, None),
            )
            .await;
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid role request",
            );
        }
    };
    if input
        .name
        .as_deref()
        .is_some_and(|name| name.trim().is_empty())
        || input
            .permissions
            .as_ref()
            .is_some_and(|permissions| validate_role_input("valid", permissions).is_err())
    {
        audit::record_state(
            &s,
            Some(actor.id),
            "role_mutation_denied",
            &role_audit(&before, None, None),
        )
        .await;
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Invalid role update",
        );
    }
    let keys = input
        .permissions
        .as_ref()
        .map(|permissions| permissions.iter().map(String::as_str).collect::<Vec<_>>());
    let updated = match repository::update_role_with_permissions_and_scopes(
        &s.db,
        id,
        input.name.as_deref().map(str::trim),
        input.description.as_deref().map(str::trim),
        keys.as_deref(),
        input.scopes.as_deref(),
    )
    .await
    {
        Ok(Some(role)) => role,
        Ok(None) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &format!("role_id={id};reason=not_found"),
            )
            .await;
            return user_error(StatusCode::NOT_FOUND, "not_found", "Role not found");
        }
        Err(error) if role_scope_error(&error).is_some() => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &role_audit(&before, None, None),
            )
            .await;
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid role scope",
            );
        }
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &role_audit(&before, None, None),
            )
            .await;
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            );
        }
    };
    let details = role_audit(
        &updated,
        Some(&before.permissions),
        Some(&updated.permissions),
    );
    audit::record_state(&s, Some(actor.id), "role_updated", &details).await;
    if input.permissions.is_some() {
        audit::record_state(&s, Some(actor.id), "role_permissions_changed", &details).await;
    }
    if input.scopes.is_some() {
        audit::record_state(
            &s,
            Some(actor.id),
            "role_scopes_changed",
            &role_scope_audit(&updated),
        )
        .await;
    }
    s.realtime.publish("roles.changed");
    if input.permissions.is_some() {
        s.realtime.publish("sessions.changed");
    }
    Json(updated).into_response()
}

async fn delete_role(
    State(s): State<AppState>,
    h: HeaderMap,
    path: Result<Path<i64>, PathRejection>,
) -> impl IntoResponse {
    let actor = match require_role_admin(&s, &h).await {
        Ok(u) => u,
        Err(response) => return response,
    };
    let Path(id) = match path {
        Ok(path) => path,
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                "reason=invalid_input",
            )
            .await;
            return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role id");
        }
    };
    let Some(role) = (match repository::get_role(&s.db, id).await {
        Ok(role) => role,
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &format!("role_id={id};reason=database_error"),
            )
            .await;
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            );
        }
    }) else {
        audit::record_state(
            &s,
            Some(actor.id),
            "role_mutation_denied",
            &format!("role_id={id};reason=not_found"),
        )
        .await;
        return user_error(StatusCode::NOT_FOUND, "not_found", "Role not found");
    };
    if role.system_managed {
        audit::record_state(
            &s,
            Some(actor.id),
            "role_mutation_denied",
            &role_audit(&role, None, None),
        )
        .await;
        return user_error(
            StatusCode::CONFLICT,
            "conflict",
            "Built-in roles cannot be deleted",
        );
    }
    match repository::delete_role(&s.db, id).await {
        Ok(1) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_deleted",
                &role_audit(&role, Some(&role.permissions), None),
            )
            .await;
            s.realtime.publish("roles.changed");
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(count) if count == 0 || count > 1 => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &role_audit(&role, None, None),
            )
            .await;
            user_error(StatusCode::NOT_FOUND, "not_found", "Role not found")
        }
        Ok(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &role_audit(&role, None, None),
            )
            .await;
            user_error(StatusCode::NOT_FOUND, "not_found", "Role not found")
        }
        Err(error) if error.to_string().contains("assigned") => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &role_audit(&role, Some(&role.permissions), None),
            )
            .await;
            user_error(
                StatusCode::CONFLICT,
                "conflict",
                "Role is assigned to users",
            )
        }
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "role_mutation_denied",
                &role_audit(&role, Some(&role.permissions), None),
            )
            .await;
            user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    }
}

async fn create_user(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(input): Json<UserCreate>,
) -> impl IntoResponse {
    let actor = match require_user_admin(&s, &h).await {
        Ok(u) => u,
        Err(response) => return response,
    };
    let email = input.email.trim().to_ascii_lowercase();
    let role = input.role.trim();
    if !email.contains('@')
        || input.password.len() < 12
        || !role_slug_exists(&s, role).await.unwrap_or(false)
    {
        audit::record_state(
            &s,
            Some(actor.id),
            "user_create_denied",
            &user_audit(None, "invalid_input"),
        )
        .await;
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Valid email, role, and password of at least 12 characters required",
        );
    }
    let hash = match auth::hash_password(&input.password) {
        Ok(hash) => hash,
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_create_failed",
                &user_audit(None, "hashing_error"),
            )
            .await;
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal_error",
                "Unable to create user",
            );
        }
    };
    match repository::insert_user(&s.db, &email, &hash, role).await {
        Ok(user) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_created",
                &user_audit(Some(user.id), "success"),
            )
            .await;
            s.realtime.publish("users.changed");
            (StatusCode::CREATED, Json(user)).into_response()
        }
        Err(error) if error.to_string().to_ascii_lowercase().contains("unique") => {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_create_denied",
                &user_audit(None, "duplicate_email"),
            )
            .await;
            user_error(
                StatusCode::CONFLICT,
                "duplicate_email",
                "Email already exists",
            )
        }
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_create_failed",
                &user_audit(None, "database_error"),
            )
            .await;
            user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    }
}

async fn update_user(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
    Json(input): Json<UserPatch>,
) -> impl IntoResponse {
    let actor = match require_user_admin(&s, &h).await {
        Ok(u) => u,
        Err(response) => return response,
    };
    let target_exists = repository::list_users(&s.db)
        .await
        .ok()
        .is_some_and(|users| users.into_iter().any(|u| u.id == id));
    if !target_exists {
        audit::record_state(
            &s,
            Some(actor.id),
            "user_update_denied",
            &user_audit(Some(id), "not_found"),
        )
        .await;
        return user_error(StatusCode::NOT_FOUND, "not_found", "User not found");
    }
    if input.role.is_none() && input.disabled.is_none() {
        audit::record_state(
            &s,
            Some(actor.id),
            "user_update_denied",
            &user_audit(Some(id), "invalid_input"),
        )
        .await;
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "At least one field is required",
        );
    }
    if actor.id == id && input.disabled == Some(true) {
        audit::record_state(
            &s,
            Some(actor.id),
            "user_update_denied",
            &user_audit(Some(id), "self_disable"),
        )
        .await;
        return user_error(
            StatusCode::FORBIDDEN,
            "self_mutation",
            "You cannot disable your own account",
        );
    }
    if let Some(role) = input.role.as_deref() {
        if !role_slug_exists(&s, role.trim()).await.unwrap_or(false) {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_update_denied",
                &user_audit(Some(id), "invalid_role"),
            )
            .await;
            return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid role");
        }
    }
    let role = input.role.as_deref().map(str::trim);
    let updated = match repository::update_user(&s.db, id, role, input.disabled).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_update_denied",
                &user_audit(Some(id), "not_found"),
            )
            .await;
            return user_error(StatusCode::NOT_FOUND, "not_found", "User not found");
        }
        Err(error) if error.to_string().contains("last active") => {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_update_denied",
                &user_audit(Some(id), "last_admin"),
            )
            .await;
            return user_error(
                StatusCode::CONFLICT,
                "last_admin",
                "Cannot remove the last active administrator",
            );
        }
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_update_failed",
                &user_audit(Some(id), "database_error"),
            )
            .await;
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            );
        }
    };
    let detail = if input.disabled == Some(true) {
        "user_disabled"
    } else {
        "user_updated"
    };
    audit::record_state(&s, Some(actor.id), detail, &user_audit(Some(id), "success")).await;
    s.realtime.publish("users.changed");
    if input.role.is_some() || input.disabled.is_some() {
        s.realtime.publish("sessions.changed");
    }
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
    if !authorize(
        &s.db,
        &actor,
        Permission::SessionsRevoke,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(
            &s,
            Some(actor.id),
            "session_revoke_denied",
            "reason=authorization",
        )
        .await;
        return user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Administrator access required",
        );
    }
    let Path(id) = match path {
        Ok(path) => path,
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "session_revoke_denied",
                "reason=invalid_input",
            )
            .await;
            return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid user id");
        }
    };
    if actor.id == id {
        audit::record_state(
            &s,
            Some(actor.id),
            "session_revoke_denied",
            &user_audit(Some(id), "self_target"),
        )
        .await;
        return user_error(
            StatusCode::FORBIDDEN,
            "self_mutation",
            "You cannot revoke your own sessions",
        );
    }
    let target_exists = match repository::list_users(&s.db).await {
        Ok(users) => users.into_iter().any(|user| user.id == id),
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "session_revoke_denied",
                &user_audit(Some(id), "database_error"),
            )
            .await;
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            );
        }
    };
    if !target_exists {
        audit::record_state(
            &s,
            Some(actor.id),
            "session_revoke_denied",
            &user_audit(Some(id), "not_found"),
        )
        .await;
        return user_error(StatusCode::NOT_FOUND, "not_found", "User not found");
    }
    match repository::revoke_user_sessions(&s.db, id).await {
        Ok(revoked) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "sessions_revoked",
                &format!("target_user_id={id};count={revoked}"),
            )
            .await;
            s.realtime.publish("sessions.changed");
            Json(SessionsRevokeResponse { revoked }).into_response()
        }
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "session_revoke_denied",
                &user_audit(Some(id), "database_error"),
            )
            .await;
            user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
    }
}

async fn delete_user(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> impl IntoResponse {
    let actor = match require_user_admin(&s, &h).await {
        Ok(u) => u,
        Err(response) => return response,
    };
    if actor.id == id {
        audit::record_state(
            &s,
            Some(actor.id),
            "user_delete_denied",
            &user_audit(Some(id), "self_delete"),
        )
        .await;
        return user_error(
            StatusCode::FORBIDDEN,
            "self_mutation",
            "You cannot delete your own account",
        );
    }
    match repository::delete_user(&s.db, id).await {
        Ok(0) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_delete_denied",
                &user_audit(Some(id), "not_found"),
            )
            .await;
            user_error(StatusCode::NOT_FOUND, "not_found", "User not found")
        }
        Ok(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_deleted",
                &user_audit(Some(id), "success"),
            )
            .await;
            s.realtime.publish("users.changed");
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) if error.to_string().contains("last active") => {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_delete_denied",
                &user_audit(Some(id), "last_admin"),
            )
            .await;
            user_error(
                StatusCode::CONFLICT,
                "last_admin",
                "Cannot remove the last active administrator",
            )
        }
        Err(_) => {
            audit::record_state(
                &s,
                Some(actor.id),
                "user_delete_failed",
                &user_audit(Some(id), "database_error"),
            )
            .await;
            user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database unavailable",
            )
        }
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
    if !authorize(
        &s.db,
        &user,
        Permission::CertificatesWrite,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(&s, Some(user.id), "authorization_denied", "acme_issue").await;
        return StatusCode::FORBIDDEN.into_response();
    }
    let req = match input.request().normalized() {
        Ok(r) => r,
        Err(_e) => {
            let code = "invalid_hostname";
            audit::record_state(&s, Some(user.id), "acme_issue_failed", code).await;
            return acme_error(StatusCode::BAD_REQUEST, code, "Invalid ACME hostname");
        }
    };
    if matches!(&req.challenge, AcmeChallenge::Http01)
        && req.hostnames.iter().any(|x| x.starts_with("*."))
    {
        audit::record_state(
            &s,
            Some(user.id),
            "acme_issue_failed",
            "unsupported_challenge",
        )
        .await;
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
            acme_error(
                StatusCode::CONFLICT,
                "acme_busy",
                "An ACME operation is already running",
            )
        }
        Err(_) => {
            audit::record_state(&s, Some(user.id), "acme_issue_failed", "service_error").await;
            acme_error(
                StatusCode::BAD_GATEWAY,
                "acme_failed",
                "ACME operation failed",
            )
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
    if !authorize(
        &s.db,
        &user,
        Permission::CertificatesWrite,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(
            &s,
            Some(user.id),
            "authorization_denied",
            "CertificatesWrite",
        )
        .await;
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
            acme_error(
                StatusCode::CONFLICT,
                "acme_busy",
                "An ACME operation is already running",
            )
        }
        Err(_) => {
            audit::record_state(&s, Some(user.id), "acme_renew_failed", "service_error").await;
            acme_error(
                StatusCode::BAD_GATEWAY,
                "acme_failed",
                "ACME operation failed",
            )
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
    if !authorize(
        &s.db,
        &user,
        Permission::CertificatesRead,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(
            &s,
            Some(user.id),
            "authorization_denied",
            "CertificatesRead",
        )
        .await;
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
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
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
        return user_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Authentication required",
        );
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
    let stream = unfold(
        (receiver, true, s, h, revalidation),
        |(mut receiver, ready, state, headers, mut revalidation)| async move {
            if ready {
                let event = Event::default().event("ready").data("{}");
                return Some((
                    Ok::<Event, Infallible>(event),
                    (receiver, false, state, headers, revalidation),
                ));
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
        },
    );
    let mut response = Sse::new(stream)
        .keep_alive(
            KeepAlive::new()
                .interval(Duration::from_secs(15))
                .text("heartbeat"),
        )
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

async fn update_preferences(
    State(s): State<AppState>,
    h: HeaderMap,
    Json(input): Json<UserPreferencesPatch>,
) -> impl IntoResponse {
    let user = match current(&s, &h).await {
        Ok(user) => user,
        Err(status) => return user_error(status, "unauthorized", "Authentication required"),
    };
    let preferred_locale = match input.preferred_locale {
        Some(Some(value)) => match locale::validate_locale(&value) {
            Ok(locale) => Some(locale),
            Err(_) => {
                return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid locale")
            }
        },
        Some(None) => None,
        None => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid locale"),
    };
    match repository::update_user_preferred_locale(&s.db, user.id, preferred_locale).await {
        Ok(Some(updated)) => Json(updated).into_response(),
        Ok(None) => user_error(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "Authentication required",
        ),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
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
    if !authorize(
        &s.db,
        &user,
        Permission::AuditLogsRead,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(&s, Some(user.id), "authorization_denied", "AuditLogsRead").await;
        return StatusCode::FORBIDDEN.into_response();
    }

    let page = match params.page.as_deref().unwrap_or("1").parse::<u32>() {
        Ok(value) if value >= 1 => value,
        _ => return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid page"),
    };
    let page_size = match params.page_size.as_deref().unwrap_or("25").parse::<u32>() {
        Ok(value) if (1..=100).contains(&value) => value,
        _ => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid page size",
            )
        }
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
            Err(_) => {
                return user_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_input",
                    "Invalid timestamp",
                )
            }
        },
        None => None,
    };
    let to = match params.to.as_deref().filter(|value| !value.is_empty()) {
        Some(value) => match normalize_audit_timestamp(value) {
            Ok(value) => Some(value),
            Err(_) => {
                return user_error(
                    StatusCode::BAD_REQUEST,
                    "invalid_input",
                    "Invalid timestamp",
                )
            }
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
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnalyticsQuery {
    proxy_host_id: Option<i64>,
    from: Option<String>,
    to: Option<String>,
    limit: Option<usize>,
}
fn parse_analytics_query(raw: Option<String>) -> Result<AnalyticsQuery, ()> {
    raw.as_deref()
        .map(serde_urlencoded::from_str)
        .transpose()
        .map_err(|_| ())
        .map(|v| {
            v.unwrap_or(AnalyticsQuery {
                proxy_host_id: None,
                from: None,
                to: None,
                limit: None,
            })
        })
}
fn analytics_filter(q: AnalyticsQuery) -> Result<AnalyticsFilter, ()> {
    let from = q
        .from
        .as_deref()
        .map(DateTime::parse_from_rfc3339)
        .transpose()
        .map_err(|_| ())?
        .map(|v| v.with_timezone(&Utc));
    let to =
        q.to.as_deref()
            .map(DateTime::parse_from_rfc3339)
            .transpose()
            .map_err(|_| ())?
            .map(|v| v.with_timezone(&Utc));
    if q.proxy_host_id.is_some_and(|id| id <= 0)
        || q.limit.unwrap_or(0) > crate::analytics::DEFAULT_MAX_BUCKETS
    {
        return Err(());
    }
    if let (Some(a), Some(b)) = (from, to) {
        if a > b || b.signed_duration_since(a) > chrono::Duration::hours(24) {
            return Err(());
        }
    }
    Ok(AnalyticsFilter {
        proxy_host_id: q.proxy_host_id,
        from,
        to,
        limit: q.limit.unwrap_or(0),
    })
}
async fn require_analytics_read(
    s: &AppState,
    h: &HeaderMap,
    host: Option<i64>,
) -> Result<User, Response> {
    let user = current(s, h)
        .await
        .map_err(|c| user_error(c, "unauthorized", "Authentication required"))?;
    let allowed = match host {
        Some(id) => authorize(
            &s.db,
            &user,
            Permission::ProxyHostsRead,
            ResourceContext::ProxyHost(id),
        )
        .await
        .unwrap_or(false),
        None => authorize(
            &s.db,
            &user,
            Permission::ProxyHostsRead,
            ResourceContext::GLOBAL,
        )
        .await
        .unwrap_or(false),
    };
    if !allowed {
        return Err(user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Analytics access denied",
        ));
    }
    Ok(user)
}
async fn analytics_summary(
    State(s): State<AppState>,
    h: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let q = match parse_analytics_query(raw).and_then(analytics_filter) {
        Ok(v) => v,
        Err(_) => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid analytics query",
            )
        }
    };
    if let Err(r) = require_analytics_read(&s, &h, q.proxy_host_id).await {
        return r;
    }
    Json(s.analytics.summary(q)).into_response()
}
async fn analytics_timeseries(
    State(s): State<AppState>,
    h: HeaderMap,
    RawQuery(raw): RawQuery,
) -> Response {
    let q = match parse_analytics_query(raw).and_then(analytics_filter) {
        Ok(v) => v,
        Err(_) => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid analytics query",
            )
        }
    };
    if let Err(r) = require_analytics_read(&s, &h, q.proxy_host_id).await {
        return r;
    }
    Json(s.analytics.timeseries(q)).into_response()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BaselineQuery {
    proxy_host_id: Option<i64>,
    window: Option<String>,
}

async fn analytics_baseline(
    State(s): State<AppState>,
    h: HeaderMap,
    Query(query): Query<BaselineQuery>,
) -> Response {
    if let Some(host_id) = query.proxy_host_id {
        if host_id <= 0 {
            return user_error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid host id");
        }
    }
    if let Err(r) = require_analytics_read(&s, &h, query.proxy_host_id).await {
        return r;
    }
    let window = match query.window.as_deref() {
        None | Some("5m") | Some("5minutes") => crate::baseline::BaselineWindow::FiveMinutes,
        Some("1h") | Some("1hour") => crate::baseline::BaselineWindow::OneHour,
        Some("24h") | Some("24hours") => crate::baseline::BaselineWindow::TwentyFourHours,
        _ => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "invalid_input",
                "Invalid window parameter",
            )
        }
    };

    s.baseline.record(&s.analytics.snapshot(), Utc::now());
    let now = Utc::now();
    let from = now - chrono::Duration::seconds(window.duration_seconds());
    let snap = s.baseline.snapshot(query.proxy_host_id, window, from, now);
    Json(snap).into_response()
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AnomalyQuery {
    host_id: Option<i64>,
    severity: Option<String>,
    rule: Option<String>,
}

fn has_auto_enforcement_authority(state: &AppState) -> bool {
    match &state.config_gateway {
        Some(gateway) if gateway.has_initialized_membership() => {
            gateway.is_confirmed_local_leader()
        }
        _ => state.cluster.is_single_node(),
    }
}

pub async fn run_adaptive_evaluation_tick(s: &AppState, allow_auto_enforce: bool) {
    let now = Utc::now();
    let analytics = s.analytics.snapshot();
    let hosts = repository::list_hosts(&s.db).await.unwrap_or_default();
    let mut baseline_updated = false;
    let can_auto_enforce = allow_auto_enforce && has_auto_enforcement_authority(s);

    for host in &hosts {
        // 1. Take baseline snapshot BEFORE recording current traffic into baseline (prevents spike normalization)
        let baseline = s.baseline.snapshot(
            Some(host.id),
            crate::baseline::BaselineWindow::FiveMinutes,
            now - chrono::Duration::minutes(5),
            now,
        );

        // 2. Evaluate anomalies
        let new_anomalies = s.anomaly.evaluate(&baseline, &analytics, now);
        if !new_anomalies.is_empty() {
            s.realtime.publish("anomaly.changed");
        }

        // 3. Record current snapshot into baseline ONLY on background scheduler tick
        if allow_auto_enforce {
            s.baseline.record(&analytics, now);
            baseline_updated = true;
        }

        // 4. Generate recommendations & auto-enforce if mode is Enforce and allow_auto_enforce is true
        let policy = repository::get_tuning_policy(&s.db, host.id)
            .await
            .unwrap_or_default();
        let current_config = repository::get_host_rate_limit_config(&s.db, host.id).await;
        let current_rl = match &current_config {
            Ok(c) => crate::rate_limit::RateLimitPolicy {
                enabled: c.enabled,
                action: c.action,
                capacity: c.capacity,
                refill_per_second: c.refill_per_second,
                key_scope: c.key_scope,
            },
            Err(_) => crate::rate_limit::RateLimitPolicy::default(),
        };

        for anomaly in &new_anomalies {
            if let Some(rec) = s.adaptive_tuning.recommend(anomaly, &current_rl, &policy) {
                if allow_auto_enforce {
                    if let Ok(Some(rec_id)) = repository::insert_tuning_recommendation_dedup(
                        &s.db,
                        &rec,
                        policy.cooldown_seconds as i64,
                    )
                    .await
                    {
                        s.realtime.publish("adaptive_tuning.changed");

                        // Auto-enforce if policy mode is Enforce, not emergency disabled, and confidence >= min_confidence
                        if policy.mode == crate::adaptive_tuning::TuningMode::Enforce
                            && !s.adaptive_tuning.is_emergency_disabled()
                            && rec.confidence >= policy.min_confidence
                            && can_auto_enforce
                        {
                            let current = match &current_config {
                                Ok(current) => current,
                                Err(error) => {
                                    audit::record_state(
                                        s,
                                        None,
                                        "adaptive_tuning_auto_enforce_failed",
                                        &format!(
                                            "recommendation_id={rec_id};host_id={};reason=database_error",
                                            rec.host_id
                                        ),
                                    )
                                    .await;
                                    tracing::error!(
                                        event = "adaptive_tuning_auto_enforce_failed",
                                        recommendation_id = rec_id,
                                        host_id = rec.host_id,
                                        error = %error
                                    );
                                    continue;
                                }
                            };
                            let previous_config_json = match serde_json::to_string(current) {
                                Ok(previous) => previous,
                                Err(_) => {
                                    audit::record_state(
                                        s,
                                        None,
                                        "adaptive_tuning_auto_enforce_failed",
                                        &format!(
                                            "recommendation_id={rec_id};host_id={};reason=serialization_error",
                                            rec.host_id
                                        ),
                                    )
                                    .await;
                                    tracing::error!(
                                        event = "adaptive_tuning_auto_enforce_failed",
                                        recommendation_id = rec_id,
                                        host_id = rec.host_id,
                                        reason = "serialization_error"
                                    );
                                    continue;
                                }
                            };
                            let mut runtime_policy = crate::rate_limit::RateLimitPolicy {
                                enabled: current.enabled,
                                action: current.action,
                                capacity: current.capacity,
                                refill_per_second: current.refill_per_second,
                                key_scope: current.key_scope,
                            };
                            if let Some(capacity) = rec.patch.capacity {
                                runtime_policy.capacity = capacity;
                            }
                            if let Some(refill_per_second) = rec.patch.refill_per_second {
                                runtime_policy.refill_per_second = refill_per_second;
                            }
                            let command = ConfigCommand::UpdateRuntimePolicy {
                                command_id: Uuid::new_v4(),
                                host_id: rec.host_id,
                                policy: runtime_policy.clone(),
                            };
                            let receipt = match submit_config_command_leader_only_as(
                                s,
                                command.clone(),
                                CommandActor::system(),
                            )
                            .await
                            {
                                Ok(receipt) => receipt,
                                Err(ConfigSubmissionError::Cluster(error)) => {
                                    audit::record_state(
                                        s,
                                        None,
                                        "adaptive_tuning_auto_enforce_failed",
                                        &format!(
                                            "recommendation_id={rec_id};host_id={};reason=cluster_write_failed",
                                            rec.host_id
                                        ),
                                    )
                                    .await;
                                    tracing::warn!(
                                        event = "adaptive_tuning_auto_enforce_failed",
                                        recommendation_id = rec_id,
                                        host_id = rec.host_id,
                                        error = %error
                                    );
                                    continue;
                                }
                                Err(ConfigSubmissionError::LocalApplyPending(receipt)) => {
                                    audit::record_state(
                                        s,
                                        None,
                                        "adaptive_tuning_auto_enforce_committed",
                                        &format!(
                                            "recommendation_id={rec_id};host_id={};state=committed",
                                            rec.host_id
                                        ),
                                    )
                                    .await;
                                    audit::record_state(
                                        s,
                                        None,
                                        "adaptive_tuning_auto_enforce_activation_pending",
                                        &format!(
                                            "recommendation_id={rec_id};host_id={};reason=local_apply_pending",
                                            rec.host_id
                                        ),
                                    )
                                    .await;
                                    publish_committed_command(s, &command, &receipt);
                                    continue;
                                }
                                Err(ConfigSubmissionError::Database) => {
                                    audit::record_state(
                                        s,
                                        None,
                                        "adaptive_tuning_auto_enforce_failed",
                                        &format!(
                                            "recommendation_id={rec_id};host_id={};reason=database_error",
                                            rec.host_id
                                        ),
                                    )
                                    .await;
                                    continue;
                                }
                            };
                            s.rate_limiter.set_host_policy(rec.host_id, runtime_policy);
                            publish_committed_command(s, &command, &receipt);
                            if !matches!(
                                repository::mark_tuning_recommendation_applied(
                                    &s.db,
                                    rec_id,
                                    &previous_config_json,
                                )
                                .await,
                                Ok(true)
                            ) {
                                audit::record_state(
                                    s,
                                    None,
                                    "adaptive_tuning_auto_enforce_metadata_failed",
                                    &format!(
                                        "recommendation_id={rec_id};host_id={};reason=metadata_update_failed",
                                        rec.host_id
                                    ),
                                )
                                .await;
                                continue;
                            }
                            audit::record_state(
                                s,
                                None,
                                "adaptive_tuning_auto_enforced",
                                &format!(
                                    "recommendation_id={rec_id};host_id={};confidence={};state=committed",
                                    rec.host_id, rec.confidence
                                ),
                            )
                            .await;
                            s.realtime.publish("adaptive_tuning.changed");
                        }
                    }
                }
            }
        }
    }

    if baseline_updated {
        s.realtime.publish("baseline.changed");
    }
}

async fn list_anomalies(
    State(s): State<AppState>,
    h: HeaderMap,
    Query(query): Query<AnomalyQuery>,
) -> Response {
    if let Err(r) = require_analytics_read(&s, &h, query.host_id).await {
        return r;
    }

    let severity = query.severity.as_deref().and_then(|s| match s {
        "info" => Some(crate::anomaly::AnomalySeverity::Info),
        "warning" => Some(crate::anomaly::AnomalySeverity::Warning),
        "critical" => Some(crate::anomaly::AnomalySeverity::Critical),
        _ => None,
    });

    let rule = query.rule.as_deref().and_then(|r| match r {
        "request_rate" => Some(crate::anomaly::AnomalyRule::RequestRate),
        "error_rate" => Some(crate::anomaly::AnomalyRule::ErrorRate),
        "latency" => Some(crate::anomaly::AnomalyRule::Latency),
        "security_events" => Some(crate::anomaly::AnomalyRule::SecurityEvents),
        _ => None,
    });

    let records = s.anomaly.get_anomalies(query.host_id, severity, rule);
    Json(records).into_response()
}

async fn acknowledge_anomaly(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<u64>,
) -> Response {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return user_error(c, "unauthorized", "Authentication required"),
    };

    let record = match s.anomaly.get_record(id) {
        Some(r) => r,
        None => {
            return user_error(
                StatusCode::NOT_FOUND,
                "not_found",
                "Anomaly record not found",
            )
        }
    };

    let ctx = ResourceContext::ProxyHost(record.host_id);
    let allowed = authorize(&s.db, &user, Permission::ProxyHostsWrite, ctx)
        .await
        .unwrap_or(false)
        || authorize(
            &s.db,
            &user,
            Permission::ProxyHostsWrite,
            ResourceContext::GLOBAL,
        )
        .await
        .unwrap_or(false);

    if !allowed {
        return user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Mutation access denied for this host",
        );
    }

    match s.anomaly.acknowledge(id) {
        Some(rec) => {
            audit::record_state(
                &s,
                Some(user.id),
                "anomaly_acknowledged",
                &format!("anomaly_id={id};host_id={}", rec.host_id),
            )
            .await;
            s.realtime.publish("anomaly.changed");
            Json(rec).into_response()
        }
        None => user_error(
            StatusCode::NOT_FOUND,
            "not_found",
            "Anomaly record not found",
        ),
    }
}

async fn get_tuning_policy(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(host_id): Path<i64>,
) -> Response {
    if let Err(r) = require_analytics_read(&s, &h, Some(host_id)).await {
        return r;
    }
    match repository::get_tuning_policy(&s.db, host_id).await {
        Ok(policy) => Json(policy).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

async fn update_tuning_policy(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(host_id): Path<i64>,
    Json(input): Json<crate::adaptive_tuning::TuningPolicy>,
) -> Response {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return user_error(c, "unauthorized", "Authentication required"),
    };
    if !authorize(
        &s.db,
        &user,
        Permission::SystemSettingsManage,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        return user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Administrator access required",
        );
    }

    if let Err(err_msg) = input.validate() {
        return user_error(StatusCode::BAD_REQUEST, "invalid_input", err_msg);
    }

    if repository::update_tuning_policy(&s.db, host_id, &input)
        .await
        .is_err()
    {
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to update policy",
        );
    }

    audit::record_state(
        &s,
        Some(user.id),
        "adaptive_tuning_policy_updated",
        &format!("host_id={host_id};mode={:?}", input.mode),
    )
    .await;
    s.realtime.publish("adaptive_tuning.changed");
    Json(input).into_response()
}

async fn list_recommendations(State(s): State<AppState>, h: HeaderMap) -> Response {
    if let Err(r) = require_analytics_read(&s, &h, None).await {
        return r;
    }

    match repository::list_tuning_recommendations(&s.db).await {
        Ok(list) => Json(list).into_response(),
        Err(_) => user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

async fn apply_recommendation(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return user_error(c, "unauthorized", "Authentication required"),
    };
    if !authorize(
        &s.db,
        &user,
        Permission::SystemSettingsManage,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        return user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Administrator access required",
        );
    }

    if s.adaptive_tuning.is_emergency_disabled() {
        return user_error(
            StatusCode::CONFLICT,
            "emergency_disabled",
            "Adaptive tuning is globally disabled",
        );
    }

    let rec = match repository::get_tuning_recommendation(&s.db, id).await {
        Ok(Some(r)) => r,
        Ok(None) => {
            return user_error(
                StatusCode::NOT_FOUND,
                "recommendation_not_found",
                "Recommendation not found",
            )
        }
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Database error",
            )
        }
    };

    let policy = repository::get_tuning_policy(&s.db, rec.host_id)
        .await
        .unwrap_or_default();
    if policy.mode == crate::adaptive_tuning::TuningMode::Monitor {
        return user_error(
            StatusCode::BAD_REQUEST,
            "monitor_mode_only",
            "Adaptive tuning for this host is set to monitor-only mode",
        );
    }
    if rec.applied {
        return user_error(
            StatusCode::BAD_REQUEST,
            "already_applied_or_not_found",
            "Recommendation cannot be applied",
        );
    }
    let current = match repository::get_host_rate_limit_config(&s.db, rec.host_id).await {
        Ok(current) => current,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Unable to read runtime policy",
            )
        }
    };
    let previous_config_json = match serde_json::to_string(&current) {
        Ok(value) => value,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Unable to prepare runtime policy",
            )
        }
    };
    let mut runtime_policy = crate::rate_limit::RateLimitPolicy {
        enabled: current.enabled,
        action: current.action,
        capacity: current.capacity,
        refill_per_second: current.refill_per_second,
        key_scope: current.key_scope,
    };
    if let Some(capacity) = rec.patch.capacity {
        runtime_policy.capacity = capacity;
    }
    if let Some(refill_per_second) = rec.patch.refill_per_second {
        runtime_policy.refill_per_second = refill_per_second;
    }
    if runtime_policy.validate().is_err() {
        return user_error(
            StatusCode::BAD_REQUEST,
            "invalid_input",
            "Recommendation contains an invalid runtime policy",
        );
    }
    let host_id = rec.host_id;
    let command = ConfigCommand::UpdateRuntimePolicy {
        command_id: Uuid::new_v4(),
        host_id,
        policy: runtime_policy.clone(),
    };
    let receipt = match submit_config_command(&s, command.clone(), &user).await {
        Ok(receipt) => receipt,
        Err(ConfigSubmissionError::Cluster(error)) => return cluster_write_response(error),
        Err(ConfigSubmissionError::LocalApplyPending(receipt)) => {
            audit::record_state(
                &s,
                Some(user.id),
                "recommendation_apply_committed",
                &format!("recommendation_id={id};host_id={host_id};state=committed"),
            )
            .await;
            audit::record_state(
                &s,
                Some(user.id),
                "recommendation_activation_pending",
                &format!(
                    "recommendation_id={id};host_id={host_id};operation=apply;reason=local_apply_pending"
                ),
            )
            .await;
            publish_committed_command(&s, &command, &receipt);
            return cluster_write_response(ClusterWriteError::LocalApplyPending { receipt });
        }
        Err(ConfigSubmissionError::Database) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Runtime policy update failed",
            )
        }
    };
    s.rate_limiter
        .set_host_policy(host_id, runtime_policy.clone());
    let marked =
        repository::mark_tuning_recommendation_applied(&s.db, id, &previous_config_json).await;
    if !matches!(marked, Ok(true)) {
        audit::record_state(
            &s,
            Some(user.id),
            "recommendation_apply_failed",
            &format!("recommendation_id={id};host_id={host_id};reason=metadata_update_failed"),
        )
        .await;
        publish_committed_command(&s, &command, &receipt);
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Runtime policy committed but recommendation metadata could not be updated",
        );
    }

    audit::record_state(
        &s,
        Some(user.id),
        "recommendation_applied",
        &format!("recommendation_id={id};host_id={host_id}"),
    )
    .await;
    s.realtime.publish("adaptive_tuning.changed");
    publish_committed_command(&s, &command, &receipt);
    StatusCode::OK.into_response()
}

async fn rollback_recommendation(
    State(s): State<AppState>,
    h: HeaderMap,
    Path(id): Path<i64>,
) -> Response {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return user_error(c, "unauthorized", "Authentication required"),
    };
    if !authorize(
        &s.db,
        &user,
        Permission::SystemSettingsManage,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        return user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Administrator access required",
        );
    }

    let rec = match repository::get_tuning_recommendation(&s.db, id).await {
        Ok(Some(rec)) if rec.applied => rec,
        Ok(Some(_)) | Ok(None) => {
            return user_error(
                StatusCode::BAD_REQUEST,
                "not_applied_or_not_found",
                "Recommendation cannot be rolled back",
            )
        }
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Unable to read recommendation",
            )
        }
    };
    let Some(previous_config_json) = rec.previous_config_json else {
        return user_error(
            StatusCode::BAD_REQUEST,
            "not_applied_or_not_found",
            "Recommendation cannot be rolled back",
        );
    };
    let restored: RateLimitConfig = match serde_json::from_str(&previous_config_json) {
        Ok(restored) => restored,
        Err(_) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Stored runtime policy is invalid",
            )
        }
    };
    let host_id = rec.host_id;
    let runtime_policy = crate::rate_limit::RateLimitPolicy {
        enabled: restored.enabled,
        action: restored.action,
        capacity: restored.capacity,
        refill_per_second: restored.refill_per_second,
        key_scope: restored.key_scope,
    };
    let command = ConfigCommand::UpdateRuntimePolicy {
        command_id: Uuid::new_v4(),
        host_id,
        policy: runtime_policy.clone(),
    };
    let receipt = match submit_config_command(&s, command.clone(), &user).await {
        Ok(receipt) => receipt,
        Err(ConfigSubmissionError::Cluster(error)) => return cluster_write_response(error),
        Err(ConfigSubmissionError::LocalApplyPending(receipt)) => {
            audit::record_state(
                &s,
                Some(user.id),
                "recommendation_rollback_committed",
                &format!("recommendation_id={id};host_id={host_id};state=committed"),
            )
            .await;
            audit::record_state(
                &s,
                Some(user.id),
                "recommendation_activation_pending",
                &format!(
                    "recommendation_id={id};host_id={host_id};operation=rollback;reason=local_apply_pending"
                ),
            )
            .await;
            publish_committed_command(&s, &command, &receipt);
            return cluster_write_response(ClusterWriteError::LocalApplyPending { receipt });
        }
        Err(ConfigSubmissionError::Database) => {
            return user_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "database_error",
                "Runtime policy rollback failed",
            )
        }
    };
    s.rate_limiter.set_host_policy(host_id, runtime_policy);
    if !matches!(
        repository::mark_tuning_recommendation_rolled_back(&s.db, id).await,
        Ok(true)
    ) {
        audit::record_state(
            &s,
            Some(user.id),
            "recommendation_rollback_failed",
            &format!("recommendation_id={id};host_id={host_id};reason=metadata_update_failed"),
        )
        .await;
        publish_committed_command(&s, &command, &receipt);
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Runtime policy committed but recommendation metadata could not be updated",
        );
    }

    audit::record_state(
        &s,
        Some(user.id),
        "recommendation_rolled_back",
        &format!("recommendation_id={id};host_id={host_id}"),
    )
    .await;
    s.realtime.publish("adaptive_tuning.changed");
    publish_committed_command(&s, &command, &receipt);
    StatusCode::OK.into_response()
}

async fn emergency_disable_tuning(State(s): State<AppState>, h: HeaderMap) -> Response {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return user_error(c, "unauthorized", "Authentication required"),
    };
    if !authorize(
        &s.db,
        &user,
        Permission::SystemSettingsManage,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        return user_error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Administrator access required",
        );
    }

    let next_state = !s.adaptive_tuning.is_emergency_disabled();
    if repository::set_emergency_disabled(&s.db, next_state)
        .await
        .is_err()
    {
        return user_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Unable to update emergency disable status",
        );
    }
    s.adaptive_tuning.set_emergency_disabled(next_state);

    audit::record_state(
        &s,
        Some(user.id),
        "adaptive_tuning_emergency_toggle",
        &format!("disabled={next_state}"),
    )
    .await;
    s.realtime.publish("adaptive_tuning.changed");
    Json(serde_json::json!({"emergency_disabled": next_state})).into_response()
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
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return c.into_response(),
    };
    let global_read = authorize(
        &s.db,
        &user,
        Permission::ProxyHostsRead,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false);
    let scoped_read =
        repository::user_has_scoped_permission(&s.db, user.id, Permission::ProxyHostsRead.key())
            .await
            .unwrap_or(false);
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
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return c.into_response(),
    };
    if !authorize(
        &s.db,
        &user,
        Permission::ProxyHostsRead,
        ResourceContext::ProxyHost(id),
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(
            &s,
            Some(user.id),
            "authorization_denied",
            r#"{"resource_type":"proxy_host","resource_id":"[REDACTED]"}"#,
        )
        .await;
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
    if !authorize(
        &s.db,
        &u,
        Permission::ProxyHostsWrite,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(&s, Some(u.id), "authorization_denied", "ProxyHostsWrite").await;
        return StatusCode::FORBIDDEN.into_response();
    }
    if req.name.trim().is_empty()
        || req.domain.trim().is_empty()
        || req.upstream_host.trim().is_empty()
        || req.upstream_port == 0
    {
        audit::record_state(
            &s,
            Some(u.id),
            "proxy_host_create_denied",
            "reason=invalid_input",
        )
        .await;
        return StatusCode::BAD_REQUEST.into_response();
    }
    let host = ProxyHost {
        id: repository::new_proxy_host_id(),
        name: req.name,
        domain: req.domain.to_ascii_lowercase(),
        upstream_host: req.upstream_host,
        upstream_port: req.upstream_port,
        tls_mode: req.tls_mode,
        certificate_id: req.certificate_id,
        enabled: req.enabled,
    };
    let command = ConfigCommand::CreateProxyHost {
        command_id: Uuid::new_v4(),
        host: host.clone(),
    };
    let receipt = match submit_config_command(&s, command.clone(), &u).await {
        Ok(receipt) => receipt,
        Err(ConfigSubmissionError::LocalApplyPending(receipt)) => {
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_created",
                &format!("host_id={};state=committed", host.id),
            )
            .await;
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_activation_pending",
                &format!(
                    "host_id={};operation=create;reason=local_apply_pending",
                    host.id
                ),
            )
            .await;
            publish_committed_command(&s, &command, &receipt);
            return cluster_write_response(ClusterWriteError::LocalApplyPending { receipt });
        }
        Err(ConfigSubmissionError::Cluster(error)) => {
            if matches!(
                error,
                ClusterWriteError::DuplicateDomain | ClusterWriteError::IdCollision
            ) {
                let reason = if error == ClusterWriteError::DuplicateDomain {
                    "duplicate_domain"
                } else {
                    "id_collision"
                };
                audit::record_state(
                    &s,
                    Some(u.id),
                    "proxy_host_create_denied",
                    &format!("reason={reason}"),
                )
                .await;
                return cluster_write_response(error);
            }
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_create_failed",
                "reason=cluster_write_failed",
            )
            .await;
            return cluster_write_response(error);
        }
        Err(ConfigSubmissionError::Database) => {
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_create_denied",
                "reason=duplicate_domain",
            )
            .await;
            return (
                StatusCode::CONFLICT,
                Json(ErrorEnvelope {
                    code: "duplicate_domain".into(),
                    message: "Domain already exists".into(),
                }),
            )
                .into_response();
        }
    };
    audit::record_state(
        &s,
        Some(u.id),
        "proxy_host_created",
        &format!("host_id={};state=committed", host.id),
    )
    .await;
    publish_committed_command(&s, &command, &receipt);
    let desired = DesiredConfig {
        proxy_hosts: repository::list_hosts(&s.db).await.unwrap_or_default(),
    };
    if s.reloader.apply(desired).await.is_err() {
        audit::record_state(
            &s,
            Some(u.id),
            "proxy_host_activation_failed",
            &format!("host_id={};operation=create;reason=reload_failed", host.id),
        )
        .await;
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorEnvelope {
                code: "reload_failed".into(),
                message: "Proxy host was committed but not activated".into(),
            }),
        )
            .into_response();
    }
    (StatusCode::CREATED, Json(host)).into_response()
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
    if !authorize(
        &s.db,
        &u,
        Permission::ProxyHostsWrite,
        ResourceContext::ProxyHost(id),
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(
            &s,
            Some(u.id),
            "authorization_denied",
            r#"{"resource_type":"proxy_host","resource_id":"[REDACTED]"}"#,
        )
        .await;
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(_) = repository::get_host(&s.db, id).await.ok().flatten() else {
        audit::record_state(
            &s,
            Some(u.id),
            "proxy_host_update_denied",
            "reason=not_found",
        )
        .await;
        return StatusCode::NOT_FOUND.into_response();
    };
    if req.name.trim().is_empty()
        || req.domain.trim().is_empty()
        || req.upstream_host.trim().is_empty()
        || req.upstream_port == 0
    {
        audit::record_state(
            &s,
            Some(u.id),
            "proxy_host_update_denied",
            "reason=invalid_input",
        )
        .await;
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
    let command = ConfigCommand::UpdateProxyHost {
        command_id: Uuid::new_v4(),
        host_id: id,
        host: next.clone(),
    };
    let receipt = match submit_config_command(&s, command.clone(), &u).await {
        Ok(receipt) => receipt,
        Err(ConfigSubmissionError::LocalApplyPending(receipt)) => {
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_updated",
                &format!("host_id={id};state=committed"),
            )
            .await;
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_activation_pending",
                &format!("host_id={id};operation=update;reason=local_apply_pending"),
            )
            .await;
            publish_committed_command(&s, &command, &receipt);
            return cluster_write_response(ClusterWriteError::LocalApplyPending { receipt });
        }
        Err(ConfigSubmissionError::Cluster(error)) => {
            if matches!(
                error,
                ClusterWriteError::DuplicateDomain | ClusterWriteError::NotFound
            ) {
                let reason = if error == ClusterWriteError::DuplicateDomain {
                    "duplicate_domain"
                } else {
                    "not_found"
                };
                audit::record_state(
                    &s,
                    Some(u.id),
                    "proxy_host_update_denied",
                    &format!("reason={reason}"),
                )
                .await;
                return cluster_write_response(error);
            }
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_update_failed",
                "reason=cluster_write_failed",
            )
            .await;
            return cluster_write_response(error);
        }
        Err(ConfigSubmissionError::Database) => {
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_update_failed",
                "reason=database_error",
            )
            .await;
            return StatusCode::CONFLICT.into_response();
        }
    };
    audit::record_state(
        &s,
        Some(u.id),
        "proxy_host_updated",
        &format!("host_id={id};state=committed"),
    )
    .await;
    publish_committed_command(&s, &command, &receipt);
    let desired = DesiredConfig {
        proxy_hosts: repository::list_hosts(&s.db).await.unwrap_or_default(),
    };
    if s.reloader.apply(desired).await.is_err() {
        audit::record_state(
            &s,
            Some(u.id),
            "proxy_host_activation_failed",
            &format!("host_id={id};operation=update;reason=reload_failed"),
        )
        .await;
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorEnvelope {
                code: "reload_failed".into(),
                message: "Proxy host update was committed but not activated".into(),
            }),
        )
            .into_response();
    }
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
    if !authorize(
        &s.db,
        &u,
        Permission::ProxyHostsWrite,
        ResourceContext::ProxyHost(id),
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(
            &s,
            Some(u.id),
            "authorization_denied",
            r#"{"resource_type":"proxy_host","resource_id":"[REDACTED]"}"#,
        )
        .await;
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(_) = repository::get_host(&s.db, id).await.ok().flatten() else {
        audit::record_state(
            &s,
            Some(u.id),
            "proxy_host_delete_denied",
            "reason=not_found",
        )
        .await;
        return StatusCode::NOT_FOUND.into_response();
    };
    let command = ConfigCommand::DeleteProxyHost {
        command_id: Uuid::new_v4(),
        host_id: id,
    };
    let receipt = match submit_config_command(&s, command.clone(), &u).await {
        Ok(receipt) => receipt,
        Err(ConfigSubmissionError::LocalApplyPending(receipt)) => {
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_deleted",
                &format!("host_id={id};state=committed"),
            )
            .await;
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_activation_pending",
                &format!("host_id={id};operation=delete;reason=local_apply_pending"),
            )
            .await;
            publish_committed_command(&s, &command, &receipt);
            return cluster_write_response(ClusterWriteError::LocalApplyPending { receipt });
        }
        Err(ConfigSubmissionError::Cluster(error)) => {
            if error == ClusterWriteError::NotFound {
                audit::record_state(
                    &s,
                    Some(u.id),
                    "proxy_host_delete_denied",
                    "reason=not_found",
                )
                .await;
                return cluster_write_response(error);
            }
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_delete_failed",
                "reason=cluster_write_failed",
            )
            .await;
            return cluster_write_response(error);
        }
        Err(ConfigSubmissionError::Database) => {
            audit::record_state(
                &s,
                Some(u.id),
                "proxy_host_delete_failed",
                "reason=database_error",
            )
            .await;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };
    audit::record_state(
        &s,
        Some(u.id),
        "proxy_host_deleted",
        &format!("host_id={id};state=committed"),
    )
    .await;
    publish_committed_command(&s, &command, &receipt);
    let desired = DesiredConfig {
        proxy_hosts: repository::list_hosts(&s.db).await.unwrap_or_default(),
    };
    if s.reloader.apply(desired).await.is_err() {
        audit::record_state(
            &s,
            Some(u.id),
            "proxy_host_activation_failed",
            &format!("host_id={id};operation=delete;reason=reload_failed"),
        )
        .await;
        return (
            StatusCode::BAD_GATEWAY,
            Json(ErrorEnvelope {
                code: "reload_failed".into(),
                message: "Proxy host deletion was committed but not activated".into(),
            }),
        )
            .into_response();
    }
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
    if !authorize(
        &s.db,
        &u,
        Permission::CertificatesWrite,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
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
            Err(_) => {
                audit::record_state(
                    &s,
                    Some(u.id),
                    "certificate_upload_denied",
                    "reason=invalid_multipart",
                )
                .await;
                return StatusCode::BAD_REQUEST.into_response();
            }
        };
        total += bytes.len();
        if total > 3 * 1024 * 1024 {
            audit::record_state(
                &s,
                Some(u.id),
                "certificate_upload_denied",
                "reason=payload_too_large",
            )
            .await;
            return StatusCode::PAYLOAD_TOO_LARGE.into_response();
        }
        if bytes.len() > 1024 * 1024 {
            audit::record_state(
                &s,
                Some(u.id),
                "certificate_upload_denied",
                "reason=field_too_large",
            )
            .await;
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
        audit::record_state(
            &s,
            Some(u.id),
            "certificate_upload_denied",
            "reason=missing_fields",
        )
        .await;
        return StatusCode::BAD_REQUEST.into_response();
    };
    match s.certificates.import_custom(&name, &cert, &key) {
        Ok(record) => {
            match repository::insert_certificate(
                &s.db,
                &record.name,
                "custom",
                &serde_json::to_string(&record.covered_hostnames).unwrap_or_default(),
                &record.expiry,
                &record.certificate_path.to_string_lossy(),
                &record.key_path.to_string_lossy(),
            )
            .await
            {
                Ok(id) => {
                    audit::record_state(
                        &s,
                        Some(u.id),
                        "certificate_uploaded",
                        &format!("certificate_id={id}"),
                    )
                    .await;
                    s.realtime.publish("certificates.changed");
                    (StatusCode::CREATED,Json(serde_json::json!({"id":id,"name":record.name,"source":"custom","covered_hostnames":record.covered_hostnames,"expiry":record.expiry}))).into_response()
                }
                Err(_) => {
                    audit::record_state(
                        &s,
                        Some(u.id),
                        "certificate_upload_failed",
                        "reason=database_error",
                    )
                    .await;
                    StatusCode::CONFLICT.into_response()
                }
            }
        }
        Err(_) => {
            audit::record_state(
                &s,
                Some(u.id),
                "certificate_upload_denied",
                "reason=invalid_certificate",
            )
            .await;
            StatusCode::BAD_REQUEST.into_response()
        }
    }
}

async fn list_certificates(State(s): State<AppState>, h: HeaderMap) -> impl IntoResponse {
    let user = match current(&s, &h).await {
        Ok(u) => u,
        Err(c) => return c.into_response(),
    };
    if !authorize(
        &s.db,
        &user,
        Permission::CertificatesRead,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(
            &s,
            Some(user.id),
            "authorization_denied",
            "CertificatesRead",
        )
        .await;
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
    if !authorize(
        &s.db,
        &user,
        Permission::CertificatesWrite,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        audit::record_state(
            &s,
            Some(user.id),
            "authorization_denied",
            "CertificatesWrite",
        )
        .await;
        return StatusCode::FORBIDDEN.into_response();
    }
    let Some((name, cert_path, key_path)) = repository::certificate_paths(&s.db, id)
        .await
        .ok()
        .flatten()
    else {
        audit::record_state(
            &s,
            Some(user.id),
            "certificate_activation_denied",
            "reason=not_found",
        )
        .await;
        return StatusCode::NOT_FOUND.into_response();
    };
    if CertificateStore::validate_material_paths(
        std::path::Path::new(&cert_path),
        std::path::Path::new(&key_path),
    )
    .is_err()
    {
        audit::record_state(
            &s,
            Some(user.id),
            "certificate_activation_denied",
            "reason=invalid_material",
        )
        .await;
        return StatusCode::BAD_REQUEST.into_response();
    }
    let previous_id = match repository::active_certificate_id(&s.db).await {
        Ok(value) => value,
        Err(_) => {
            audit::record_state(
                &s,
                Some(user.id),
                "certificate_activation_failed",
                "reason=database_error",
            )
            .await;
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
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
        audit::record_state(
            &s,
            Some(user.id),
            "certificate_activation_failed",
            "reason=activation_failed",
        )
        .await;
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

async fn get_cluster_status(State(s): State<AppState>, h: HeaderMap) -> Response {
    if let Err(r) = require_analytics_read(&s, &h, None).await {
        return r;
    }
    let snapshot = s.cluster.snapshot().await;
    Json(snapshot).into_response()
}
