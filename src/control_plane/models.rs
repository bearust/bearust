use crate::ai_advisor::{AdvisorErrorCode, AdvisorJobId, AdvisorJobStatus, AdvisorWorkflow};
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AcmeEnvironment {
    Staging,
    Production,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum AcmeChallenge {
    #[serde(rename = "http01")]
    Http01,
    #[serde(rename = "cloudflare_dns01")]
    CloudflareDns01,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeRequest {
    pub environment: AcmeEnvironment,
    pub challenge: AcmeChallenge,
    pub hostnames: Vec<String>,
}

/// Control-plane payload. Credentials are write-only and are never serialized.
#[derive(Clone, Debug, Deserialize)]
pub struct AcmeIssueRequest {
    pub environment: AcmeEnvironment,
    pub challenge: AcmeChallenge,
    pub hostnames: Vec<String>,
    #[serde(default, alias = "cloudflare_api_token")]
    pub cloudflare_token: Option<String>,
}
impl AcmeIssueRequest {
    pub fn request(&self) -> AcmeRequest {
        AcmeRequest {
            environment: self.environment.clone(),
            challenge: self.challenge.clone(),
            hostnames: self.hostnames.clone(),
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct AcmeJobResponse {
    pub job_id: String,
    pub certificate_id: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AcmeStatus {
    pub certificate_id: i64,
    pub environment: AcmeEnvironment,
    pub challenge: AcmeChallenge,
    pub hostnames: Vec<String>,
    pub renewal_state: String,
    pub next_renewal_at: Option<String>,
    pub last_attempt_at: Option<String>,
    pub last_error_code: Option<String>,
}

impl AcmeRequest {
    pub fn normalized(mut self) -> Result<Self, String> {
        let mut hosts = Vec::new();
        for raw in self.hostnames.drain(..) {
            let host = raw.trim().to_ascii_lowercase();
            if host.is_empty() || host.chars().any(|c| c.is_whitespace()) {
                return Err("invalid hostname".into());
            }
            if let Some(suffix) = host.strip_prefix("*.") {
                if self.challenge == AcmeChallenge::Http01 {
                    return Err("http-01 does not support wildcard hostnames".into());
                }
                if suffix.contains('*') || !valid_dns_name(suffix) || suffix.split('.').count() < 2
                {
                    return Err("invalid wildcard hostname".into());
                }
            } else if host.contains('*') {
                return Err("invalid wildcard hostname".into());
            } else if !valid_dns_name(&host) {
                return Err("invalid hostname".into());
            }
            if !hosts.contains(&host) {
                hosts.push(host);
            }
        }
        if hosts.is_empty() {
            return Err("at least one hostname is required".into());
        }
        self.hostnames = hosts;
        Ok(self)
    }
}

fn valid_dns_name(host: &str) -> bool {
    if host.len() > 253 || host.starts_with('.') || host.ends_with('.') {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    })
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User {
    pub id: i64,
    pub email: String,
    pub role: String,
    pub created_at: String,
    pub disabled: bool,
    pub preferred_locale: Option<String>,
}

/// Safe, bounded response for a plugin reload operation.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginReloadResponse {
    pub loaded: usize,
    pub failed: usize,
}

/// Redacted plugin metadata exposed by the control plane.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginStatusResponse {
    pub id: String,
    pub display_name: String,
    pub abi_version: u32,
    pub digest: String,
    pub enabled: bool,
    pub loaded: bool,
    pub last_error_code: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub trust_status: String,
}

/// Safe response for a plugin health invocation. Runtime details and module
/// paths are intentionally not exposed by the control plane. `detail` is
/// populated only for `abi_version: 2` plugins and is already length-capped
/// by the plugin runtime before it reaches this response.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PluginHealthResponse {
    pub status: i32,
    pub elapsed_ms: u64,
    pub detail: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserPreferencesPatch {
    #[serde(default, deserialize_with = "deserialize_optional_locale")]
    pub preferred_locale: Option<Option<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserThemePreference {
    pub preferred_theme: Option<String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserThemePatch {
    pub preferred_theme: Option<String>,
}

fn deserialize_optional_locale<'de, D>(deserializer: D) -> Result<Option<Option<String>>, D::Error>
where
    D: Deserializer<'de>,
{
    Option::<String>::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Deserialize)]
pub struct UserCreate {
    pub email: String,
    pub password: String,
    pub role: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct UserPatch {
    pub role: Option<String>,
    pub disabled: Option<bool>,
}

#[derive(Clone, Debug, Serialize)]
pub struct SessionsRevokeResponse {
    pub revoked: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogQuery {
    pub event: Option<String>,
    pub actor_id: Option<i64>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub q: Option<String>,
    pub page: u32,
    pub page_size: u32,
}

/// Raw query parameters for the audit-log HTTP endpoint. Numeric values are
/// kept as strings so the handler can return the control-plane error envelope
/// for malformed input instead of exposing extractor errors.
#[derive(Clone, Debug, Default, Deserialize)]
pub struct AuditLogParams {
    pub event: Option<String>,
    pub actor_id: Option<String>,
    pub from: Option<String>,
    pub to: Option<String>,
    pub q: Option<String>,
    pub page: Option<String>,
    pub page_size: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogItem {
    pub id: i64,
    pub actor: String,
    pub event: String,
    pub details: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditLogPage {
    pub items: Vec<AuditLogItem>,
    pub page: u32,
    pub page_size: u32,
    pub total: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvisorJobRecord {
    pub job_id: AdvisorJobId,
    pub owner_id: i64,
    pub workflow: AdvisorWorkflow,
    pub status: AdvisorJobStatus,
    pub redacted_input: String,
    pub redacted_result: Option<String>,
    pub error_code: Option<AdvisorErrorCode>,
    pub provider_model: String,
    pub config_version: String,
    pub config_hash: String,
    pub created_at: String,
    pub updated_at: String,
    pub expires_at: String,
    pub draft_decision: Option<AdvisorDraftDecision>,
    pub draft_decided_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AdvisorDraftDecision {
    Approved,
    Rejected,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AdvisorJobPage {
    pub items: Vec<AdvisorJobRecord>,
    pub page: u32,
    pub page_size: u32,
    pub total: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleRecord {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub system_managed: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct PermissionRecord {
    pub id: i64,
    pub key: String,
    pub description: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RoleDetail {
    pub id: i64,
    pub slug: String,
    pub name: String,
    pub description: String,
    pub system_managed: bool,
    pub permissions: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<RolePermissionScope>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct RolePermissionScope {
    pub permission: String,
    pub proxy_host_ids: Vec<i64>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum WafMode {
    MonitorOnly,
    Block,
}

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WafAction {
    #[default]
    Inherit,
    Allow,
    Log,
    Block,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WafConfig {
    pub mode: WafMode,
    pub updated_at: String,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub action: crate::rate_limit::RateLimitAction,
    pub capacity: u32,
    pub refill_per_second: f64,
    pub key_scope: crate::rate_limit::RateLimitKeyScope,
    pub updated_at: String,
}

/// Persisted bot policy views used by control-plane handlers. Secret material
/// is intentionally omitted from the serializable view.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BotConfigRecord {
    pub mode: String,
    pub threshold: u16,
    pub ttl_seconds: u64,
    pub updated_at: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BotRuleRecord {
    pub id: i64,
    pub category: String,
    pub weight: u16,
    pub trusted_user_agent: Option<String>,
    pub trusted_domain: Option<String>,
    pub enabled: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WafRule {
    pub id: i64,
    pub name: String,
    pub source: String,
    pub category: String,
    pub severity: String,
    pub enabled: bool,
    pub action: WafAction,
    pub matcher_json: String,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum IpSecurityAction {
    #[default]
    Monitor,
    Block,
    Allow,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct IpSecurityRule {
    pub id: i64,
    pub cidr: String,
    pub action: IpSecurityAction,
    pub score: i32,
    pub country_code: Option<String>,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IpSecurityRuleCreate {
    pub cidr: String,
    #[serde(default)]
    pub action: IpSecurityAction,
    #[serde(default)]
    pub score: i32,
    pub country_code: Option<String>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct IpSecurityRulePatch {
    pub cidr: Option<String>,
    pub action: Option<IpSecurityAction>,
    pub score: Option<i32>,
    pub country_code: Option<Option<String>>,
    pub enabled: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyHostAuth {
    pub host_id: i64,
    pub enabled: bool,
    pub realm: String,
    pub username: String,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyHostAuthPatch {
    pub enabled: Option<bool>,
    pub realm: Option<String>,
    pub username: Option<String>,
    pub password: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WafFeedback {
    pub id: i64,
    pub reporter_id: Option<i64>,
    pub request_id: Option<String>,
    pub rule_id: Option<i64>,
    pub label: String,
    pub note: String,
    pub created_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WafFeedbackCreate {
    pub request_id: Option<String>,
    pub rule_id: Option<i64>,
    #[serde(default = "default_false_positive_label")]
    pub label: String,
    #[serde(default)]
    pub note: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AnalyticsRetentionConfig {
    pub retention_minutes: u32,
    pub updated_at: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AnalyticsRetentionPatch {
    pub retention_minutes: u32,
}

fn default_false_positive_label() -> String {
    "false_positive".into()
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleCreate {
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    #[serde(default)]
    pub scopes: Vec<RolePermissionScope>,
}

#[derive(Clone, Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct RolePatch {
    pub name: Option<String>,
    pub description: Option<String>,
    pub permissions: Option<Vec<String>>,
    #[serde(default)]
    pub scopes: Option<Vec<RolePermissionScope>>,
}

pub type UserSummary = User;
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyHost {
    pub id: i64,
    pub name: String,
    pub domain: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    pub tls_mode: String,
    pub certificate_id: Option<i64>,
    pub enabled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DesiredConfig {
    pub proxy_hosts: Vec<ProxyHost>,
}

/// Read/write control-plane contract for the live upstream topology. The
/// configuration fields mirror the native TOML model while backend health and
/// in-flight counts are read-only runtime observations.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LoadBalancerConfigRequest {
    pub pools: Vec<crate::config::PoolConfig>,
    pub routes: Vec<crate::config::RouteConfig>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LoadBalancerSnapshot {
    pub generation: u64,
    pub pools: Vec<LoadBalancerPool>,
    pub routes: Vec<crate::config::RouteConfig>,
    pub capabilities: LoadBalancerCapabilities,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LoadBalancerPool {
    pub name: String,
    pub algorithm: crate::config::Algorithm,
    pub connect_timeout_seconds: u64,
    pub request_timeout_seconds: u64,
    pub passive_health: bool,
    pub backends: Vec<LoadBalancerBackend>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoadBalancerBackend {
    pub id: usize,
    pub address: String,
    pub health_check: crate::config::HealthCheckKind,
    pub health_path: Option<String>,
    pub weight: u32,
    pub healthy: bool,
    pub inflight: usize,
    pub response_time_ewma_ms: Option<u64>,
    pub passive_failures: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LoadBalancerCapabilities {
    pub algorithms: Vec<String>,
    pub health_checks: Vec<String>,
    pub passive_health: bool,
    pub adaptive_weighting: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorEnvelope {
    pub code: String,
    pub message: String,
}
#[derive(Clone, Debug, Deserialize)]
pub struct SetupRequest {
    pub email: String,
    pub password: String,
    pub setup_token: String,
}
#[derive(Clone, Debug, Deserialize)]
pub struct LoginRequest {
    pub email: String,
    pub password: String,
}
#[derive(Clone, Debug, Deserialize)]
pub struct ProxyHostRequest {
    pub name: String,
    pub domain: String,
    pub upstream_host: String,
    pub upstream_port: u16,
    #[serde(default = "default_tls")]
    pub tls_mode: String,
    pub certificate_id: Option<i64>,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}
fn default_tls() -> String {
    "disabled".into()
}
fn default_enabled() -> bool {
    true
}
#[derive(Clone, Debug, Serialize)]
pub struct CertificateMetadata {
    pub id: i64,
    pub name: String,
    pub source: String,
    pub covered_hostnames: Vec<String>,
    pub expiry: String,
    pub active: bool,
}
