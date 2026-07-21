use serde::{Deserialize, Serialize};

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
