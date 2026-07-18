use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct User { pub id: i64, pub email: String, pub role: String, pub created_at: String }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProxyHost { pub id: i64, pub name: String, pub domain: String, pub upstream_host: String, pub upstream_port: u16, pub tls_mode: String, pub certificate_id: Option<i64>, pub enabled: bool }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DesiredConfig { pub proxy_hosts: Vec<ProxyHost> }
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorEnvelope { pub code: String, pub message: String }
#[derive(Clone, Debug, Deserialize)]
pub struct SetupRequest { pub email: String, pub password: String, pub setup_token: String }
#[derive(Clone, Debug, Deserialize)]
pub struct LoginRequest { pub email: String, pub password: String }
#[derive(Clone, Debug, Deserialize)]
pub struct ProxyHostRequest { pub name: String, pub domain: String, pub upstream_host: String, pub upstream_port: u16, #[serde(default = "default_tls")] pub tls_mode: String, pub certificate_id: Option<i64>, #[serde(default = "default_enabled")] pub enabled: bool }
fn default_tls() -> String { "disabled".into() }
fn default_enabled() -> bool { true }
#[derive(Clone, Debug, Serialize)]
pub struct CertificateMetadata { pub id: i64, pub name: String, pub source: String, pub covered_hostnames: Vec<String>, pub expiry: String, pub active: bool }
