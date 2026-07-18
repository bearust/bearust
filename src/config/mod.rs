mod error;
pub use error::ConfigError;
use serde::Deserialize;
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub health: HealthConfig,
    pub upstream_pools: Vec<PoolConfig>,
    pub routes: Vec<RouteConfig>,
}
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    pub bind: SocketAddr,
    #[serde(default = "default_control_bind")]
    pub control_bind: SocketAddr,
    #[serde(default = "default_control_database")]
    pub control_database: PathBuf,
    #[serde(default = "default_certificate_store")]
    pub certificate_store: PathBuf,
    #[serde(default = "default_shutdown")]
    pub graceful_shutdown_seconds: u64,
    #[serde(default = "default_pid")]
    pub pid_file: PathBuf,
    #[serde(default)]
    pub tls: Option<TlsConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    #[serde(default = "default_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_health_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_unhealthy")]
    pub unhealthy_threshold: u64,
    #[serde(default = "default_healthy")]
    pub healthy_threshold: u64,
}
impl Default for HealthConfig {
    fn default() -> Self {
        Self {
            interval_seconds: 10,
            timeout_seconds: 2,
            unhealthy_threshold: 3,
            healthy_threshold: 2,
        }
    }
}
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    pub name: String,
    pub algorithm: Algorithm,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
    pub backends: Vec<BackendConfig>,
}
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BackendConfig {
    pub address: SocketAddr,
    pub health_check: HealthCheckKind,
    pub health_path: Option<String>,
}
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub name: String,
    pub host: String,
    pub path_prefix: String,
    pub upstream_pool: String,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    RoundRobin,
    LeastConnections,
}
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckKind {
    Tcp,
    Http,
}

fn default_shutdown() -> u64 {
    30
}
fn default_control_bind() -> SocketAddr {
    // Library/test default avoids binding a shared fixed port. Production
    // deployments should set an explicit control_bind in their TOML.
    "127.0.0.1:0".parse().expect("valid default")
}
fn default_control_database() -> PathBuf {
    "./data/bearust.sqlite".into()
}
fn default_certificate_store() -> PathBuf {
    "./data/certificates".into()
}
fn default_pid() -> PathBuf {
    "./bearust.pid".into()
}
fn default_interval() -> u64 {
    10
}
fn default_health_timeout() -> u64 {
    2
}
fn default_unhealthy() -> u64 {
    3
}
fn default_healthy() -> u64 {
    2
}
fn default_connect_timeout() -> u64 {
    3
}
fn default_request_timeout() -> u64 {
    30
}

pub fn load(path: &Path) -> Result<Config, ConfigError> {
    let input = std::fs::read_to_string(path).map_err(|source| ConfigError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    Config::parse(&input)
}
impl Config {
    pub fn parse(input: &str) -> Result<Self, ConfigError> {
        let config: Self = toml::from_str(input)?;
        config.validate()?;
        Ok(config)
    }
    fn validate(&self) -> Result<(), ConfigError> {
        if self.server.graceful_shutdown_seconds == 0 {
            return err("server.graceful_shutdown_seconds", "must be positive");
        }
        if let Some(tls) = &self.server.tls {
            if tls.cert_path.as_os_str().is_empty() {
                return err("server.tls.cert_path", "must not be empty");
            }
            if tls.key_path.as_os_str().is_empty() {
                return err("server.tls.key_path", "must not be empty");
            }
        }
        for (name, value) in [
            ("health.interval_seconds", self.health.interval_seconds),
            ("health.timeout_seconds", self.health.timeout_seconds),
            (
                "health.unhealthy_threshold",
                self.health.unhealthy_threshold,
            ),
            ("health.healthy_threshold", self.health.healthy_threshold),
        ] {
            if value == 0 {
                return err(name, "must be positive");
            }
        }
        if self.upstream_pools.is_empty() {
            return err("upstream_pools", "must not be empty");
        }
        if self.routes.is_empty() {
            return err("routes", "must not be empty");
        }
        let mut pools = HashSet::new();
        for (i, p) in self.upstream_pools.iter().enumerate() {
            if !pools.insert(&p.name) {
                return err(&format!("upstream_pools[{i}].name"), "duplicate name");
            }
            if p.backends.is_empty() {
                return err(
                    &format!("upstream_pools[{i}].backends"),
                    "must not be empty",
                );
            }
            if p.connect_timeout_seconds == 0 {
                return err(
                    &format!("upstream_pools[{i}].connect_timeout_seconds"),
                    "must be positive",
                );
            }
            if p.request_timeout_seconds == 0 {
                return err(
                    &format!("upstream_pools[{i}].request_timeout_seconds"),
                    "must be positive",
                );
            }
            for (j, b) in p.backends.iter().enumerate() {
                if b.health_check == HealthCheckKind::Http
                    && b.health_path.as_deref().map_or(true, |x| {
                        !x.starts_with('/') || x.chars().any(|ch| ch.is_ascii_control())
                    })
                {
                    return err(
                        &format!("upstream_pools[{i}].backends[{j}].health_path"),
                        "HTTP health checks require a path beginning with /",
                    );
                }
            }
        }
        let mut route_names = HashSet::new();
        let mut route_keys = HashSet::new();
        for (i, r) in self.routes.iter().enumerate() {
            if !route_names.insert(&r.name) {
                return Err(validation(&format!("routes[{i}].name"), "duplicate name"));
            }
            if !pools.iter().any(|name| *name == &r.upstream_pool) {
                return Err(validation(
                    &format!("routes[{i}].upstream_pool"),
                    format!("unknown pool {}", r.upstream_pool),
                ));
            }
            if !r.path_prefix.starts_with('/') {
                return Err(validation(
                    &format!("routes[{i}].path_prefix"),
                    "must begin with /",
                ));
            }
            if !is_valid_config_host(&r.host) {
                return Err(validation(
                    &format!("routes[{i}].host"),
                    "must be a non-empty host authority without control characters",
                ));
            }
            let key = (normalize_config_host(&r.host), r.path_prefix.clone());
            if !route_keys.insert(key) {
                return Err(validation(
                    &format!("routes[{i}]"),
                    "duplicate normalized host and path prefix",
                ));
            }
        }
        Ok(())
    }
}

fn is_valid_config_host(host: &str) -> bool {
    let value = host.trim();
    if value.is_empty()
        || value
            .chars()
            .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
    {
        return false;
    }
    // Reject URI-like authorities and malformed bracketed IPv6/ports.
    if value.contains('/') || value.contains('@') || value.contains('?') || value.contains('#') {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower.starts_with('[') {
        let Some(end) = lower.find(']') else {
            return false;
        };
        if end == 1 {
            return false;
        }
        if lower[1..end].parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
        let rest = &lower[end + 1..];
        if !rest.is_empty() {
            let Some(port) = rest.strip_prefix(':') else {
                return false;
            };
            let port = port.strip_suffix('.').unwrap_or(port);
            if port.is_empty() || port.parse::<u16>().is_err() {
                return false;
            }
        }
    } else if lower.matches(':').count() == 1 {
        let Some((_, port)) = lower.rsplit_once(':') else {
            return false;
        };
        let port = port.strip_suffix('.').unwrap_or(port);
        if port.is_empty() || port.parse::<u16>().is_err() {
            return false;
        }
    } else if lower.matches(':').count() > 1 {
        // Unbracketed IPv6 is accepted for backwards compatibility.
        if lower.parse::<std::net::Ipv6Addr>().is_err() {
            return false;
        }
    } else if lower.parse::<std::net::IpAddr>().is_err() && {
        let labels_host = lower.strip_suffix('.').unwrap_or(&lower);
        labels_host.starts_with('.')
            || labels_host.ends_with('.')
            || labels_host.split('.').any(|label| {
                label.is_empty()
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
            })
    } {
        return false;
    }
    !normalize_config_host(value).is_empty()
}
fn err(field: &str, message: impl Into<String>) -> Result<(), ConfigError> {
    Err(validation(field, message))
}
fn validation(field: &str, message: impl Into<String>) -> ConfigError {
    ConfigError::Validation {
        field: field.into(),
        message: message.into(),
    }
}
pub fn normalize_config_host(host: &str) -> String {
    let mut h = host.trim().to_ascii_lowercase();

    // Strip a numeric port before trimming the DNS root dot. This also handles
    // `api.example.com.:8080` without leaving a trailing dot behind.
    if h.starts_with('[') {
        // Bracketed IPv6 may have a port after the closing bracket. Only strip
        // that port; never interpret an IPv6 hextet as a port.
        if let Some(end) = h.find(']') {
            if h[end + 1..]
                .strip_prefix(':')
                .and_then(|p| p.strip_suffix('.').or(Some(p)))
                .and_then(|p| p.parse::<u16>().ok())
                .is_some()
            {
                h.truncate(end + 1);
            }
        }
    } else if let Some((prefix, port)) = h.rsplit_once(':') {
        // An unbracketed IPv6 address contains colons in its host portion and
        // must not have its final hextet removed as though it were a port.
        let port = port.strip_suffix('.').unwrap_or(port);
        if !prefix.contains(':') && port.parse::<u16>().is_ok() {
            h = prefix.to_string();
        }
    }

    if h.ends_with('.') {
        h.pop();
    }
    if h.starts_with('[') {
        if let Some(end) = h.find(']') {
            return h[1..end].to_string();
        }
    }
    h
}
