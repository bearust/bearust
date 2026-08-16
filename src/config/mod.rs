mod error;
use crate::analytics_prometheus::PrometheusConfig;
pub use error::ConfigError;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::SocketAddr,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub health: HealthConfig,
    pub upstream_pools: Vec<PoolConfig>,
    pub routes: Vec<RouteConfig>,
    #[serde(default)]
    pub rate_limit: RateLimitConfig,
    #[serde(default)]
    pub prometheus: PrometheusConfig,
    #[serde(default)]
    pub cluster: ClusterConfig,
    #[serde(default)]
    pub plugins: PluginConfig,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PluginConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_plugin_directory")]
    pub directory: PathBuf,
    #[serde(default = "default_plugin_max_plugins")]
    pub max_plugins: usize,
    #[serde(default = "default_plugin_max_module_bytes")]
    pub max_module_bytes: usize,
    #[serde(default = "default_plugin_max_memory_pages")]
    pub max_memory_pages: u32,
    #[serde(default = "default_plugin_max_fuel")]
    pub max_fuel: u64,
    #[serde(default = "default_plugin_invocation_timeout_ms")]
    pub invocation_timeout_ms: u64,
    #[serde(default = "default_plugin_max_output_bytes")]
    pub max_output_bytes: usize,
    #[serde(default)]
    pub require_signature: bool,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory: default_plugin_directory(),
            max_plugins: default_plugin_max_plugins(),
            max_module_bytes: default_plugin_max_module_bytes(),
            max_memory_pages: default_plugin_max_memory_pages(),
            max_fuel: default_plugin_max_fuel(),
            invocation_timeout_ms: default_plugin_invocation_timeout_ms(),
            max_output_bytes: default_plugin_max_output_bytes(),
            require_signature: false,
        }
    }
}

impl PluginConfig {
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.enabled && self.directory.as_os_str().is_empty() {
            return err(
                "plugins.directory",
                "must not be empty when plugins are enabled",
            );
        }
        macro_rules! check_limit {
            ($field:literal, $value:expr, $maximum:expr) => {
                if $value == 0 {
                    return err($field, "must be positive");
                }
                if $value > $maximum {
                    return err($field, format!("must not exceed {}", $maximum));
                }
            };
        }
        check_limit!("plugins.max_plugins", self.max_plugins, 256usize);
        check_limit!(
            "plugins.max_module_bytes",
            self.max_module_bytes,
            64 * 1024 * 1024usize
        );
        check_limit!("plugins.max_memory_pages", self.max_memory_pages, 4096u32);
        check_limit!("plugins.max_fuel", self.max_fuel, 1_000_000_000u64);
        check_limit!(
            "plugins.invocation_timeout_ms",
            self.invocation_timeout_ms,
            60_000u64
        );
        // Raised from 1 MiB to 2 MiB in Phase 13F: a `transform.response`
        // plugin's manifest-validation floor
        // (`plugin_runtime::MIN_TRANSFORM_RESPONSE_INPUT_BYTES`, 1.5 MiB)
        // would otherwise be impossible to satisfy under any configuration.
        check_limit!(
            "plugins.max_output_bytes",
            self.max_output_bytes,
            2 * 1024 * 1024usize
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RateLimitConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub action: RateLimitAction,
    #[serde(default = "default_rate_capacity")]
    pub capacity: u64,
    #[serde(default = "default_rate_refill")]
    pub refill_per_second: f64,
    #[serde(default)]
    pub key_scope: RateLimitKeyScope,
}
impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            action: RateLimitAction::Monitor,
            capacity: default_rate_capacity(),
            refill_per_second: default_rate_refill(),
            key_scope: RateLimitKeyScope::ProxyHostIp,
        }
    }
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitAction {
    #[default]
    Monitor,
    Block,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKeyScope {
    #[default]
    ProxyHostIp,
    ProxyHostPathIp,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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
    #[serde(default)]
    pub http3: Http3Config,
    /// CIDRs whose forwarding headers may be used for client identity.
    #[serde(default)]
    pub trusted_proxy_cidrs: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct TlsConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Http3Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_http3_bind")]
    pub bind: SocketAddr,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_http3_bind(),
        }
    }
}

fn default_http3_bind() -> SocketAddr {
    "127.0.0.1:8443"
        .parse()
        .expect("valid default HTTP/3 bind address")
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
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
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    pub name: String,
    pub algorithm: Algorithm,
    #[serde(default = "default_connect_timeout")]
    pub connect_timeout_seconds: u64,
    #[serde(default = "default_request_timeout")]
    pub request_timeout_seconds: u64,
    /// Feed real-traffic failures back into backend eligibility in addition
    /// to the active probe supervisor.
    #[serde(default)]
    pub passive_health: bool,
    pub backends: Vec<BackendConfig>,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct BackendConfig {
    pub address: SocketAddr,
    pub health_check: HealthCheckKind,
    pub health_path: Option<String>,
    #[serde(default = "default_backend_weight")]
    pub weight: u32,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct RouteConfig {
    pub name: String,
    pub host: String,
    pub path_prefix: String,
    pub upstream_pool: String,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    RoundRobin,
    LeastConnections,
    Weighted,
    IpHash,
    AdaptiveWeight,
    Plugin,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
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
fn default_backend_weight() -> u32 {
    1
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ClusterConfig {
    #[serde(default = "default_node_id")]
    pub node_id: String,
    #[serde(default)]
    pub peers: Vec<ClusterPeer>,
    #[serde(default = "default_cluster_bind")]
    pub bind: SocketAddr,
    #[serde(default = "default_cluster_timeout")]
    pub timeout_seconds: u64,
    /// Shared secret used to authenticate cluster peer handshakes. It is
    /// intentionally never serialized into status responses.
    #[serde(default)]
    pub auth_token: String,
}

impl Default for ClusterConfig {
    fn default() -> Self {
        let node_id = std::env::var("NODE_ID")
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .unwrap_or_else(default_node_id);

        let peers = std::env::var("CLUSTER_PEERS")
            .ok()
            .and_then(|s| ClusterPeer::parse_peers(&s).ok())
            .unwrap_or_default();

        Self {
            node_id,
            peers,
            bind: default_cluster_bind(),
            timeout_seconds: default_cluster_timeout(),
            auth_token: std::env::var("CLUSTER_AUTH_TOKEN").unwrap_or_default(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ClusterPeer {
    pub node_id: String,
    pub address: SocketAddr,
}

impl ClusterPeer {
    pub fn parse_peers(input: &str) -> Result<Vec<Self>, ConfigError> {
        let trimmed = input.trim();
        if trimmed.is_empty() {
            return Ok(vec![]);
        }
        let mut peers = Vec::new();
        for item in trimmed.split(',') {
            let item = item.trim();
            if item.is_empty() {
                return Err(ConfigError::Validation {
                    field: "cluster.peers".into(),
                    message: "empty peer entry in peer list".into(),
                });
            }
            let parts: Vec<&str> = item.split('=').collect();
            if parts.len() != 2 {
                return Err(ConfigError::Validation {
                    field: "cluster.peers".into(),
                    message: format!("invalid peer format '{item}', expected node_id=host:port"),
                });
            }
            let node_id = parts[0].trim().to_string();
            if node_id.is_empty()
                || node_id
                    .chars()
                    .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
            {
                return Err(ConfigError::Validation {
                    field: "cluster.peers".into(),
                    message: format!("invalid peer node_id '{node_id}'"),
                });
            }
            let addr_str = parts[1].trim();
            let address: SocketAddr = addr_str.parse().map_err(|_| ConfigError::Validation {
                field: "cluster.peers".into(),
                message: format!("invalid peer address '{addr_str}' for node '{node_id}'"),
            })?;
            peers.push(ClusterPeer { node_id, address });
        }
        Ok(peers)
    }
}

fn default_node_id() -> String {
    "node1".into()
}
fn default_cluster_bind() -> SocketAddr {
    "127.0.0.1:0".parse().expect("valid default")
}
fn default_cluster_timeout() -> u64 {
    2
}
fn default_rate_capacity() -> u64 {
    100
}
fn default_rate_refill() -> f64 {
    10.0
}
fn default_plugin_directory() -> PathBuf {
    "./plugins".into()
}
fn default_plugin_max_plugins() -> usize {
    64
}
fn default_plugin_max_module_bytes() -> usize {
    16 * 1024 * 1024
}
fn default_plugin_max_memory_pages() -> u32 {
    256
}
fn default_plugin_max_fuel() -> u64 {
    10_000_000
}
fn default_plugin_invocation_timeout_ms() -> u64 {
    1_000
}
fn default_plugin_max_output_bytes() -> usize {
    64 * 1024
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
        let mut config: Self = toml::from_str(input)?;
        if let Ok(env_node_id) = std::env::var("NODE_ID") {
            let trimmed = env_node_id.trim();
            if !trimmed.is_empty() {
                config.cluster.node_id = trimmed.to_string();
            }
        }
        if let Ok(env_peers) = std::env::var("CLUSTER_PEERS") {
            config.cluster.peers = ClusterPeer::parse_peers(&env_peers)?;
        }
        if let Ok(env_token) = std::env::var("CLUSTER_AUTH_TOKEN") {
            config.cluster.auth_token = env_token;
        }
        config.validate()?;
        Ok(config)
    }
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.cluster.node_id.trim().is_empty()
            || self
                .cluster
                .node_id
                .chars()
                .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
        {
            return err(
                "cluster.node_id",
                "must be a non-empty string without whitespace or control characters",
            );
        }
        if self.cluster.timeout_seconds == 0 || self.cluster.timeout_seconds > 60 {
            return err("cluster.timeout_seconds", "must be between 1 and 60");
        }
        if self.cluster.peers.len() > 64 {
            return err(
                "cluster.peers",
                "peer count exceeds maximum limit of 64 peers",
            );
        }
        if !self.cluster.peers.is_empty() && !(32..=256).contains(&self.cluster.auth_token.len()) {
            return err(
                "cluster.auth_token",
                "must be between 32 and 256 bytes when peers are configured",
            );
        }
        let mut peer_ids = HashSet::new();
        let mut peer_addrs = HashSet::new();
        for (i, p) in self.cluster.peers.iter().enumerate() {
            if p.node_id.trim().is_empty()
                || p.node_id
                    .chars()
                    .any(|ch| ch.is_ascii_control() || ch.is_whitespace())
            {
                return err(
                    &format!("cluster.peers[{i}].node_id"),
                    "must be non-empty without whitespace or control characters",
                );
            }
            if p.node_id == self.cluster.node_id {
                return err(
                    &format!("cluster.peers[{i}].node_id"),
                    format!("peer node_id '{}' matches local node_id", p.node_id),
                );
            }
            if !peer_ids.insert(&p.node_id) {
                return err(
                    &format!("cluster.peers[{i}].node_id"),
                    format!("duplicate peer node_id '{}'", p.node_id),
                );
            }
            if !peer_addrs.insert(&p.address) {
                return err(
                    &format!("cluster.peers[{i}].address"),
                    format!("duplicate peer address '{}'", p.address),
                );
            }
        }
        if self.server.graceful_shutdown_seconds == 0 {
            return err("server.graceful_shutdown_seconds", "must be positive");
        }
        if let Err(message) = self.prometheus.validate() {
            return Err(validation("prometheus", message));
        }
        self.plugins.validate()?;
        if let Some(tls) = &self.server.tls {
            if tls.cert_path.as_os_str().is_empty() {
                return err("server.tls.cert_path", "must not be empty");
            }
            if tls.key_path.as_os_str().is_empty() {
                return err("server.tls.key_path", "must not be empty");
            }
        }
        if self.server.http3.enabled && self.server.tls.is_none() {
            return err(
                "server.http3.enabled",
                "requires server.tls to be configured",
            );
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
        if !(1..=1_000_000).contains(&self.rate_limit.capacity) {
            return err("rate_limit.capacity", "must be between 1 and 1000000");
        }
        if !self.rate_limit.refill_per_second.is_finite()
            || !(0.001..=100_000.0).contains(&self.rate_limit.refill_per_second)
        {
            return err(
                "rate_limit.refill_per_second",
                "must be between 0.001 and 100000",
            );
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
                if !(1..=1_000).contains(&b.weight) {
                    return err(
                        &format!("upstream_pools[{i}].backends[{j}].weight"),
                        "must be between 1 and 1000",
                    );
                }
                if b.health_check == HealthCheckKind::Http
                    && b.health_path.as_deref().is_none_or(|x| {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plugin_config_require_signature_defaults_to_false() {
        let config = PluginConfig::default();
        assert!(!config.require_signature);
    }

    #[test]
    fn plugin_config_require_signature_round_trips_through_toml() {
        let parsed: PluginConfig = toml::from_str(
            r#"
            enabled = true
            directory = "plugins"
            require_signature = true
            "#,
        )
        .unwrap();
        assert!(parsed.require_signature);
    }

    const MINIMAL_ROUTABLE: &str = r#"
[[upstream_pools]]
name = "api"
algorithm = "round_robin"

[[upstream_pools.backends]]
address = "127.0.0.1:19001"
health_check = "tcp"

[[routes]]
name = "api"
host = "api.example.com"
path_prefix = "/"
upstream_pool = "api"
"#;

    #[test]
    fn http3_enabled_without_tls_is_rejected() {
        let toml = format!(
            r#"
[server]
bind = "127.0.0.1:8080"
control_bind = "127.0.0.1:8081"

[server.http3]
enabled = true
bind = "127.0.0.1:8443"
{MINIMAL_ROUTABLE}"#
        );
        let result = Config::parse(&toml);
        assert!(
            result.is_err(),
            "http3.enabled without server.tls must be rejected"
        );
    }

    #[test]
    fn http3_disabled_by_default() {
        let toml = format!(
            r#"
[server]
bind = "127.0.0.1:8080"
control_bind = "127.0.0.1:8081"
{MINIMAL_ROUTABLE}"#
        );
        let config = Config::parse(&toml).unwrap();
        assert!(!config.server.http3.enabled);
    }
}
