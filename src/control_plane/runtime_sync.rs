//! Runtime activation for control-plane configuration.
//!
//! Proxy hosts are durable control-plane records, but the data plane routes
//! requests from the native runtime `Config`.  This adapter keeps the two
//! views coherent by materialising one reserved pool and route per enabled
//! proxy host while leaving operator-managed pools and routes untouched.

use super::{ConfigReloader, DesiredConfig, ReloadError};
use crate::config::{
    Algorithm, BackendConfig, Config, HealthCheckKind, PoolConfig, RouteConfig, TlsConfig,
};
use crate::control_plane::repository::{self, DbPool};
use crate::rate_limit::RateLimitPolicy;
use crate::runtime::RuntimeStore;
use crate::security_policy::IpSecurityStore;
use crate::{bot_store::BotStore, rate_limit_store::RateLimiterStore, waf_store::WafStore};
use async_trait::async_trait;
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

const HOST_POOL_PREFIX: &str = "proxy-host-";
const HOST_ROUTE_PREFIX: &str = "proxy-host-";

pub struct RuntimeConfigReloader {
    runtime: Arc<RuntimeStore>,
    database: DbPool,
    config_path: Arc<PathBuf>,
    pid_file: Arc<PathBuf>,
    lock: Arc<Mutex<()>>,
    waf: Option<Arc<WafStore>>,
    ip_security: Option<Arc<IpSecurityStore>>,
    bot: Option<Arc<BotStore>>,
    host_auth: Option<Arc<crate::security_policy::HostAuthStore>>,
    rate_limiter: Option<Arc<RateLimiterStore>>,
    analytics: Option<Arc<crate::analytics::AnalyticsCollector>>,
    adaptive_tuning: Option<Arc<crate::adaptive_tuning::AdaptiveTuningEngine>>,
}

pub struct RuntimePolicyStores {
    pub waf: Arc<WafStore>,
    pub ip_security: Arc<IpSecurityStore>,
    pub bot: Arc<BotStore>,
    pub host_auth: Arc<crate::security_policy::HostAuthStore>,
    pub rate_limiter: Arc<RateLimiterStore>,
    pub analytics: Arc<crate::analytics::AnalyticsCollector>,
    pub adaptive_tuning: Arc<crate::adaptive_tuning::AdaptiveTuningEngine>,
}

impl RuntimeConfigReloader {
    pub fn new(
        runtime: Arc<RuntimeStore>,
        database: DbPool,
        config_path: impl Into<Arc<PathBuf>>,
        pid_file: impl Into<Arc<PathBuf>>,
        lock: Arc<Mutex<()>>,
    ) -> Self {
        Self {
            runtime,
            database,
            config_path: config_path.into(),
            pid_file: pid_file.into(),
            lock,
            waf: None,
            ip_security: None,
            bot: None,
            host_auth: None,
            rate_limiter: None,
            analytics: None,
            adaptive_tuning: None,
        }
    }

    pub fn with_policy_stores(mut self, stores: RuntimePolicyStores) -> Self {
        self.waf = Some(stores.waf);
        self.ip_security = Some(stores.ip_security);
        self.bot = Some(stores.bot);
        self.host_auth = Some(stores.host_auth);
        self.rate_limiter = Some(stores.rate_limiter);
        self.analytics = Some(stores.analytics);
        self.adaptive_tuning = Some(stores.adaptive_tuning);
        self
    }

    async fn apply_config(&self, next: Config) -> Result<(), ReloadError> {
        let host_ids = repository::list_hosts(&self.database)
            .await
            .map_err(|error| ReloadError::Failed(format!("load proxy host identities: {error}")))?
            .into_iter()
            .filter(|host| host.enabled)
            .map(|host| (host.domain, host.id))
            .collect();
        let previous_persisted = repository::get_runtime_config(&self.database)
            .await
            .map_err(|error| {
                ReloadError::Failed(format!("read previous runtime config: {error}"))
            })?;
        repository::set_runtime_config(&self.database, &next)
            .await
            .map_err(|error| ReloadError::Failed(format!("persist runtime config: {error}")))?;
        if let Err(error) = self
            .runtime
            .apply_config_with_host_ids(next.clone(), host_ids)
            .await
        {
            let _ =
                restore_persisted_runtime_config(&self.database, previous_persisted.as_ref()).await;
            return Err(ReloadError::Failed(error.to_string()));
        }
        if let Err(error) = persist_config(&self.config_path, &next) {
            // The control-plane database is the durable source of truth for
            // runtime changes. Container deployments commonly mount the base
            // TOML read-only (and a single-file bind mount cannot be replaced
            // atomically), so failure to mirror it back must not reject an
            // otherwise valid and already-persisted live update.
            tracing::warn!(
                event = "config_file_persist_skipped",
                path = %self.config_path.display(),
                reason = %error,
                "runtime configuration remains persisted in the control-plane database"
            );
        }
        Ok(())
    }

    async fn resolve_upstream(host: &str, port: u16) -> Result<SocketAddr, ReloadError> {
        if let Ok(address) = host.parse::<IpAddr>() {
            return Ok(SocketAddr::new(address, port));
        }
        let mut addresses = tokio::net::lookup_host((host, port))
            .await
            .map_err(|error| ReloadError::Failed(format!("resolve upstream host: {error}")))?;
        addresses
            .next()
            .ok_or_else(|| ReloadError::Failed("upstream host resolved to no addresses".into()))
    }

    async fn refresh_policy_stores(&self) -> Result<(), ReloadError> {
        if let Some(waf) = &self.waf {
            waf.reload(&self.database)
                .await
                .map_err(ReloadError::Failed)?;
        }
        if let Some(ip_security) = &self.ip_security {
            ip_security
                .reload(&self.database)
                .await
                .map_err(ReloadError::Failed)?;
        }
        if let Some(bot) = &self.bot {
            bot.reload(&self.database)
                .await
                .map_err(ReloadError::Failed)?;
        }
        if let Some(host_auth) = &self.host_auth {
            host_auth
                .reload(&self.database)
                .await
                .map_err(ReloadError::Failed)?;
        }
        if let Some(rate_limiter) = &self.rate_limiter {
            let config = repository::get_rate_limit_config(&self.database)
                .await
                .map_err(|error| ReloadError::Failed(format!("load rate-limit policy: {error}")))?;
            rate_limiter.set_policy(RateLimitPolicy {
                enabled: config.enabled,
                action: config.action,
                capacity: config.capacity,
                refill_per_second: config.refill_per_second,
                key_scope: config.key_scope,
            });
            rate_limiter.clear_host_policies();
            for (host_id, config) in repository::list_host_rate_limit_configs(&self.database)
                .await
                .map_err(|error| {
                    ReloadError::Failed(format!("load host rate-limit policies: {error}"))
                })?
            {
                rate_limiter.set_host_policy(
                    host_id,
                    RateLimitPolicy {
                        enabled: config.enabled,
                        action: config.action,
                        capacity: config.capacity,
                        refill_per_second: config.refill_per_second,
                        key_scope: config.key_scope,
                    },
                );
            }
        }
        if let Some(analytics) = &self.analytics {
            let retention = repository::get_analytics_retention(&self.database)
                .await
                .map_err(|error| {
                    ReloadError::Failed(format!("load analytics retention: {error}"))
                })?;
            analytics.set_retention_minutes(retention.retention_minutes as usize);
        }
        if let Some(adaptive_tuning) = &self.adaptive_tuning {
            let disabled = repository::get_emergency_disabled(&self.database)
                .await
                .map_err(|error| {
                    ReloadError::Failed(format!("load adaptive tuning state: {error}"))
                })?;
            adaptive_tuning.set_emergency_disabled(disabled);
        }
        Ok(())
    }

    async fn materialize(
        &self,
        mut config: Config,
        hosts: &[crate::control_plane::models::ProxyHost],
    ) -> Result<Config, ReloadError> {
        config
            .upstream_pools
            .retain(|pool| !pool.name.starts_with(HOST_POOL_PREFIX));
        config
            .routes
            .retain(|route| !route.name.starts_with(HOST_ROUTE_PREFIX));

        for host in hosts.iter().filter(|host| host.enabled) {
            let address = Self::resolve_upstream(&host.upstream_host, host.upstream_port).await?;
            config.upstream_pools.push(PoolConfig {
                name: format!("{HOST_POOL_PREFIX}{}", host.id),
                algorithm: Algorithm::RoundRobin,
                connect_timeout_seconds: 3,
                request_timeout_seconds: 30,
                passive_health: true,
                backends: vec![BackendConfig {
                    address,
                    health_check: HealthCheckKind::Tcp,
                    health_path: None,
                    weight: 1,
                }],
            });
            config.routes.push(RouteConfig {
                name: format!("{HOST_ROUTE_PREFIX}{}", host.id),
                host: host.domain.clone(),
                path_prefix: "/".into(),
                upstream_pool: format!("{HOST_POOL_PREFIX}{}", host.id),
            });
        }
        config
            .validate()
            .map_err(|error| ReloadError::Failed(error.to_string()))?;
        Ok(config)
    }

    pub async fn apply_native_config(&self, config: Config) -> Result<(), ReloadError> {
        let _guard = self.lock.lock().await;
        config
            .validate()
            .map_err(|error| ReloadError::Failed(error.to_string()))?;
        self.apply_config(config).await
    }

    pub async fn refresh_from_database(&self, event_type: &str) -> Result<(), ReloadError> {
        let _guard = self.lock.lock().await;
        if event_type == "runtime_config.changed" {
            if let Some(config) = repository::get_runtime_config(&self.database)
                .await
                .map_err(|error| {
                    ReloadError::Failed(format!("load persisted runtime config: {error}"))
                })?
            {
                self.apply_config(config).await?;
            }
        } else if matches!(event_type, "proxy_hosts.changed" | "cluster.catch_up") {
            let hosts = repository::list_hosts(&self.database)
                .await
                .map_err(|error| ReloadError::Failed(format!("load proxy hosts: {error}")))?;
            let current = self.runtime.load().config().clone();
            let next = self.materialize(current, &hosts).await?;
            self.apply_config(next).await?;
        }
        self.refresh_policy_stores().await
    }

    async fn reload_parent(&self) -> Result<(), ReloadError> {
        crate::reload::signal_reload(Path::new(self.pid_file.as_ref()))
            .map_err(|error| ReloadError::Failed(error.to_string()))
    }
}

#[async_trait]
impl ConfigReloader for RuntimeConfigReloader {
    async fn apply(&self, desired: DesiredConfig) -> Result<(), ReloadError> {
        let _guard = self.lock.lock().await;
        let current = self.runtime.load().config().clone();
        let next = self.materialize(current, &desired.proxy_hosts).await?;
        self.apply_config(next).await
    }

    async fn apply_runtime_config(&self, config: Config) -> Result<(), ReloadError> {
        self.apply_native_config(config).await
    }

    async fn refresh_from_database(&self, event_type: &str) -> Result<(), ReloadError> {
        RuntimeConfigReloader::refresh_from_database(self, event_type).await
    }

    async fn apply_certificate_change(&self, certificate_id: i64) -> Result<(), ReloadError> {
        let _guard = self.lock.lock().await;
        let previous = self.runtime.load().config().clone();
        let Some((_name, certificate_path, key_path)) =
            repository::certificate_paths(&self.database, certificate_id)
                .await
                .map_err(|error| ReloadError::Failed(format!("read certificate paths: {error}")))?
        else {
            return Err(ReloadError::Failed("certificate was not found".into()));
        };
        let mut next = self.runtime.load().config().clone();
        next.server.tls = Some(TlsConfig {
            cert_path: certificate_path.into(),
            key_path: key_path.into(),
        });
        next.validate()
            .map_err(|error| ReloadError::Failed(error.to_string()))?;
        self.apply_config(next).await?;
        // Pingora binds TLS settings when the service is constructed.  Ask
        // the supervisor to perform its validated zero-downtime replacement
        // so the newly activated material reaches the listener as well.
        if let Err(error) = self.reload_parent().await {
            // The control-plane request may be running in the current proxy
            // child. If the supervisor cannot start the replacement, restore
            // the old runtime/TOML snapshot before reporting failure.
            let _ = self.apply_config(previous).await;
            return Err(error);
        }
        Ok(())
    }
}

async fn restore_persisted_runtime_config(
    database: &DbPool,
    previous: Option<&Config>,
) -> Result<(), sqlx::Error> {
    match previous {
        Some(config) => repository::set_runtime_config(database, config).await,
        None => sqlx::query("DELETE FROM runtime_config WHERE id=1")
            .execute(database)
            .await
            .map(|_| ()),
    }
}

fn persist_config(path: &Path, config: &Config) -> Result<(), String> {
    let serialized = toml::to_string_pretty(config)
        .map_err(|error| format!("serialize configuration: {error}"))?;
    let temporary = path.with_extension("control-plane.tmp");
    std::fs::write(&temporary, serialized)
        .map_err(|error| format!("write temporary configuration: {error}"))?;
    std::fs::rename(&temporary, path).map_err(|error| format!("replace configuration: {error}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    #[test]
    fn reserved_names_are_stable() {
        assert_eq!(format!("{HOST_POOL_PREFIX}42"), "proxy-host-42");
        assert_eq!(format!("{HOST_ROUTE_PREFIX}42"), "proxy-host-42");
    }

    #[test]
    fn config_is_serializable_after_materialized_fields_are_added() {
        let config: Config = toml::from_str(
            r#"
            [server]
            bind = "127.0.0.1:8080"
            [[upstream_pools]]
            name = "manual"
            algorithm = "round_robin"
            [[upstream_pools.backends]]
            address = "127.0.0.1:9000"
            health_check = "tcp"
            [[routes]]
            name = "manual"
            host = "manual.example.test"
            path_prefix = "/"
            upstream_pool = "manual"
            "#,
        )
        .unwrap();
        assert!(toml::to_string_pretty(&config).is_ok());
    }
}
