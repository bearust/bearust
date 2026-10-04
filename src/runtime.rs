use crate::{
    balancer::PoolState,
    config::{self, Config},
    health::{HealthError, HealthSupervisor},
    router::{ResolvedRoute, Router},
    tls::{self, TlsSnapshot},
};
use arc_swap::ArcSwap;
use std::{collections::HashMap, path::Path, sync::Arc};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Health(#[from] HealthError),
    #[error(transparent)]
    Tls(#[from] tls::TlsError),
    #[error("signal handler failed: {0}")]
    Signal(String),
}

pub struct RuntimeSnapshot {
    generation: u64,
    config: Arc<Config>,
    router: Router,
    pools: HashMap<String, Arc<PoolState>>,
    tls: Option<Arc<TlsSnapshot>>,
    proxy_host_ids: HashMap<String, i64>,
}

impl RuntimeSnapshot {
    pub fn build(config: Config, previous: Option<&RuntimeSnapshot>) -> Result<Self, RuntimeError> {
        let generation = previous.map_or(1, |snapshot| snapshot.generation + 1);
        let pools = config
            .upstream_pools
            .iter()
            .map(|pool_config| {
                let pool = Arc::new(PoolState::new(pool_config));
                if let Some(old) =
                    previous.and_then(|snapshot| snapshot.pools.get(&pool_config.name))
                {
                    pool.preserve_health_from(old);
                }
                (pool_config.name.clone(), pool)
            })
            .collect();
        let tls = config
            .server
            .tls
            .as_ref()
            .map(TlsSnapshot::from_config)
            .transpose()?
            .map(Arc::new);
        let proxy_host_ids = previous
            .map(|snapshot| snapshot.proxy_host_ids.clone())
            .unwrap_or_default();
        let mut snapshot = Self {
            generation,
            router: Router::new(&config.routes),
            config: Arc::new(config),
            pools,
            tls,
            proxy_host_ids: HashMap::new(),
        };
        snapshot.set_proxy_host_ids(proxy_host_ids);
        Ok(snapshot)
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn tls(&self) -> Option<Arc<TlsSnapshot>> {
        self.tls.clone()
    }
    pub fn route(&self, authority: &str, path: &str) -> Option<(&ResolvedRoute, Arc<PoolState>)> {
        let route = self.router.route(authority, path)?;
        Some((route, Arc::clone(self.pools.get(&route.upstream_pool)?)))
    }
    pub fn pool(&self, name: &str) -> Option<Arc<PoolState>> {
        self.pools.get(name).cloned()
    }
    pub fn proxy_host_id(&self, authority: &str) -> Option<i64> {
        self.proxy_host_ids
            .get(&crate::router::normalize_host(authority)?)
            .copied()
    }

    fn set_proxy_host_ids(&mut self, ids: HashMap<String, i64>) {
        // IDs come from the control-plane database, never from operator-
        // supplied route names. Keep identity and routes in one atomic snapshot.
        let routed_hosts: std::collections::HashSet<_> = self
            .config
            .routes
            .iter()
            .filter_map(|route| crate::router::normalize_host(&route.host))
            .collect();
        self.proxy_host_ids = ids
            .into_iter()
            .filter_map(|(host, id)| {
                let host = crate::router::normalize_host(&host)?;
                (id > 0 && routed_hosts.contains(&host)).then_some((host, id))
            })
            .collect();
    }
    pub fn pools(&self) -> impl Iterator<Item = Arc<PoolState>> + '_ {
        self.pools.values().cloned()
    }
}

pub struct RuntimeStore {
    current: ArcSwap<RuntimeSnapshot>,
    reload_lock: Mutex<()>,
    health: Mutex<Option<HealthSupervisor>>,
}

impl RuntimeStore {
    pub fn new(snapshot: RuntimeSnapshot) -> Self {
        Self {
            current: ArcSwap::from_pointee(snapshot),
            reload_lock: Mutex::new(()),
            health: Mutex::new(None),
        }
    }
    pub async fn from_path(path: &Path) -> Result<Self, RuntimeError> {
        let snapshot = RuntimeSnapshot::build(config::load(path)?, None)?;
        let supervisor =
            HealthSupervisor::start(snapshot.pools().collect(), snapshot.config().health.clone())
                .await?;
        let store = Self::new(snapshot);
        *store.health.lock().await = Some(supervisor);
        Ok(store)
    }
    pub fn load(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }
    pub async fn reload(&self, path: &Path) -> Result<ReloadOutcome, RuntimeError> {
        let _guard = self.reload_lock.lock().await;
        let old = self.load();
        let candidate = RuntimeSnapshot::build(config::load(path)?, Some(&old))?;
        let replacement = HealthSupervisor::start(
            candidate.pools().collect(),
            candidate.config().health.clone(),
        )
        .await?;
        let outcome = ReloadOutcome {
            old_generation: old.generation,
            new_generation: candidate.generation,
        };
        self.current.store(Arc::new(candidate));
        let old_supervisor = self.health.lock().await.replace(replacement);
        if let Some(supervisor) = old_supervisor {
            supervisor.shutdown().await?;
        }
        Ok(outcome)
    }

    /// Apply a validated configuration supplied by the control plane without
    /// waiting for a process signal. The candidate is built and its health
    /// workers are started before the active snapshot is swapped, so a bad
    /// pool or route can never partially replace live traffic configuration.
    pub async fn apply_config(&self, config: Config) -> Result<ReloadOutcome, RuntimeError> {
        self.apply_config_with_identity(config, None).await
    }

    pub async fn apply_config_with_host_ids(
        &self,
        config: Config,
        host_ids: HashMap<String, i64>,
    ) -> Result<ReloadOutcome, RuntimeError> {
        self.apply_config_with_identity(config, Some(host_ids))
            .await
    }

    async fn apply_config_with_identity(
        &self,
        config: Config,
        host_ids: Option<HashMap<String, i64>>,
    ) -> Result<ReloadOutcome, RuntimeError> {
        config.validate()?;
        let _guard = self.reload_lock.lock().await;
        let old = self.load();
        let mut candidate = RuntimeSnapshot::build(config, Some(&old))?;
        if let Some(host_ids) = host_ids {
            candidate.set_proxy_host_ids(host_ids);
        }
        let replacement = HealthSupervisor::start(
            candidate.pools().collect(),
            candidate.config().health.clone(),
        )
        .await?;
        let outcome = ReloadOutcome {
            old_generation: old.generation,
            new_generation: candidate.generation,
        };
        self.current.store(Arc::new(candidate));
        let old_supervisor = self.health.lock().await.replace(replacement);
        if let Some(supervisor) = old_supervisor {
            supervisor.shutdown().await?;
        }
        Ok(outcome)
    }

    /// Stop health workers owned by this store.
    ///
    /// This is primarily useful for graceful shutdown and deterministic tests;
    /// dropping a store alone cannot await the spawned Tokio tasks.
    pub async fn shutdown(&self) -> Result<(), RuntimeError> {
        let supervisor = self.health.lock().await.take();
        if let Some(supervisor) = supervisor {
            supervisor.shutdown().await?;
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReloadOutcome {
    pub old_generation: u64,
    pub new_generation: u64,
}
