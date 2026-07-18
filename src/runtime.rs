use crate::{
    balancer::PoolState,
    config::{self, Config},
    health::{HealthError, HealthSupervisor},
    router::{ResolvedRoute, Router},
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
}

pub struct RuntimeSnapshot {
    generation: u64,
    config: Arc<Config>,
    router: Router,
    pools: HashMap<String, Arc<PoolState>>,
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
        Ok(Self {
            generation,
            router: Router::new(&config.routes),
            config: Arc::new(config),
            pools,
        })
    }
    pub fn generation(&self) -> u64 {
        self.generation
    }
    pub fn config(&self) -> &Config {
        &self.config
    }
    pub fn route(&self, authority: &str, path: &str) -> Option<(&ResolvedRoute, Arc<PoolState>)> {
        let route = self.router.route(authority, path)?;
        Some((route, Arc::clone(self.pools.get(&route.upstream_pool)?)))
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
