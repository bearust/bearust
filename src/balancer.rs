use crate::config::{Algorithm, HealthCheckKind, PoolConfig};
use std::{
    hash::Hash,
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BackendId(usize);

impl From<usize> for BackendId {
    fn from(value: usize) -> Self {
        Self(value)
    }
}

impl BackendId {
    pub fn index(self) -> usize {
        self.0
    }
}

struct BackendState {
    id: BackendId,
    address: SocketAddr,
    healthy: AtomicBool,
    inflight: AtomicUsize,
    health_check: HealthCheckKind,
    health_path: Option<String>,
}

pub struct PoolState {
    name: String,
    algorithm: Algorithm,
    backends: Vec<Arc<BackendState>>,
    cursor: AtomicUsize,
}

pub struct BackendLease {
    backend: Arc<BackendState>,
}

impl PoolState {
    pub fn new(config: &PoolConfig) -> Self {
        let backends = config
            .backends
            .iter()
            .enumerate()
            .map(|(index, backend)| {
                Arc::new(BackendState {
                    id: index.into(),
                    address: backend.address,
                    healthy: AtomicBool::new(false),
                    inflight: AtomicUsize::new(0),
                    health_check: backend.health_check,
                    health_path: backend.health_path.clone(),
                })
            })
            .collect();
        Self {
            name: config.name.clone(),
            algorithm: config.algorithm,
            backends,
            cursor: AtomicUsize::new(0),
        }
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn preserve_health_from(&self, previous: &PoolState) {
        for backend in &self.backends {
            let Some(old) = previous.backends.iter().find(|old| {
                old.address == backend.address
                    && old.health_check == backend.health_check
                    && old.health_path == backend.health_path
            }) else {
                continue;
            };
            backend
                .healthy
                .store(old.healthy.load(Ordering::Acquire), Ordering::Release);
        }
    }

    pub fn select(self: &Arc<Self>, excluded: Option<BackendId>) -> Option<BackendLease> {
        if self.backends.is_empty() {
            return None;
        }
        let start = self.cursor.fetch_add(1, Ordering::Relaxed) % self.backends.len();
        let selected = match self.algorithm {
            Algorithm::RoundRobin => (0..self.backends.len())
                .map(|offset| (start + offset) % self.backends.len())
                .map(|index| &self.backends[index])
                .find(|backend| {
                    Some(backend.id) != excluded && backend.healthy.load(Ordering::Acquire)
                })
                .cloned(),
            Algorithm::LeastConnections => {
                let mut best: Option<Arc<BackendState>> = None;
                let mut best_count = usize::MAX;
                for offset in 0..self.backends.len() {
                    let backend = &self.backends[(start + offset) % self.backends.len()];
                    if Some(backend.id) == excluded || !backend.healthy.load(Ordering::Acquire) {
                        continue;
                    }
                    let count = backend.inflight.load(Ordering::Relaxed);
                    if count < best_count {
                        best_count = count;
                        best = Some(Arc::clone(backend));
                    }
                }
                best
            }
        }?;

        selected.inflight.fetch_add(1, Ordering::AcqRel);
        Some(BackendLease { backend: selected })
    }

    pub fn set_healthy(&self, id: BackendId, healthy: bool) {
        if let Some(backend) = self.backends.get(id.0) {
            backend.healthy.store(healthy, Ordering::Release);
        }
    }

    pub fn backend_ids(&self) -> Vec<BackendId> {
        self.backends.iter().map(|backend| backend.id).collect()
    }

    pub fn backend_address(&self, id: BackendId) -> Option<SocketAddr> {
        self.backends.get(id.0).map(|backend| backend.address)
    }

    pub fn backend_health_check(&self, id: BackendId) -> Option<(HealthCheckKind, Option<String>)> {
        self.backends
            .get(id.0)
            .map(|b| (b.health_check, b.health_path.clone()))
    }

    pub fn is_healthy(&self, id: BackendId) -> bool {
        self.backends
            .get(id.0)
            .is_some_and(|backend| backend.healthy.load(Ordering::Acquire))
    }

    pub fn total_inflight(&self) -> usize {
        self.backends
            .iter()
            .map(|backend| backend.inflight.load(Ordering::Acquire))
            .sum()
    }
}

impl BackendLease {
    pub fn id(&self) -> BackendId {
        self.backend.id
    }

    pub fn address(&self) -> SocketAddr {
        self.backend.address
    }
}

impl Drop for BackendLease {
    fn drop(&mut self) {
        let previous = self.backend.inflight.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(
            previous > 0,
            "backend lease dropped with no in-flight request"
        );
    }
}
