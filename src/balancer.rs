use crate::config::{Algorithm, HealthCheckKind, PoolConfig};
use std::{
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    net::SocketAddr,
    sync::{
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

const PASSIVE_FAILURE_THRESHOLD: usize = 3;

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
    weight: u32,
    response_ewma_ms: AtomicU64,
    passive_failures: AtomicUsize,
    health_check: HealthCheckKind,
    health_path: Option<String>,
}

pub struct PoolState {
    name: String,
    algorithm: Algorithm,
    backends: Vec<Arc<BackendState>>,
    cursor: AtomicUsize,
    passive_health: bool,
    connect_timeout: Duration,
    request_timeout: Duration,
}

pub struct BackendLease {
    backend: Arc<BackendState>,
}

/// A read-only snapshot of one backend's current state, as reported to a
/// `balance.select` plugin (via `src/proxy.rs`, which converts this into
/// the plugin SDK's `BackendCandidate` wire type). Deliberately not the
/// SDK type itself -- `balancer.rs` has no dependency on the plugin
/// system, matching how it also doesn't know about WAF or transforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendSnapshot {
    pub id: BackendId,
    pub address: SocketAddr,
    pub healthy: bool,
    pub inflight: usize,
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
                    weight: backend.weight,
                    response_ewma_ms: AtomicU64::new(0),
                    passive_failures: AtomicUsize::new(0),
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
            passive_health: config.passive_health,
            connect_timeout: Duration::from_secs(config.connect_timeout_seconds),
            request_timeout: Duration::from_secs(config.request_timeout_seconds),
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
            backend.response_ewma_ms.store(
                old.response_ewma_ms.load(Ordering::Acquire),
                Ordering::Release,
            );
            backend.passive_failures.store(
                old.passive_failures.load(Ordering::Acquire),
                Ordering::Release,
            );
        }
    }

    pub fn select(self: &Arc<Self>, excluded: Option<BackendId>) -> Option<BackendLease> {
        self.select_with_key(excluded, None)
    }

    /// Select a backend using the configured algorithm. `key` is the stable
    /// client identity used by IP-hash pools; other algorithms ignore it.
    pub fn select_with_key(
        self: &Arc<Self>,
        excluded: Option<BackendId>,
        key: Option<&[u8]>,
    ) -> Option<BackendLease> {
        if self.backends.is_empty() {
            return None;
        }
        let cursor = self.cursor.fetch_add(1, Ordering::Relaxed) as u64;
        let start = cursor as usize % self.backends.len();
        let candidates: Vec<Arc<BackendState>> = self
            .backends
            .iter()
            .filter(|backend| {
                Some(backend.id) != excluded && backend.healthy.load(Ordering::Acquire)
            })
            .cloned()
            .collect();
        if candidates.is_empty() {
            return None;
        }
        let selected = match self.algorithm {
            // A `Plugin`-configured pool's primary selection happens in
            // `src/proxy.rs::apply_load_balancer_plugin`, called before
            // `select()`. This arm is `select()`'s role as that path's
            // deterministic fallback -- identical to `RoundRobin` so a
            // `Plugin` pool never has "no algorithm" to fall back to.
            Algorithm::RoundRobin | Algorithm::Plugin => (0..self.backends.len())
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
            Algorithm::Weighted => weighted_choice(&candidates, cursor, false),
            Algorithm::AdaptiveWeight => weighted_choice(&candidates, cursor, true),
            Algorithm::IpHash => {
                let Some(key) = key else {
                    return self.select_with_key(excluded, Some(&start.to_ne_bytes()));
                };
                let mut hasher = DefaultHasher::new();
                key.hash(&mut hasher);
                candidates
                    .get((hasher.finish() as usize) % candidates.len())
                    .cloned()
            }
        }?;

        selected.inflight.fetch_add(1, Ordering::AcqRel);
        Some(BackendLease { backend: selected })
    }

    pub fn set_healthy(&self, id: BackendId, healthy: bool) {
        if let Some(backend) = self.backends.get(id.0) {
            backend.healthy.store(healthy, Ordering::Release);
            if healthy {
                backend.passive_failures.store(0, Ordering::Release);
            }
        }
    }

    /// Record a completed request for adaptive weighting and optional
    /// passive health. Active probes remain the source of recovery; a real
    /// successful request only clears the passive failure counter.
    pub fn record_result(&self, id: BackendId, status_code: u16, latency_ms: u64) {
        let Some(backend) = self.backends.get(id.0) else {
            return;
        };
        let mut previous = backend.response_ewma_ms.load(Ordering::Acquire);
        loop {
            let next = if previous == 0 {
                latency_ms.max(1)
            } else {
                previous.saturating_mul(4).saturating_add(latency_ms.max(1)) / 5
            };
            match backend.response_ewma_ms.compare_exchange_weak(
                previous,
                next.max(1),
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => break,
                Err(actual) => previous = actual,
            }
        }
        if !self.passive_health {
            return;
        }
        if status_code == 0 || status_code >= 500 {
            let failures = backend.passive_failures.fetch_add(1, Ordering::AcqRel) + 1;
            if failures >= PASSIVE_FAILURE_THRESHOLD {
                backend.healthy.store(false, Ordering::Release);
            }
        } else {
            backend.passive_failures.store(0, Ordering::Release);
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

    pub fn passive_health(&self) -> bool {
        self.passive_health
    }

    pub fn backend_weight(&self, id: BackendId) -> Option<u32> {
        self.backends.get(id.0).map(|backend| backend.weight)
    }

    pub fn response_ewma_ms(&self, id: BackendId) -> Option<u64> {
        self.backends
            .get(id.0)
            .map(|backend| backend.response_ewma_ms.load(Ordering::Acquire))
            .filter(|value| *value > 0)
    }

    pub fn passive_failures(&self, id: BackendId) -> Option<usize> {
        self.backends
            .get(id.0)
            .map(|backend| backend.passive_failures.load(Ordering::Acquire))
    }

    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }
    pub fn request_timeout(&self) -> Duration {
        self.request_timeout
    }

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// A read-only snapshot of every backend in this pool, for a
    /// `balance.select` plugin to choose among. Pure; does not affect
    /// selection state.
    pub fn candidates(&self) -> Vec<BackendSnapshot> {
        self.backends
            .iter()
            .map(|backend| BackendSnapshot {
                id: backend.id,
                address: backend.address,
                healthy: backend.healthy.load(Ordering::Acquire),
                inflight: backend.inflight.load(Ordering::Acquire),
            })
            .collect()
    }

    /// Leases `id` directly if it names a backend in this pool that is
    /// currently healthy and isn't `excluded` -- `None` on any of those
    /// three failures. Used to apply a `balance.select` plugin's pick;
    /// the caller falls back to `select()` when this returns `None`.
    pub fn select_specific(
        self: &Arc<Self>,
        id: BackendId,
        excluded: Option<BackendId>,
    ) -> Option<BackendLease> {
        if Some(id) == excluded {
            return None;
        }
        let backend = self.backends.get(id.0)?;
        if !backend.healthy.load(Ordering::Acquire) {
            return None;
        }
        backend.inflight.fetch_add(1, Ordering::AcqRel);
        Some(BackendLease {
            backend: Arc::clone(backend),
        })
    }
}

fn weighted_choice(
    candidates: &[Arc<BackendState>],
    cursor: u64,
    adaptive: bool,
) -> Option<Arc<BackendState>> {
    let weights: Vec<u64> = candidates
        .iter()
        .map(|backend| {
            let base = backend.weight.max(1) as u64;
            if !adaptive {
                return base;
            }
            let latency = backend.response_ewma_ms.load(Ordering::Acquire);
            if latency == 0 {
                return base;
            }
            base.saturating_mul((1_000 / latency.max(1)).max(1))
        })
        .collect();
    let total = weights.iter().copied().sum::<u64>().max(1);
    let mut slot = cursor % total;
    for (candidate, weight) in candidates.iter().zip(weights) {
        if slot < weight {
            return Some(Arc::clone(candidate));
        }
        slot -= weight;
    }
    candidates.last().cloned()
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
