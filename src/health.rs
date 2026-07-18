use crate::{
    balancer::PoolState,
    config::{HealthCheckKind, HealthConfig},
};
use std::{num::NonZeroU64, sync::Arc, time::Duration};
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::watch,
    task::JoinHandle,
    time,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthState {
    Probing,
    Healthy,
    Unhealthy,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HealthTransition {
    BecameHealthy,
    BecameUnhealthy,
}

pub struct HealthTracker {
    state: HealthState,
    successes: u64,
    failures: u64,
    healthy_threshold: NonZeroU64,
    unhealthy_threshold: NonZeroU64,
}
impl HealthTracker {
    pub fn new(healthy_threshold: u64, unhealthy_threshold: u64) -> Self {
        Self {
            state: HealthState::Probing,
            successes: 0,
            failures: 0,
            healthy_threshold: NonZeroU64::new(healthy_threshold).unwrap_or(NonZeroU64::MIN),
            unhealthy_threshold: NonZeroU64::new(unhealthy_threshold).unwrap_or(NonZeroU64::MIN),
        }
    }
    pub fn state(&self) -> HealthState {
        self.state
    }
    pub fn record(&mut self, success: bool) -> Option<HealthTransition> {
        if success {
            self.successes = self.successes.saturating_add(1);
            self.failures = 0;
        } else {
            self.failures = self.failures.saturating_add(1);
            self.successes = 0;
        }
        match self.state {
            HealthState::Healthy if !success && self.failures >= self.unhealthy_threshold.get() => {
                self.state = HealthState::Unhealthy;
                Some(HealthTransition::BecameUnhealthy)
            }
            HealthState::Probing | HealthState::Unhealthy
                if success && self.successes >= self.healthy_threshold.get() =>
            {
                self.state = HealthState::Healthy;
                Some(HealthTransition::BecameHealthy)
            }
            HealthState::Probing if !success && self.failures >= self.unhealthy_threshold.get() => {
                self.state = HealthState::Unhealthy;
                Some(HealthTransition::BecameUnhealthy)
            }
            _ => None,
        }
    }
}

pub async fn probe_tcp(address: std::net::SocketAddr, timeout: Duration) -> bool {
    time::timeout(timeout, TcpStream::connect(address))
        .await
        .is_ok_and(|r| r.is_ok())
}

pub async fn probe_http(address: std::net::SocketAddr, path: &str, timeout: Duration) -> bool {
    let result = time::timeout(timeout, async {
        let mut stream = TcpStream::connect(address).await?;
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, address
        );
        stream.write_all(request.as_bytes()).await?;
        let mut data = Vec::with_capacity(64);
        let mut byte = [0u8; 1];
        while data.len() < 128 {
            if stream.read_exact(&mut byte).await.is_err() {
                break;
            }
            data.push(byte[0]);
            if data.ends_with(b"\r\n") {
                break;
            }
        }
        let line = std::str::from_utf8(&data).ok().unwrap_or("");
        Ok::<bool, std::io::Error>(
            line.split_whitespace()
                .nth(1)
                .and_then(|s| s.parse::<u16>().ok())
                .is_some_and(|s| (200..=299).contains(&s)),
        )
    })
    .await;
    result.ok().and_then(|r| r.ok()).unwrap_or(false)
}

#[derive(Debug, Error)]
pub enum HealthError {
    #[error("health worker failed: {0}")]
    Join(#[from] tokio::task::JoinError),
}

pub struct HealthSupervisor {
    cancel: watch::Sender<bool>,
    tasks: Vec<JoinHandle<()>>,
}
impl HealthSupervisor {
    pub async fn start(
        pools: Vec<Arc<PoolState>>,
        config: HealthConfig,
    ) -> Result<Self, HealthError> {
        let interval = Duration::from_secs(config.interval_seconds);
        let timeout = Duration::from_secs(config.timeout_seconds);
        Self::start_with_durations(pools, config, interval, timeout).await
    }
    pub async fn start_with_durations(
        pools: Vec<Arc<PoolState>>,
        config: HealthConfig,
        interval: Duration,
        timeout: Duration,
    ) -> Result<Self, HealthError> {
        let (cancel, _) = watch::channel(false);
        let mut tasks = Vec::new();
        for pool in pools {
            for id in pool.backend_ids() {
                let (kind, path) = pool.backend_health_check(id).expect("backend id from pool");
                let address = pool.backend_address(id).expect("backend id from pool");
                let mut rx = cancel.subscribe();
                let pool = Arc::clone(&pool);
                let mut tracker =
                    HealthTracker::new(config.healthy_threshold, config.unhealthy_threshold);
                tasks.push(tokio::spawn(async move {
                    loop {
                        let ok = match kind { HealthCheckKind::Tcp => probe_tcp(address, timeout).await, HealthCheckKind::Http => probe_http(address, path.as_deref().unwrap_or("/health"), timeout).await };
                        if let Some(transition) = tracker.record(ok) {
                            pool.set_healthy(id, transition == HealthTransition::BecameHealthy);
                            tracing::debug!(pool = pool.name(), backend = %address, ?transition, "backend health transition");
                        }
                        tokio::select! {
                            _ = time::sleep(interval) => {}
                            changed = rx.changed() => if changed.is_err() || *rx.borrow() { break; }
                        }
                    }
                }));
            }
        }
        Ok(Self { cancel, tasks })
    }
    pub async fn shutdown(self) -> Result<(), HealthError> {
        let _ = self.cancel.send(true);
        for task in self.tasks {
            task.await?;
        }
        Ok(())
    }
}
