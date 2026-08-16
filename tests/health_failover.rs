mod support;
use bearust::health::{probe_http, probe_tcp, HealthState, HealthTracker, HealthTransition};
use bearust::{
    balancer::PoolState,
    config::{Algorithm, BackendConfig, HealthCheckKind, HealthConfig, PoolConfig},
};
use std::{
    sync::{
        atomic::{AtomicU16, Ordering},
        Arc,
    },
    time::Duration,
};

#[test]
fn new_backend_requires_success_threshold() {
    let mut tracker = HealthTracker::new(2, 3);
    assert_eq!(tracker.state(), HealthState::Probing);
    assert_eq!(tracker.record(true), None);
    assert_eq!(tracker.record(true), Some(HealthTransition::BecameHealthy));
}

#[test]
fn healthy_backend_requires_consecutive_failures() {
    let mut tracker = HealthTracker::new(1, 3);
    tracker.record(true);
    assert_eq!(tracker.record(false), None);
    assert_eq!(tracker.record(true), None);
    assert_eq!(tracker.record(false), None);
    assert_eq!(tracker.record(false), None);
    assert_eq!(
        tracker.record(false),
        Some(HealthTransition::BecameUnhealthy)
    );
}

#[test]
fn health_thresholds_do_not_wrap_when_larger_than_u32() {
    let mut tracker = HealthTracker::new(u64::MAX, u64::MAX);
    for _ in 0..3 {
        assert_eq!(tracker.record(true), None);
    }
    assert_eq!(tracker.state(), HealthState::Probing);
}

#[tokio::test]
async fn tcp_and_http_probes_follow_status() {
    let status = Arc::new(AtomicU16::new(204));
    let server = support::spawn_http_backend(Arc::clone(&status), "ok").await;
    assert!(probe_tcp(server.address, Duration::from_secs(1)).await);
    assert!(probe_http(server.address, "/health", Duration::from_secs(1)).await);
    status.store(503, Ordering::Relaxed);
    assert!(!probe_http(server.address, "/health", Duration::from_secs(1)).await);
    server.shutdown().await;
}

#[tokio::test]
async fn http_probe_rejects_header_injection_path() {
    let address = "127.0.0.1:1".parse().unwrap();
    assert!(
        !probe_http(
            address,
            "/health\\r\\nX-Injected: yes",
            Duration::from_millis(25)
        )
        .await
    );
}

#[tokio::test]
async fn refused_port_fails() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    assert!(!probe_tcp(address, Duration::from_millis(100)).await);
}

#[tokio::test]
async fn http_probe_times_out_when_backend_does_not_respond() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        tokio::time::sleep(Duration::from_secs(1)).await;
    });
    assert!(!probe_http(address, "/health", Duration::from_millis(25)).await);
    task.abort();
}

#[tokio::test]
async fn supervisor_transitions_backend_eligibility_within_one_second() {
    tokio::time::timeout(Duration::from_secs(1), async {
        let status = Arc::new(AtomicU16::new(503));
        let server = support::spawn_http_backend(Arc::clone(&status), "upstream").await;
        let config = PoolConfig {
            name: "e2e".into(),
            algorithm: Algorithm::RoundRobin,
            connect_timeout_seconds: 1,
            request_timeout_seconds: 1,
            passive_health: false,
            backends: vec![BackendConfig {
                address: server.address,
                health_check: HealthCheckKind::Http,
                health_path: Some("/health".into()),
                weight: 1,
            }],
        };
        let pool = Arc::new(PoolState::new(&config));
        let health = HealthConfig {
            interval_seconds: 1,
            timeout_seconds: 1,
            unhealthy_threshold: 1,
            healthy_threshold: 1,
        };
        let supervisor = bearust::health::HealthSupervisor::start_with_durations(
            vec![Arc::clone(&pool)],
            health,
            Duration::from_millis(10),
            Duration::from_millis(20),
        )
        .await
        .unwrap();
        tokio::time::sleep(Duration::from_millis(30)).await;
        assert!(pool.select(None).is_none());
        status.store(204, Ordering::Relaxed);
        for _ in 0..50 {
            if pool.select(None).is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let lease = pool.select(None);
        assert!(lease.is_some(), "healthy backend should become selectable");
        drop(lease);
        status.store(503, Ordering::Relaxed);
        for _ in 0..50 {
            if pool.select(None).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(
            pool.select(None).is_none(),
            "failed backend should leave rotation"
        );
        supervisor.shutdown().await.unwrap();
        server.shutdown().await;
    })
    .await
    .unwrap();
}
