mod support;
use bearust::health::{probe_http, probe_tcp, HealthState, HealthTracker, HealthTransition};
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
async fn refused_port_fails() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    assert!(!probe_tcp(address, Duration::from_millis(100)).await);
}
