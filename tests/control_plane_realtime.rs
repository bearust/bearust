use bearust::control_plane::realtime::RealtimeHub;

#[tokio::test]
async fn hub_assigns_monotonic_ids_and_drops_slow_subscribers_without_blocking() {
    let hub = RealtimeHub::new(1);
    let mut receiver = hub.subscribe();
    hub.publish("users.changed");
    let first = receiver.recv().await.unwrap();
    assert_eq!(first.id, 1);
    hub.publish("roles.changed");
    hub.publish("certificates.changed");
    assert!(matches!(
        receiver.recv().await,
        Err(tokio::sync::broadcast::error::RecvError::Lagged(1))
    ));
}
