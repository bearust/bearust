use axum::{
    body::{to_bytes, Body},
    http::Request,
};
use bearust::{
    analytics_prometheus::PrometheusConfig,
    config::PluginConfig,
    control_plane::{audit, build_state, realtime::RealtimeHub, router},
    plugin_runtime::{PluginAuditEvent, PluginAuditSink, PluginManager},
};
use std::{fs, sync::Arc};
use tempfile::tempdir;
use tower::util::ServiceExt;

#[derive(Default)]
struct AuditCapture(std::sync::Mutex<Vec<PluginAuditEvent>>);

impl PluginAuditSink for AuditCapture {
    fn record(&self, event: &PluginAuditEvent) {
        self.0.lock().unwrap().push(event.clone());
    }
}

fn write_plugin(root: &std::path::Path, status: i32) {
    let plugin = root.join("demo");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        r#"id = "demo-plugin"
display_name = "Demo"
abi_version = 1
module = "demo.wasm"
capabilities = ["health_check"]
[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1024
"#,
    )
    .unwrap();
    fs::write(
        plugin.join("demo.wasm"),
        wat::parse_str(format!(
            "(module (func (export \"bearust_abi_version\") (result i32) i32.const 1) (func (export \"bearust_health_check\") (result i32) i32.const {status}))"
        ))
        .unwrap(),
    )
    .unwrap();
}

fn manager(root: &std::path::Path, realtime: Arc<RealtimeHub>) -> Arc<PluginManager> {
    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.to_path_buf(),
        ..PluginConfig::default()
    });
    manager.attach_realtime(realtime);
    manager
}

#[test]
fn lifecycle_events_follow_atomic_publication_and_metrics_are_bounded() {
    let root = tempdir().unwrap();
    write_plugin(root.path(), 7);
    let realtime = Arc::new(RealtimeHub::new(16));
    let mut events = realtime.subscribe();
    let manager = manager(root.path(), realtime);

    manager.reload_from_disk().unwrap();
    assert_eq!(events.try_recv().unwrap().kind, "plugins.changed");
    assert_eq!(manager.list().len(), 1);

    manager.set_enabled("demo-plugin", false).unwrap();
    assert_eq!(events.try_recv().unwrap().kind, "plugins.changed");
    manager.unload("demo-plugin").unwrap();
    assert_eq!(events.try_recv().unwrap().kind, "plugins.changed");

    let metrics = manager.metrics().render_prometheus();
    assert!(metrics
        .contains("bearust_plugins_operations_total{operation=\"reload\",outcome=\"success\"} 1"));
    assert!(metrics
        .contains("bearust_plugins_operations_total{operation=\"disable\",outcome=\"success\"} 1"));
    assert!(metrics
        .contains("bearust_plugins_operations_total{operation=\"unload\",outcome=\"success\"} 1"));
    assert!(metrics.contains("bearust_plugins_loaded 0"));
    assert!(!metrics.contains("demo-plugin"));
}

#[test]
fn failed_reload_records_failure_without_success_event() {
    let root = tempdir().unwrap();
    write_plugin(root.path(), 1);
    let realtime = Arc::new(RealtimeHub::new(16));
    let mut events = realtime.subscribe();
    let manager = manager(root.path(), realtime);
    manager.reload_from_disk().unwrap();
    assert_eq!(events.try_recv().unwrap().kind, "plugins.changed");

    fs::write(root.path().join("demo/plugin.toml"), b"not valid toml").unwrap();
    assert!(manager.reload_from_disk().is_err());
    assert!(events.try_recv().is_err());
    let metrics = manager.metrics().render_prometheus();
    assert!(metrics
        .contains("bearust_plugins_operations_total{operation=\"reload\",outcome=\"failure\"} 1"));
}

#[test]
fn manager_audit_sink_receives_only_bounded_redacted_values() {
    let root = tempdir().unwrap();
    write_plugin(root.path(), 1);
    let realtime = Arc::new(RealtimeHub::new(16));
    let manager = manager(root.path(), realtime);
    let capture = Arc::new(AuditCapture::default());
    manager.attach_audit_sink(capture.clone());

    manager.reload_from_disk().unwrap();
    manager.health_check("demo-plugin").unwrap();
    let events = capture.0.lock().unwrap();
    assert_eq!(events[0].plugin_id(), "all");
    assert_eq!(events[0].operation(), "reload");
    assert_eq!(events[0].outcome(), "success");
    assert!(events.iter().all(|event| {
        !event.plugin_id().contains('/')
            && !event.plugin_id().contains("digest")
            && event.plugin_id().len() <= 64
    }));

    let unsafe_event = PluginAuditEvent::new(
        "/var/lib/bearust/plugins/demo-plugin?digest=secret",
        "read-file",
        "maybe",
        Some("/etc/bearust/private-module.wasm"),
    );
    assert_eq!(unsafe_event.plugin_id(), "unavailable");
    assert_eq!(unsafe_event.operation(), "unknown");
    assert_eq!(unsafe_event.outcome(), "failure");
    assert_eq!(unsafe_event.error_code(), None);
}

#[test]
fn partial_reload_publishes_redacted_invalidation_after_snapshot_commit() {
    let root = tempdir().unwrap();
    write_plugin(root.path(), 1);
    let bad = root.path().join("bad");
    fs::create_dir_all(&bad).unwrap();
    fs::write(bad.join("plugin.toml"), b"not valid toml").unwrap();
    let realtime = Arc::new(RealtimeHub::new(16));
    let mut events = realtime.subscribe();
    let manager = manager(root.path(), realtime);

    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.failed, 1);
    assert_eq!(events.try_recv().unwrap().kind, "plugins.changed");
    assert!(manager.list().iter().any(|status| status.loaded));
    assert!(manager
        .metrics()
        .render_prometheus()
        .contains("operation=\"reload\",outcome=\"failure\"} 1"));
}

#[tokio::test]
async fn audit_sse_and_prometheus_observability_are_redacted_and_bounded() {
    let dir = tempdir().unwrap();
    let mut state = build_state("sqlite::memory:", dir.path(), "setup-token")
        .await
        .unwrap();
    audit::record_plugin_state(
        &state,
        Some(7),
        "/var/lib/bearust/plugins/demo-plugin",
        "reload",
        "success",
        Some("/tmp/private-module.wasm#sha256=secret"),
    )
    .await;
    let details: String = sqlx::query_scalar(
        "SELECT details FROM audit_logs WHERE event='plugin_lifecycle' ORDER BY created_at DESC LIMIT 1",
    )
    .fetch_one(&state.db)
    .await
    .unwrap();
    assert!(!details.contains("/var/lib"));
    assert!(!details.contains("private-module"));
    assert!(!details.contains("sha256"));
    assert!(details.contains("unavailable"));
    assert!(details.contains("\"operation\":\"reload\""));

    let mut events = state.realtime.subscribe();
    state.realtime.publish("plugins.changed");
    let event = events.recv().await.unwrap();
    let payload = serde_json::to_string(&event).unwrap();
    assert!(payload.contains("plugins.changed"));
    assert!(!payload.contains("/var/lib"));
    assert!(!payload.contains("private-module"));
    assert!(!payload.contains("sha256"));

    state.prometheus = PrometheusConfig {
        enabled: true,
        require_auth: false,
        max_output_bytes: 8 * 1024,
        ..Default::default()
    };
    state
        .plugin_manager
        .metrics()
        .record_operation("reload", "success");
    state
        .plugin_manager
        .metrics()
        .record_operation("health_check", "failure");
    let response = router(state.clone())
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 16 * 1024).await.unwrap();
    let body = String::from_utf8(body.to_vec()).unwrap();
    assert!(body.len() <= 8 * 1024);
    assert!(body.contains("operation=\"reload\",outcome=\"success\""));
    assert!(body.contains("operation=\"health_check\",outcome=\"failure\""));
    assert!(!body.contains("demo-plugin"));

    state.prometheus.max_output_bytes = 128;
    let response = router(state)
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let body = to_bytes(response.into_body(), 1024).await.unwrap();
    assert!(body.len() <= 128);
}
