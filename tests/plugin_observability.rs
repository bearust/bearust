use bearust::{
    config::PluginConfig, control_plane::realtime::RealtimeHub, plugin_runtime::PluginManager,
};
use std::{fs, sync::Arc};
use tempfile::tempdir;

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
