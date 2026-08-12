use bearust::config::PluginConfig;
use bearust::plugin_runtime::{
    module_digest, resolve_module_path, CompiledPlugin, HealthResult, PluginEngine, PluginError,
    PluginLimits, PluginManager, PluginManifest, PluginPolicy, ValidatedManifest,
};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;
use tempfile::tempdir;

fn manifest(extra: &str) -> String {
    format!(
        r#"id = "demo-plugin"
display_name = "Demo"
abi_version = 1
module = "demo.wasm"
capabilities = ["health_check"]
[limits]
memory_pages = 4
fuel = 1000
invocation_timeout_ms = 100
max_output_bytes = 1024
{extra}
"#
    )
}

#[test]
fn valid_manifest() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let m = PluginManifest::from_toml(manifest("").as_bytes()).unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    assert_eq!(m.validate(&p).unwrap().id, "demo-plugin");
}

#[test]
fn checked_in_health_fixture_is_deterministic_and_loadable() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("health-ok");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/health_ok/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!("fixtures/plugins/health_ok/health_ok.wat")).unwrap();
    fs::write(plugin.join("health_ok.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);
    assert_eq!(manager.health_check("health-ok").unwrap().status, 1);
    assert_eq!(manager.list()[0].digest, module_digest(&module));
}

#[test]
fn v2_health_fixture_round_trips_json_over_guest_memory() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("health-ok-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/health_ok_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/health_ok_v2/health_ok_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("health_ok_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);
    let result = manager.health_check("health-ok-v2").unwrap();
    assert_eq!(result.status, 1);
    assert_eq!(result.detail.as_deref(), Some("wat-v2"));
}

#[test]
fn notify_sink_fixture_round_trips_json_and_reports_success() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("notify-sink-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/notify_sink_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/notify_sink_v2/notify_sink_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("notify_sink_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);

    let sink = manager
        .waf_block_sink_plugin()
        .expect("notify-sink-v2 declares notify.waf_block and is enabled");
    let event = bearust_plugin_sdk::WafBlockEvent {
        request_id: "req-1".into(),
        occurred_at_ms: 1_700_000_000_000,
        category: "sqli".into(),
        score: 42,
        severity: "high".into(),
        reason_ids: "sqli".into(),
    };
    assert_eq!(sink.notify_waf_block(&event).unwrap(), 0);
}

#[test]
fn waf_block_sink_plugin_is_none_when_no_plugin_declares_the_capability() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("health-ok-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/health_ok_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/health_ok_v2/health_ok_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("health_ok_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    assert!(manager.waf_block_sink_plugin().is_none());
}

#[test]
fn waf_block_sink_plugin_is_none_when_disabled() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("notify-sink-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/notify_sink_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/notify_sink_v2/notify_sink_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("notify_sink_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager.set_enabled("notify-sink-v2", false).unwrap();
    assert!(manager.waf_block_sink_plugin().is_none());
}

#[test]
fn unknown_fields_rejected() {
    assert!(PluginManifest::from_toml(manifest("extra = true").as_bytes()).is_err());
}

#[test]
fn invalid_ids_rejected() {
    for id in ["Demo", "", "-demo", "demo-", "demo--plugin"] {
        let text = manifest("").replace("demo-plugin", id);
        let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
        assert!(m.validate(&PluginPolicy::default()).is_err());
    }
}

#[test]
fn capabilities_and_abi_rejected() {
    let dup = manifest("").replace("[\"health_check\"]", "[\"health_check\", \"health_check\"]");
    assert!(PluginManifest::from_toml(dup.as_bytes())
        .unwrap()
        .validate(&PluginPolicy::default())
        .is_err());
    let unknown = manifest("").replace("[\"health_check\"]", "[\"network\"]");
    assert!(PluginManifest::from_toml(unknown.as_bytes())
        .unwrap()
        .validate(&PluginPolicy::default())
        .is_err());
    let abi = manifest("").replace("abi_version = 1", "abi_version = 99");
    assert_eq!(
        PluginManifest::from_toml(abi.as_bytes())
            .unwrap()
            .validate(&PluginPolicy::default())
            .unwrap_err()
            .code(),
        "abi_mismatch"
    );
}

#[test]
fn abi_version_two_is_accepted_at_manifest_validation() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let text = manifest("").replace("abi_version = 1", "abi_version = 2");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    assert_eq!(m.validate(&p).unwrap().abi_version, 2);
}

#[test]
fn abi_version_two_rejects_output_limit_below_the_v2_input_floor() {
    // A v2 plugin's health check also writes its *input* JSON (up to 40
    // bytes) through the max_output_bytes bound, so anything under the
    // 64-byte v2 floor must be rejected at validate() time rather than
    // failing every invocation with an opaque MemoryLimit.
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("max_output_bytes = 1024", "max_output_bytes = 16");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap_err(), PluginError::InvalidManifest);

    // Exactly at the floor is accepted.
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("max_output_bytes = 1024", "max_output_bytes = 64");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap().abi_version, 2);
}

#[test]
fn abi_version_one_output_floor_is_unaffected_by_the_v2_floor() {
    // v1 keeps the original four-byte (i32 status) floor: a 16-byte cap is
    // still valid for v1 even though it is rejected for v2 above.
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let text = manifest("").replace("max_output_bytes = 1024", "max_output_bytes = 16");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap().abi_version, 1);

    // ...but below the i32 floor it is still rejected.
    let text = manifest("").replace("max_output_bytes = 1024", "max_output_bytes = 3");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap_err(), PluginError::InvalidManifest);
}

#[test]
fn notify_capability_requires_abi_version_two() {
    let text = manifest("").replace("[\"health_check\"]", "[\"notify.waf_block\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(
        m.validate(&PluginPolicy::default()).unwrap_err(),
        PluginError::InvalidManifest
    );
}

#[test]
fn notify_capability_is_accepted_with_abi_version_two() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"notify.waf_block\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let validated = m.validate(&p).unwrap();
    assert_eq!(validated.capabilities, vec!["notify.waf_block".to_string()]);
}

#[test]
fn notify_capability_rejects_output_limit_below_the_notify_input_floor() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"notify.waf_block\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 100");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap_err(), PluginError::InvalidManifest);

    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"notify.waf_block\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap().abi_version, 2);
}

#[test]
fn waf_detect_capability_requires_abi_version_two() {
    let text = manifest("").replace("[\"health_check\"]", "[\"waf.detect\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(
        m.validate(&PluginPolicy::default()).unwrap_err(),
        PluginError::InvalidManifest
    );
}

#[test]
fn waf_detect_capability_is_accepted_with_abi_version_two() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"waf.detect\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 49152");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let validated = m.validate(&p).unwrap();
    assert_eq!(validated.capabilities, vec!["waf.detect".to_string()]);
}

#[test]
fn waf_detect_capability_rejects_output_limit_below_the_waf_detect_input_floor() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"waf.detect\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 4096");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap_err(), PluginError::InvalidManifest);

    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"waf.detect\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 49152");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap().abi_version, 2);
}

#[test]
fn transform_capability_requires_abi_version_two() {
    let text = manifest("").replace("[\"health_check\"]", "[\"transform.request\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(
        m.validate(&PluginPolicy::default()).unwrap_err(),
        PluginError::InvalidManifest
    );
}

#[test]
fn transform_capability_is_accepted_with_abi_version_two() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"transform.request\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 32768");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let validated = m.validate(&p).unwrap();
    assert_eq!(
        validated.capabilities,
        vec!["transform.request".to_string()]
    );
}

#[test]
fn transform_capability_rejects_output_limit_below_the_transform_input_floor() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"transform.request\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 4096");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap_err(), PluginError::InvalidManifest);

    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"transform.request\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 32768");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap().abi_version, 2);
}

#[test]
fn transform_response_capability_requires_abi_version_two() {
    let text = manifest("").replace("[\"health_check\"]", "[\"transform.response\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(
        m.validate(&PluginPolicy::default()).unwrap_err(),
        PluginError::InvalidManifest
    );
}

#[test]
fn transform_response_capability_is_accepted_with_abi_version_two() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"transform.response\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 1572864");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        max_output_bytes: 2 * 1024 * 1024,
        ..Default::default()
    };
    let validated = m.validate(&p).unwrap();
    assert_eq!(
        validated.capabilities,
        vec!["transform.response".to_string()]
    );
}

#[test]
fn transform_response_capability_rejects_output_limit_below_the_transform_response_input_floor() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        max_output_bytes: 2 * 1024 * 1024,
        ..Default::default()
    };
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"transform.response\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 1048576");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap_err(), PluginError::InvalidManifest);

    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"transform.response\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 1572864");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap().abi_version, 2);
}

#[test]
fn balance_select_capability_requires_abi_version_two() {
    let text = manifest("").replace("[\"health_check\"]", "[\"balance.select\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(
        m.validate(&PluginPolicy::default()).unwrap_err(),
        PluginError::InvalidManifest
    );
}

#[test]
fn balance_select_capability_is_accepted_with_abi_version_two() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"balance.select\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 49152");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let validated = m.validate(&p).unwrap();
    assert_eq!(validated.capabilities, vec!["balance.select".to_string()]);
}

#[test]
fn balance_select_capability_rejects_output_limit_below_the_balance_input_floor() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"balance.select\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 4096");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap_err(), PluginError::InvalidManifest);

    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"balance.select\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 49152");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap().abi_version, 2);
}

#[test]
fn v2_missing_balance_select_export_is_abi_mismatch() {
    // Exports the mandatory v2 baseline (memory, alloc, dealloc,
    // bearust_health_check_v2) but not bearust_balance_select, even
    // though the manifest declares the balance.select capability.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(
        compile_error_v2_with_capabilities(wat, vec!["balance.select".into()]),
        PluginError::AbiMismatch
    );
}

#[test]
fn v2_out_of_bounds_alloc_pointer_is_trap_on_the_balance_select_input_write() {
    // Hostile guest: bearust_alloc hands back a pointer far past the end of
    // the guest's single 65536-byte page. The host must reject it while
    // bounds-checking the *input* write, before bearust_balance_select is
    // even called. Mirrors the equivalent transform.response-path test.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1000000)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_balance_select") (param i32 i32) (result i64)
            unreachable))"#;
    let plugin = compile_v2_with_capabilities(wat, vec!["balance.select".into()]).unwrap();
    let request = bearust_plugin_sdk::LoadBalanceRequest {
        pool: "api".into(),
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
        backends: Vec::new(),
        excluded_backend_id: None,
    };
    assert_eq!(
        plugin.balance_select(&request).unwrap_err(),
        PluginError::Trap
    );
}

#[test]
fn v2_malformed_balance_select_output_is_trap() {
    // A guest that returns a packed pointer/length pointing at bytes that
    // are not valid LoadBalanceResult JSON.
    let wat = r#"(module
        (memory (export "memory") 1)
        (data (i32.const 0) "not json")
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1024)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_balance_select") (param i32 i32) (result i64)
            i64.const 8))"#; // pack(0, 8): (0i64 << 32) | 8
    let plugin = compile_v2_with_capabilities(wat, vec!["balance.select".into()]).unwrap();
    let request = bearust_plugin_sdk::LoadBalanceRequest {
        pool: "api".into(),
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
        backends: Vec::new(),
        excluded_backend_id: None,
    };
    assert_eq!(
        plugin.balance_select(&request).unwrap_err(),
        PluginError::Trap
    );
}

#[test]
fn path_containment_and_missing_module() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("ok.wasm"), b"x").unwrap();
    fs::create_dir(dir.path().join("folder")).unwrap();
    assert!(resolve_module_path(dir.path(), "../ok.wasm").is_err());
    assert!(resolve_module_path(dir.path(), "/tmp/ok.wasm").is_err());
    assert!(resolve_module_path(dir.path(), "missing.wasm").is_err());
    assert!(resolve_module_path(dir.path(), "folder").is_err());
}

#[cfg(unix)]
#[test]
fn symlink_escape_rejected() {
    let dir = tempdir().unwrap();
    let outside = tempdir().unwrap();
    fs::write(outside.path().join("x.wasm"), b"x").unwrap();
    std::os::unix::fs::symlink(outside.path().join("x.wasm"), dir.path().join("x.wasm")).unwrap();
    assert!(resolve_module_path(dir.path(), "x.wasm").is_err());
}

#[test]
fn oversized_limits_rejected() {
    let text = manifest("").replace("memory_pages = 4", "memory_pages = 999999");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert!(m.validate(&PluginPolicy::default()).is_err());
}

#[test]
fn digest_is_stable_lowercase_sha256() {
    let a = module_digest(b"module");
    assert_eq!(a, module_digest(b"module"));
    assert_eq!(a.len(), 64);
    assert!(a
        .bytes()
        .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
}

#[test]
fn errors_are_safe_codes() {
    assert_eq!(PluginError::InvalidManifest.code(), "invalid_manifest");
    assert_eq!(PluginError::InvalidManifest.to_string(), "invalid_manifest");
}

fn validated(limits: PluginLimits) -> ValidatedManifest {
    ValidatedManifest {
        id: "demo-plugin".into(),
        display_name: "Demo".into(),
        abi_version: 1,
        module: PathBuf::from("demo.wasm"),
        capabilities: vec!["health_check".into()],
        limits,
    }
}

fn limits() -> PluginLimits {
    PluginLimits {
        memory_pages: 1,
        fuel: 10_000,
        invocation_timeout_ms: 100,
        max_output_bytes: 1024,
    }
}

fn compile(wat: &str, limits: PluginLimits) -> Result<CompiledPlugin, PluginError> {
    compile_bytes(&wat::parse_str(wat).unwrap(), limits)
}

fn compile_bytes(bytes: &[u8], limits: PluginLimits) -> Result<CompiledPlugin, PluginError> {
    let engine = PluginEngine::new(PluginPolicy::default())?;
    engine.compile(validated(limits), bytes)
}

fn compile_error(wat: &str) -> PluginError {
    match compile(wat, limits()) {
        Ok(_) => panic!("module unexpectedly compiled"),
        Err(error) => error,
    }
}

fn compile_v2(wat: &str, limits: PluginLimits) -> Result<CompiledPlugin, PluginError> {
    compile_bytes_v2(&wat::parse_str(wat).unwrap(), limits)
}

fn compile_bytes_v2(bytes: &[u8], limits: PluginLimits) -> Result<CompiledPlugin, PluginError> {
    let engine = PluginEngine::new(PluginPolicy::default())?;
    engine.compile(validated_v2(limits), bytes)
}

fn validated_v2(limits: PluginLimits) -> ValidatedManifest {
    ValidatedManifest {
        abi_version: 2,
        ..validated(limits)
    }
}

fn compile_error_v2(wat: &str) -> PluginError {
    match compile_v2(wat, limits()) {
        Ok(_) => panic!("module unexpectedly compiled"),
        Err(error) => error,
    }
}

fn validated_v2_with_capabilities(
    limits: PluginLimits,
    capabilities: Vec<String>,
) -> ValidatedManifest {
    ValidatedManifest {
        capabilities,
        ..validated_v2(limits)
    }
}

fn compile_error_v2_with_capabilities(wat: &str, capabilities: Vec<String>) -> PluginError {
    let engine = PluginEngine::new(PluginPolicy::default()).unwrap();
    let bytes = wat::parse_str(wat).unwrap();
    match engine.compile(
        validated_v2_with_capabilities(limits(), capabilities),
        &bytes,
    ) {
        Ok(_) => panic!("module unexpectedly compiled"),
        Err(error) => error,
    }
}

fn compile_v2_with_capabilities(
    wat: &str,
    capabilities: Vec<String>,
) -> Result<CompiledPlugin, PluginError> {
    let engine = PluginEngine::new(PluginPolicy::default())?;
    let bytes = wat::parse_str(wat).unwrap();
    engine.compile(
        validated_v2_with_capabilities(limits(), capabilities),
        &bytes,
    )
}

#[test]
fn v2_missing_alloc_export_is_abi_mismatch() {
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(compile_error_v2(wat), PluginError::AbiMismatch);
}

#[test]
fn v2_missing_health_check_v2_export_is_abi_mismatch() {
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32)))"#;
    assert_eq!(compile_error_v2(wat), PluginError::AbiMismatch);
}

#[test]
fn v2_missing_memory_export_is_abi_mismatch() {
    let wat = r#"(module
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(compile_error_v2(wat), PluginError::AbiMismatch);
}

#[test]
fn v2_wrong_signature_export_is_abi_mismatch() {
    // bearust_alloc declared with the wrong result type (i64 instead of i32).
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i64) i64.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(compile_error_v2(wat), PluginError::AbiMismatch);
}

#[test]
fn v2_missing_notify_export_is_abi_mismatch() {
    // Exports the mandatory v2 baseline (memory, alloc, dealloc,
    // bearust_health_check_v2) but not bearust_notify_waf_block, even
    // though the manifest declares the notify.waf_block capability.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(
        compile_error_v2_with_capabilities(wat, vec!["notify.waf_block".into()]),
        PluginError::AbiMismatch
    );
}

#[test]
fn v2_missing_waf_detect_export_is_abi_mismatch() {
    // Exports the mandatory v2 baseline (memory, alloc, dealloc,
    // bearust_health_check_v2) but not bearust_waf_detect, even though the
    // manifest declares the waf.detect capability.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(
        compile_error_v2_with_capabilities(wat, vec!["waf.detect".into()]),
        PluginError::AbiMismatch
    );
}

#[test]
fn v2_missing_transform_export_is_abi_mismatch() {
    // Exports the mandatory v2 baseline (memory, alloc, dealloc,
    // bearust_health_check_v2) but not bearust_transform_request, even
    // though the manifest declares the transform.request capability.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(
        compile_error_v2_with_capabilities(wat, vec!["transform.request".into()]),
        PluginError::AbiMismatch
    );
}

#[test]
fn v2_missing_transform_response_export_is_abi_mismatch() {
    // Exports the mandatory v2 baseline (memory, alloc, dealloc,
    // bearust_health_check_v2) but not bearust_transform_response, even
    // though the manifest declares the transform.response capability.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(
        compile_error_v2_with_capabilities(wat, vec!["transform.response".into()]),
        PluginError::AbiMismatch
    );
}

#[test]
fn v2_out_of_bounds_alloc_pointer_is_trap_on_the_notify_input_write() {
    // Hostile guest: bearust_alloc hands back a pointer far past the end of
    // the guest's single 65536-byte page. The host must reject it while
    // bounds-checking the *input* write, before bearust_notify_waf_block is
    // even called. Mirrors
    // v2_out_of_bounds_alloc_pointer_is_trap_on_the_input_write for the
    // health-check path.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1000000)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_notify_waf_block") (param i32 i32) (result i32)
            unreachable))"#;
    let plugin = compile_v2_with_capabilities(wat, vec!["notify.waf_block".into()]).unwrap();
    let event = bearust_plugin_sdk::WafBlockEvent {
        request_id: "req-1".into(),
        occurred_at_ms: 1_700_000_000_000,
        category: "sqli".into(),
        score: 42,
        severity: "high".into(),
        reason_ids: "sqli".into(),
    };
    assert_eq!(
        plugin.notify_waf_block(&event).unwrap_err(),
        PluginError::Trap
    );
}

#[test]
fn v2_out_of_bounds_alloc_pointer_is_trap_on_the_detect_input_write() {
    // Hostile guest: bearust_alloc hands back a pointer far past the end of
    // the guest's single 65536-byte page. The host must reject it while
    // bounds-checking the *input* write, before bearust_waf_detect is even
    // called. Mirrors the equivalent notify-path test.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1000000)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_waf_detect") (param i32 i32) (result i64)
            unreachable))"#;
    let plugin = compile_v2_with_capabilities(wat, vec!["waf.detect".into()]).unwrap();
    let request = bearust_plugin_sdk::WafDetectRequest {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    assert_eq!(plugin.detect(&request).unwrap_err(), PluginError::Trap);
}

#[test]
fn v2_out_of_bounds_alloc_pointer_is_trap_on_the_transform_input_write() {
    // Hostile guest: bearust_alloc hands back a pointer far past the end of
    // the guest's single 65536-byte page. The host must reject it while
    // bounds-checking the *input* write, before bearust_transform_request is
    // even called. Mirrors the equivalent detect-path test.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1000000)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_transform_request") (param i32 i32) (result i64)
            unreachable))"#;
    let plugin = compile_v2_with_capabilities(wat, vec!["transform.request".into()]).unwrap();
    let request = bearust_plugin_sdk::TransformRequest {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
    };
    assert_eq!(plugin.transform(&request).unwrap_err(), PluginError::Trap);
}

#[test]
fn v2_out_of_bounds_alloc_pointer_is_trap_on_the_transform_response_input_write() {
    // Hostile guest: bearust_alloc hands back a pointer far past the end of
    // the guest's single 65536-byte page. The host must reject it while
    // bounds-checking the *input* write, before bearust_transform_response
    // is even called. Mirrors the equivalent transform.request-path test.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1000000)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_transform_response") (param i32 i32) (result i64)
            unreachable))"#;
    let plugin = compile_v2_with_capabilities(wat, vec!["transform.response".into()]).unwrap();
    let request = bearust_plugin_sdk::TransformResponseRequest {
        status: 200,
        body: String::new(),
    };
    assert_eq!(
        plugin.transform_response(&request).unwrap_err(),
        PluginError::Trap
    );
}

#[test]
fn v2_malformed_transform_output_is_trap() {
    // A guest that returns a packed pointer/length pointing at bytes that
    // are not valid TransformResponse JSON.
    let wat = r#"(module
        (memory (export "memory") 1)
        (data (i32.const 0) "not json")
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1024)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_transform_request") (param i32 i32) (result i64)
            i64.const 8))"#; // pack(0, 8): (0i64 << 32) | 8
    let plugin = compile_v2_with_capabilities(wat, vec!["transform.request".into()]).unwrap();
    let request = bearust_plugin_sdk::TransformRequest {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
    };
    assert_eq!(plugin.transform(&request).unwrap_err(), PluginError::Trap);
}

#[test]
fn v2_malformed_transform_response_output_is_trap() {
    // A guest that returns a packed pointer/length pointing at bytes that
    // are not valid TransformResponseResult JSON.
    let wat = r#"(module
        (memory (export "memory") 1)
        (data (i32.const 0) "not json")
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1024)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_transform_response") (param i32 i32) (result i64)
            i64.const 8))"#; // pack(0, 8): (0i64 << 32) | 8
    let plugin = compile_v2_with_capabilities(wat, vec!["transform.response".into()]).unwrap();
    let request = bearust_plugin_sdk::TransformResponseRequest {
        status: 200,
        body: String::new(),
    };
    assert_eq!(
        plugin.transform_response(&request).unwrap_err(),
        PluginError::Trap
    );
}

#[test]
fn v2_malformed_detect_output_is_trap() {
    // A guest that returns a packed pointer/length pointing at bytes that
    // are not valid WafDetectVerdict JSON.
    let wat = r#"(module
        (memory (export "memory") 1)
        (data (i32.const 0) "not json")
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1024)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_waf_detect") (param i32 i32) (result i64)
            i64.const 8))"#; // pack(0, 8): (0i64 << 32) | 8
    let plugin = compile_v2_with_capabilities(wat, vec!["waf.detect".into()]).unwrap();
    let request = bearust_plugin_sdk::WafDetectRequest {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    assert_eq!(plugin.detect(&request).unwrap_err(), PluginError::Trap);
}

#[test]
fn manager_lifecycle_publishes_atomic_status() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("demo");
    fs::create_dir(&plugin).unwrap();
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
        wat::parse_str(
            r#"(module
                (func (export "bearust_abi_version") (result i32) i32.const 1)
                (func (export "bearust_health_check") (result i32) i32.const 7))"#,
        )
        .unwrap(),
    )
    .unwrap();
    let config = PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    };
    let manager = PluginManager::new(config);
    assert_eq!(manager.reload_from_disk().unwrap().loaded, 1);
    assert_eq!(manager.list().len(), 1);
    assert_eq!(manager.health_check("demo-plugin").unwrap().status, 7);
    assert!(!manager.set_enabled("demo-plugin", false).unwrap().enabled);
    assert_eq!(
        manager.health_check("demo-plugin").unwrap_err(),
        PluginError::Disabled
    );
    assert!(manager.set_enabled("demo-plugin", true).unwrap().enabled);
    manager.unload("demo-plugin").unwrap();
    assert!(manager.list().is_empty());
}

#[test]
fn manager_missing_directory_is_fail_open() {
    let config = PluginConfig {
        enabled: true,
        directory: PathBuf::from("/definitely/missing/bearust-plugins"),
        ..PluginConfig::default()
    };
    let manager = PluginManager::new(config);
    assert_eq!(manager.reload_from_disk().unwrap().loaded, 0);
    assert!(manager.list().is_empty());
}

fn lifecycle_config(root: &std::path::Path) -> PluginConfig {
    PluginConfig {
        enabled: true,
        directory: root.to_path_buf(),
        ..PluginConfig::default()
    }
}

fn write_lifecycle_plugin(root: &std::path::Path, dir: &str, id: &str, wasm: &[u8]) {
    let plugin = root.join(dir);
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        format!(
            "id = \"{id}\"\ndisplay_name = \"Demo\"\nabi_version = 1\nmodule = \"demo.wasm\"\ncapabilities = [\"health_check\"]\n[limits]\nmemory_pages = 1\nfuel = 10000\ninvocation_timeout_ms = 100\nmax_output_bytes = 1024\n"
        ),
    )
    .unwrap();
    fs::write(plugin.join("demo.wasm"), wasm).unwrap();
}

fn lifecycle_wasm(status: i32) -> Vec<u8> {
    wat::parse_str(format!(
        "(module (func (export \"bearust_abi_version\") (result i32) i32.const 1) (func (export \"bearust_health_check\") (result i32) i32.const {status}))"
    ))
    .unwrap()
}

#[test]
fn manager_isolates_invalid_plugin_from_healthy_sibling() {
    let root = tempdir().unwrap();
    write_lifecycle_plugin(root.path(), "good", "good-plugin", &lifecycle_wasm(1));
    write_lifecycle_plugin(root.path(), "bad", "bad-plugin", b"not wasm");
    let manager = PluginManager::new(lifecycle_config(root.path()));
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);
    assert_eq!(summary.failed, 1);
    assert_eq!(manager.health_check("good-plugin").unwrap().status, 1);
    assert!(
        !manager
            .list()
            .iter()
            .find(|status| status.id == "bad-plugin")
            .unwrap()
            .loaded
    );
}

#[test]
fn manager_rejects_duplicate_ids_and_max_bound_transactionally() {
    let root = tempdir().unwrap();
    let wasm = lifecycle_wasm(2);
    write_lifecycle_plugin(root.path(), "one", "same-plugin", &wasm);
    write_lifecycle_plugin(root.path(), "two", "same-plugin", &wasm);
    let manager = PluginManager::new(lifecycle_config(root.path()));
    assert_eq!(
        manager.reload_from_disk().unwrap_err(),
        PluginError::DuplicateId
    );
    assert!(manager.list().is_empty());

    let root = tempdir().unwrap();
    write_lifecycle_plugin(root.path(), "one", "one-plugin", &wasm);
    write_lifecycle_plugin(root.path(), "two", "two-plugin", &wasm);
    let manager = PluginManager::new(PluginConfig {
        max_plugins: 1,
        ..lifecycle_config(root.path())
    });
    assert_eq!(
        manager.reload_from_disk().unwrap_err(),
        PluginError::MaxPlugins
    );
    assert!(manager.list().is_empty());
}

#[test]
fn failed_reload_retains_previous_snapshot() {
    let root = tempdir().unwrap();
    write_lifecycle_plugin(root.path(), "good", "good-plugin", &lifecycle_wasm(3));
    let manager = PluginManager::new(lifecycle_config(root.path()));
    manager.reload_from_disk().unwrap();
    fs::write(root.path().join("good/plugin.toml"), b"not valid toml").unwrap();
    assert_eq!(
        manager.reload_from_disk().unwrap_err(),
        PluginError::CompileFailed
    );
    assert_eq!(manager.health_check("good-plugin").unwrap().status, 3);
    write_lifecycle_plugin(root.path(), "good", "good-plugin", &lifecycle_wasm(3));
    write_lifecycle_plugin(root.path(), "duplicate", "good-plugin", &lifecycle_wasm(9));
    assert_eq!(
        manager.reload_from_disk().unwrap_err(),
        PluginError::DuplicateId
    );
    assert_eq!(manager.health_check("good-plugin").unwrap().status, 3);
}

#[test]
fn concurrent_health_reads_remain_bounded_during_reload() {
    let root = tempdir().unwrap();
    write_lifecycle_plugin(root.path(), "good", "good-plugin", &lifecycle_wasm(4));
    let manager = PluginManager::new(lifecycle_config(root.path()));
    manager.reload_from_disk().unwrap();
    let captured_old_result = manager.health_check("good-plugin").unwrap();
    assert_eq!(captured_old_result.status, 4);
    write_lifecycle_plugin(root.path(), "good", "good-plugin", &lifecycle_wasm(8));
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(5));
    let mut workers = Vec::new();
    for _ in 0..4 {
        let manager = std::sync::Arc::clone(&manager);
        let barrier = std::sync::Arc::clone(&barrier);
        workers.push(std::thread::spawn(move || {
            barrier.wait();
            for _ in 0..20 {
                let result = manager.health_check("good-plugin");
                if let Ok(result) = result {
                    assert!(matches!(result.status, 4 | 8));
                }
            }
        }));
    }
    barrier.wait();
    for _ in 0..3 {
        manager.reload_from_disk().unwrap();
    }
    for worker in workers {
        worker.join().unwrap();
    }
    assert_eq!(manager.health_check("good-plugin").unwrap().status, 8);
    assert_eq!(captured_old_result.status, 4);
}

#[test]
fn manager_preserves_last_error_across_enable_toggle() {
    let root = tempdir().unwrap();
    let trap = wat::parse_str(
        r#"(module
            (func (export "bearust_abi_version") (result i32) i32.const 1)
            (func (export "bearust_health_check") (result i32) unreachable))"#,
    )
    .unwrap();
    write_lifecycle_plugin(root.path(), "trap", "trap-plugin", &trap);
    let manager = PluginManager::new(lifecycle_config(root.path()));
    manager.reload_from_disk().unwrap();
    assert_eq!(
        manager.health_check("trap-plugin").unwrap_err(),
        PluginError::Trap
    );
    assert_eq!(manager.list()[0].last_error_code.as_deref(), Some("trap"));
    assert_eq!(
        manager
            .set_enabled("trap-plugin", false)
            .unwrap()
            .last_error_code
            .as_deref(),
        Some("trap")
    );
    assert_eq!(
        manager
            .set_enabled("trap-plugin", true)
            .unwrap()
            .last_error_code
            .as_deref(),
        Some("trap")
    );
    write_lifecycle_plugin(root.path(), "trap", "trap-plugin", &lifecycle_wasm(6));
    manager.reload_from_disk().unwrap();
    assert!(manager.list()[0].last_error_code.is_none());
    assert_eq!(manager.health_check("trap-plugin").unwrap().status, 6);
}

#[test]
fn engine_accepts_v1_and_bounded_status() {
    let plugin = compile(
        r#"(module
            (func (export "bearust_abi_version") (result i32) i32.const 1)
            (func (export "bearust_health_check") (result i32) i32.const 7))"#,
        limits(),
    )
    .unwrap();
    let result: HealthResult = plugin.health_check().unwrap();
    assert_eq!(result.status, 7);
    assert!(result.elapsed < Duration::from_secs(1));
}

#[test]
fn engine_allows_optional_health_export() {
    let plugin = compile(
        r#"(module (func (export "bearust_abi_version") (result i32) i32.const 1))"#,
        limits(),
    )
    .unwrap();
    assert_eq!(plugin.health_check().unwrap().status, 0);
}

#[test]
fn engine_rejects_missing_or_malformed_abi() {
    let missing = compile_error(r#"(module)"#);
    assert_eq!(missing.code(), "abi_mismatch");
    let wrong =
        compile_error(r#"(module (func (export "bearust_abi_version") (result i64) i64.const 1))"#);
    assert_eq!(wrong.code(), "abi_mismatch");
    let invalid = match compile_bytes(b"not wasm", limits()) {
        Ok(_) => panic!("invalid bytes unexpectedly compiled"),
        Err(error) => error,
    };
    assert_eq!(invalid.code(), "compile_failed");
}

#[test]
fn engine_rejects_host_and_wasi_imports() {
    for wat in [
        r#"(module
            (import "env" "host_call" (func))
            (func (export "bearust_abi_version") (result i32) i32.const 1))"#,
        r#"(module
            (import "wasi_snapshot_preview1" "fd_write" (func))
            (func (export "bearust_abi_version") (result i32) i32.const 1))"#,
    ] {
        assert_eq!(compile_error(wat).code(), "compile_failed");
    }
}

#[test]
fn engine_clamps_manifest_limits_to_policy() {
    let policy = PluginPolicy {
        max_memory_pages: 1,
        max_fuel: 100,
        max_invocation_timeout_ms: 20,
        ..PluginPolicy::default()
    };
    let engine = PluginEngine::new(policy).unwrap();
    let mut requested = limits();
    requested.memory_pages = 99;
    requested.fuel = 99_999;
    requested.invocation_timeout_ms = 99_999;
    let plugin = engine
        .compile(
            validated(requested),
            &wat::parse_str(
                r#"(module (func (export "bearust_abi_version") (result i32) i32.const 1)
                             (func (export "bearust_health_check") (result i32) i32.const 1))"#,
            )
            .unwrap(),
        )
        .unwrap();
    assert_eq!(plugin.health_check().unwrap().status, 1);
}

#[test]
fn engine_rejects_oversized_module_bytes() {
    let engine = PluginEngine::new(PluginPolicy::default()).unwrap();
    let error = match engine.compile(validated(limits()), &vec![0u8; 16 * 1024 * 1024 + 1]) {
        Ok(_) => panic!("oversized module unexpectedly compiled"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "invalid_manifest");
}

#[test]
fn engine_rejects_multi_memory_modules() {
    let error = compile_error(
        r#"(module
            (memory 1)
            (memory 1)
            (func (export "bearust_abi_version") (result i32) i32.const 1))"#,
    );
    assert_eq!(error.code(), "memory_limit");
}

#[test]
fn engine_rejects_output_limit_smaller_than_i32_abi() {
    let mut limits = limits();
    limits.max_output_bytes = 3;
    let error = match compile(
        r#"(module (func (export "bearust_abi_version") (result i32) i32.const 1))"#,
        limits,
    ) {
        Ok(_) => panic!("undersized output limit unexpectedly compiled"),
        Err(error) => error,
    };
    assert_eq!(error.code(), "invalid_manifest");
}

#[test]
fn engine_rejects_abi_version_before_health() {
    let plugin = compile(
        r#"(module
            (func (export "bearust_abi_version") (result i32) i32.const 2)
            (func (export "bearust_health_check") (result i32) unreachable))"#,
        limits(),
    )
    .unwrap();
    assert_eq!(plugin.health_check().unwrap_err().code(), "abi_mismatch");
}

#[test]
fn engine_maps_trap_fuel_and_memory_limits() {
    let trap = compile(
        r#"(module
            (func (export "bearust_abi_version") (result i32) i32.const 1)
            (func (export "bearust_health_check") (result i32) unreachable))"#,
        limits(),
    )
    .unwrap();
    assert_eq!(trap.health_check().unwrap_err().code(), "trap");

    let mut exhausted_limits = limits();
    exhausted_limits.fuel = 10;
    let exhausted = compile(
        r#"(module
            (func (export "bearust_abi_version") (result i32) i32.const 1)
            (func (export "bearust_health_check") (result i32) (loop br 0) unreachable))"#,
        exhausted_limits,
    )
    .unwrap();
    assert_eq!(
        exhausted.health_check().unwrap_err().code(),
        "fuel_exhausted"
    );

    let memory = compile(
        r#"(module
            (memory 1)
            (func (export "bearust_abi_version") (result i32) i32.const 1)
            (func (export "bearust_health_check") (result i32)
                i32.const 65536 i32.load))"#,
        limits(),
    )
    .unwrap();
    assert_eq!(memory.health_check().unwrap_err().code(), "memory_limit");
}

#[test]
fn engine_maps_epoch_timeout() {
    let mut timeout_limits = limits();
    timeout_limits.fuel = 1_000_000_000;
    timeout_limits.invocation_timeout_ms = 10;
    let plugin = compile(
        r#"(module
            (func (export "bearust_abi_version") (result i32) i32.const 1)
            (func (export "bearust_health_check") (result i32) (loop br 0) unreachable))"#,
        timeout_limits,
    )
    .unwrap();
    assert_eq!(plugin.health_check().unwrap_err().code(), "timeout");
}

#[test]
fn v2_malformed_json_output_is_trap() {
    // health_check_v2 returns a pointer to non-JSON bytes ("xyz", 3 bytes)
    // stored at offset 0.
    let wat = r#"(module
        (memory (export "memory") 1)
        (data (i32.const 0) "xyz")
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 64)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
            (i64.or
                (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                (i64.extend_i32_u (i32.const 3)))))"#;
    let plugin = compile_v2(wat, limits()).unwrap();
    assert_eq!(plugin.health_check().unwrap_err(), PluginError::Trap);
}

#[test]
fn v2_out_of_bounds_output_pointer_is_trap_not_a_host_crash() {
    // health_check_v2 claims an absurd pointer far outside the guest's
    // single-page (65536-byte) memory.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
            (i64.or
                (i64.shl (i64.extend_i32_u (i32.const 1000000)) (i64.const 32))
                (i64.extend_i32_u (i32.const 10)))))"#;
    let plugin = compile_v2(wat, limits()).unwrap();
    assert_eq!(plugin.health_check().unwrap_err(), PluginError::Trap);
}

#[test]
fn v2_negative_alloc_pointer_is_trap_on_the_input_write() {
    // Hostile guest: bearust_alloc hands back a negative pointer. The host
    // must reject it while bounds-checking the *input* write, before any
    // byte is copied and before health_check_v2 is even called.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const -1)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
            unreachable))"#;
    let plugin = compile_v2(wat, limits()).unwrap();
    assert_eq!(plugin.health_check().unwrap_err(), PluginError::Trap);
}

#[test]
fn v2_out_of_bounds_alloc_pointer_is_trap_on_the_input_write() {
    // Same hostile-allocator shape, but with a large in-range-looking
    // pointer far past the end of the guest's single 65536-byte page.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1000000)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
            unreachable))"#;
    let plugin = compile_v2(wat, limits()).unwrap();
    assert_eq!(plugin.health_check().unwrap_err(), PluginError::Trap);
}

#[test]
fn v2_oversized_output_is_memory_limit_not_trap() {
    // Two pages (131072 bytes) of real memory so the claimed range is
    // in-bounds, but the claimed length (2000) exceeds max_output_bytes
    // (1024, from the `limits()` helper) — isolates the cap check from the
    // bounds check.
    let wat = r#"(module
        (memory (export "memory") 2)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
            (i64.or
                (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                (i64.extend_i32_u (i32.const 2000)))))"#;
    // The store's memory limiter is derived from `PluginLimits.memory_pages`
    // (an independent cap from `max_output_bytes`), so it must be raised to
    // fit the WAT's declared two-page memory or `compile_v2` itself fails
    // with `MemoryLimit` before the codepath under test ever runs.
    let plugin = compile_v2(
        wat,
        PluginLimits {
            memory_pages: 2,
            ..limits()
        },
    )
    .unwrap();
    assert_eq!(plugin.health_check().unwrap_err(), PluginError::MemoryLimit);
}

#[test]
fn v2_long_detail_is_truncated_at_a_char_boundary() {
    // Build a >4096-byte JSON detail string entirely out of a 3-byte-wide
    // repeated codepoint (the Euro sign) so any naive byte-index truncation
    // at MAX_DETAIL_BYTES (4096) would split a character and panic: since
    // 4096 % 3 != 0, the cut point does not land on a char boundary by
    // coincidence the way a 4-byte-wide codepoint's would. This makes the
    // test actually exercise the char-boundary-seeking loop rather than
    // passing vacuously.
    let long = "\u{20AC}".repeat(2700); // 3 bytes each => 8100 bytes total
    let json = format!(r#"{{"healthy":true,"detail":"{long}"}}"#);
    let json_bytes = json.into_bytes();
    let wat = format!(
        r#"(module
        (memory (export "memory") 4)
        (data (i32.const 0) "{escaped}")
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 200000)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
            (i64.or
                (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
                (i64.extend_i32_u (i32.const {len})))))"#,
        escaped = wat_escape(&json_bytes),
        len = json_bytes.len(),
    );
    // Likewise, `memory_pages` must be raised to fit the WAT's declared
    // four-page memory or `compile_v2` fails with `MemoryLimit` before the
    // health-check invocation (and its detail truncation) ever runs.
    let big_limits = PluginLimits {
        max_output_bytes: 65536,
        memory_pages: 4,
        ..limits()
    };
    let plugin = compile_v2(&wat, big_limits).unwrap();
    let result = plugin.health_check().unwrap();
    let detail = result.detail.unwrap();
    assert!(detail.len() <= 4096);
    // No panic and the string is valid UTF-8 by construction (String
    // guarantees this); the assertion above proves truncation happened
    // without needing to inspect a specific cut point.
}

fn wat_escape(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("\\{b:02x}")).collect()
}

#[test]
fn waf_detect_fixture_round_trips_json_and_returns_verdict() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("waf-detect-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/waf_detect_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/waf_detect_v2/waf_detect_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("waf_detect_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);

    let detector = manager
        .waf_detector_plugin()
        .expect("waf-detect-v2 declares waf.detect and is enabled");
    let request = bearust_plugin_sdk::WafDetectRequest {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    let verdict = detector.detect(&request).unwrap();
    assert_eq!(
        verdict.decision,
        bearust_plugin_sdk::WafPluginDecision::Block
    );
    assert_eq!(verdict.category, "custom_detector");
    assert_eq!(verdict.score, 10);
}

#[test]
fn waf_detect_accepts_a_realistic_header_set_and_a_full_body() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("waf-detect-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/waf_detect_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/waf_detect_v2/waf_detect_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("waf_detect_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    let detector = manager.waf_detector_plugin().unwrap();

    let headers = (0..20)
        .map(|i| (format!("x-custom-header-{i}"), "a".repeat(100)))
        .collect();
    let request = bearust_plugin_sdk::WafDetectRequest {
        method: "POST".into(),
        path: "/api/v1/upload".into(),
        query: "token=abc123&format=json".into(),
        headers,
        body: vec![b'x'; 2048],
    };
    // Must succeed -- proves the bounded request fits comfortably under the
    // fixture's declared max_output_bytes floor, unlike the pre-fix
    // unbounded request would have.
    assert!(detector.detect(&request).is_ok());
}

#[test]
fn waf_detector_plugin_is_none_when_no_plugin_declares_the_capability() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("health-ok-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/health_ok_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/health_ok_v2/health_ok_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("health_ok_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    assert!(manager.waf_detector_plugin().is_none());
}

#[test]
fn waf_detector_plugin_is_none_when_disabled() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("waf-detect-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/waf_detect_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/waf_detect_v2/waf_detect_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("waf_detect_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager.set_enabled("waf-detect-v2", false).unwrap();
    assert!(manager.waf_detector_plugin().is_none());
}

#[test]
fn transform_fixture_round_trips_json_and_returns_headers() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("transform-request-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/transform_request_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/transform_request_v2/transform_request_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("transform_request_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);

    let transformer = manager
        .transform_plugin()
        .expect("transform-request-v2 declares transform.request and is enabled");
    let request = bearust_plugin_sdk::TransformRequest {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
    };
    let response = transformer.transform(&request).unwrap();
    assert_eq!(
        response.headers,
        vec![("x-transformed".to_string(), "yes".to_string())]
    );
}

#[test]
fn transform_plugin_is_none_when_no_plugin_declares_the_capability() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("health-ok-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/health_ok_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/health_ok_v2/health_ok_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("health_ok_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    assert!(manager.transform_plugin().is_none());
}

#[test]
fn transform_plugin_is_none_when_disabled() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("transform-request-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/transform_request_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/transform_request_v2/transform_request_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("transform_request_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager.set_enabled("transform-request-v2", false).unwrap();
    assert!(manager.transform_plugin().is_none());
}

#[test]
fn transform_response_fixture_round_trips_json_and_returns_body() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("transform-response-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/transform_response_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/transform_response_v2/transform_response_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("transform_response_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        max_output_bytes: 2 * 1024 * 1024,
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);

    let transformer = manager
        .transform_response_plugin()
        .expect("transform-response-v2 declares transform.response and is enabled");
    let request = bearust_plugin_sdk::TransformResponseRequest {
        status: 200,
        body: String::new(),
    };
    let response = transformer.transform_response(&request).unwrap();
    assert_eq!(response.body, "aGVsbG8=");
}

#[test]
fn transform_response_plugin_is_none_when_no_plugin_declares_the_capability() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("health-ok-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/health_ok_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/health_ok_v2/health_ok_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("health_ok_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    assert!(manager.transform_response_plugin().is_none());
}

#[test]
fn transform_response_plugin_is_none_when_disabled() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("transform-response-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/transform_response_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/transform_response_v2/transform_response_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("transform_response_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        max_output_bytes: 2 * 1024 * 1024,
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager.set_enabled("transform-response-v2", false).unwrap();
    assert!(manager.transform_response_plugin().is_none());
}

#[test]
fn balance_select_fixture_round_trips_json_and_returns_backend_id() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("balance-select-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/balance_select_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/balance_select_v2/balance_select_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("balance_select_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);

    let selector = manager
        .balance_select_plugin()
        .expect("balance-select-v2 declares balance.select and is enabled");
    let request = bearust_plugin_sdk::LoadBalanceRequest {
        pool: "api".into(),
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
        backends: Vec::new(),
        excluded_backend_id: None,
    };
    let response = selector.balance_select(&request).unwrap();
    assert_eq!(response.backend_id, 0);
}

#[test]
fn balance_select_plugin_is_none_when_no_plugin_declares_the_capability() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("health-ok-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/health_ok_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/health_ok_v2/health_ok_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("health_ok_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    assert!(manager.balance_select_plugin().is_none());
}

#[test]
fn balance_select_plugin_is_none_when_disabled() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("balance-select-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/balance_select_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/balance_select_v2/balance_select_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("balance_select_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager.set_enabled("balance-select-v2", false).unwrap();
    assert!(manager.balance_select_plugin().is_none());
}
