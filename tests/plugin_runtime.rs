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
