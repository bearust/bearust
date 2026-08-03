use bearust::plugin_runtime::{
    module_digest, resolve_module_path, PluginError, PluginManifest, PluginPolicy,
};
use std::fs;
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
