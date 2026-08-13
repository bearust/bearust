use bearust::plugin_runtime::PluginManifest;
use bearust::plugin_signing::verify;
use std::fs;
use std::process::Command;
use tempfile::tempdir;

fn bearust_bin() -> &'static str {
    env!("CARGO_BIN_EXE_bearust")
}

#[test]
fn keygen_then_sign_produces_a_signature_the_verifier_accepts() {
    let key_dir = tempdir().unwrap();
    let keygen = Command::new(bearust_bin())
        .args(["plugin", "keygen", "--out"])
        .arg(key_dir.path())
        .output()
        .unwrap();
    assert!(
        keygen.status.success(),
        "keygen failed: {}",
        String::from_utf8_lossy(&keygen.stderr)
    );
    assert!(key_dir.path().join("signing.key").exists());
    let printed_key = String::from_utf8(keygen.stdout).unwrap();
    assert!(!printed_key.trim().is_empty());

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(key_dir.path().join("signing.key"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    let plugin_dir = tempdir().unwrap();
    fs::write(
        plugin_dir.path().join("plugin.toml"),
        r#"id = "demo-plugin"
display_name = "Demo"
abi_version = 2
module = "demo.wasm"
capabilities = ["health_check"]

[limits]
memory_pages = 4
fuel = 1000000
invocation_timeout_ms = 100
max_output_bytes = 64
"#,
    )
    .unwrap();
    fs::write(plugin_dir.path().join("demo.wasm"), b"pretend-wasm-bytes").unwrap();

    let sign = Command::new(bearust_bin())
        .args(["plugin", "sign"])
        .arg(plugin_dir.path())
        .arg("--key")
        .arg(key_dir.path().join("signing.key"))
        .output()
        .unwrap();
    assert!(
        sign.status.success(),
        "sign failed: {}",
        String::from_utf8_lossy(&sign.stderr)
    );

    let sig_path = plugin_dir.path().join("plugin.sig");
    assert!(sig_path.exists());
    let sig_toml = fs::read_to_string(&sig_path).unwrap();
    let signature: bearust::plugin_signing::PluginSignature = toml::from_str(&sig_toml).unwrap();

    let manifest_bytes = fs::read(plugin_dir.path().join("plugin.toml")).unwrap();
    let manifest = PluginManifest::from_toml(&manifest_bytes).unwrap();
    let wasm_bytes = fs::read(plugin_dir.path().join("demo.wasm")).unwrap();
    assert!(verify(&manifest, &wasm_bytes, &signature).is_ok());
}
