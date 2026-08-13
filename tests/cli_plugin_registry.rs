use axum::{extract::State, http::StatusCode, routing::get, Router};
use flate2::write::GzEncoder;
use flate2::Compression;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write as _;
use std::net::SocketAddr;
use std::process::{Command, Stdio};
use std::sync::Arc;
use tempfile::tempdir;
use tokio::net::TcpListener;

fn bearust_bin() -> &'static str {
    env!("CARGO_BIN_EXE_bearust")
}

const MANIFEST: &[u8] = br#"id = "demo-plugin"
display_name = "Demo"
abi_version = 2
module = "demo.wasm"
capabilities = []

[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1024
"#;

fn build_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    for (path, contents) in files {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, *contents).unwrap();
    }
    let tar_bytes = builder.into_inner().unwrap();
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&tar_bytes).unwrap();
    encoder.finish().unwrap()
}

#[derive(Clone)]
struct MockState {
    tarball: Arc<Vec<u8>>,
}

async fn spawn_mock_registry(tarball: Vec<u8>, sha256: String) -> String {
    let state = MockState {
        tarball: Arc::new(tarball),
    };
    let index_json = json!({
        "entries": [{
            "id": "demo-plugin",
            "display_name": "Demo",
            "description": "A demo plugin for tests.",
            "version": "1.0.0",
            "download_url": "PLACEHOLDER/demo-plugin.tar.gz",
            "sha256": sha256,
            "signer_public_key": null,
        }]
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let index_json = serde_json::to_string(&index_json)
        .unwrap()
        .replace("PLACEHOLDER", &base);

    let app = Router::new()
        .route(
            "/index.json",
            get(move || {
                let body = index_json.clone();
                async move { ([("content-type", "application/json")], body) }
            }),
        )
        .route(
            "/demo-plugin.tar.gz",
            get(|State(state): State<MockState>| async move {
                (StatusCode::OK, state.tarball.as_ref().clone())
            }),
        )
        .with_state(state);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("{base}/index.json")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_writes_the_plugin_directory_when_confirmed() {
    let tarball = build_tarball(&[
        ("plugin.toml", MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
    ]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    let mut child = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write as _;
    child.stdin.take().unwrap().write_all(b"y\n").unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let installed_dir = plugins_dir.path().join("demo-plugin");
    assert!(installed_dir.join("plugin.toml").exists());
    assert_eq!(
        std::fs::read(installed_dir.join("demo.wasm")).unwrap(),
        b"pretend-wasm-bytes"
    );
    assert!(!installed_dir.join("plugin.sig").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_writes_nothing_when_declined() {
    let tarball = build_tarball(&[
        ("plugin.toml", MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
    ]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    let mut child = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    use std::io::Write as _;
    child.stdin.take().unwrap().write_all(b"n\n").unwrap();
    let output = child.wait_with_output().unwrap();

    assert!(output.status.success());
    assert!(!plugins_dir.path().join("demo-plugin").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_with_yes_flag_skips_the_prompt() {
    let tarball = build_tarball(&[
        ("plugin.toml", MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
    ]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url, "--yes"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(plugins_dir
        .path()
        .join("demo-plugin")
        .join("plugin.toml")
        .exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_rejects_a_checksum_mismatch_and_writes_nothing() {
    let tarball = build_tarball(&[
        ("plugin.toml", MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
    ]);
    // Deliberately wrong checksum.
    let index_url = spawn_mock_registry(tarball, "0".repeat(64)).await;

    let plugins_dir = tempdir().unwrap();
    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url, "--yes"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!plugins_dir.path().join("demo-plugin").exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_refuses_to_overwrite_an_existing_directory_without_force() {
    let tarball = build_tarball(&[
        ("plugin.toml", MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
    ]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    std::fs::create_dir_all(plugins_dir.path().join("demo-plugin")).unwrap();
    std::fs::write(
        plugins_dir.path().join("demo-plugin").join("sentinel"),
        b"pre-existing",
    )
    .unwrap();

    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url, "--yes"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(plugins_dir
        .path()
        .join("demo-plugin")
        .join("sentinel")
        .exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_with_force_overwrites_an_existing_directory() {
    let tarball = build_tarball(&[
        ("plugin.toml", MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
    ]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    std::fs::create_dir_all(plugins_dir.path().join("demo-plugin")).unwrap();
    std::fs::write(
        plugins_dir.path().join("demo-plugin").join("sentinel"),
        b"pre-existing",
    )
    .unwrap();

    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url, "--yes", "--force"])
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "install failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!plugins_dir
        .path()
        .join("demo-plugin")
        .join("sentinel")
        .exists());
    assert!(plugins_dir
        .path()
        .join("demo-plugin")
        .join("plugin.toml")
        .exists());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_reports_not_found_for_an_unknown_id() {
    let tarball = build_tarball(&[
        ("plugin.toml", MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
    ]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let plugins_dir = tempdir().unwrap();
    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "does-not-exist", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url, "--yes"])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("does-not-exist"), "stderr was: {stderr}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_lists_matching_entries() {
    let tarball = build_tarball(&[
        ("plugin.toml", MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
    ]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let output = Command::new(bearust_bin())
        .args(["plugin", "search", "demo", "--registry-url", &index_url])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("demo-plugin"), "stdout was: {stdout}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_reports_no_matches_without_failing() {
    let tarball = build_tarball(&[
        ("plugin.toml", MANIFEST),
        ("demo.wasm", b"pretend-wasm-bytes"),
    ]);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry(tarball, checksum).await;

    let output = Command::new(bearust_bin())
        .args([
            "plugin",
            "search",
            "nonexistent-query",
            "--registry-url",
            &index_url,
        ])
        .output()
        .unwrap();

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("no plugins match"), "stdout was: {stdout}");
}
