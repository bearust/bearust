use axum::body::Body;
use axum::response::Response;
use axum::{extract::State, http::StatusCode, routing::get, Router};
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use flate2::write::GzEncoder;
use flate2::Compression;
use rand::rngs::OsRng;
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

/// Like `spawn_mock_registry`, but lets the caller declare a
/// `signer_public_key` for the index entry -- needed to exercise the
/// signed-install path and a signer-key-mismatch rejection at the CLI
/// level.
async fn spawn_mock_registry_with_signer(
    tarball: Vec<u8>,
    sha256: String,
    signer_public_key: Option<String>,
) -> String {
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
            "signer_public_key": signer_public_key,
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

/// Builds a real Ed25519 keypair, signs `MANIFEST` + the given wasm bytes
/// with it, and returns a tarball containing `plugin.toml`, the module, and
/// `plugin.sig`, alongside the raw signature TOML bytes (so a test can
/// assert the installed file matches byte-for-byte) and the base64-encoded
/// public key of the signer.
fn build_signed_tarball(wasm_bytes: &[u8]) -> (Vec<u8>, Vec<u8>, String, SigningKey) {
    let manifest = bearust::plugin_runtime::PluginManifest::from_toml(MANIFEST).unwrap();
    let signing_key = SigningKey::generate(&mut OsRng);
    let signature = bearust::plugin_signing::sign(&manifest, wasm_bytes, &signing_key);
    let sig_toml = toml::to_string(&signature).unwrap();
    let sig_bytes = sig_toml.into_bytes();
    let public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes());
    let tarball = build_tarball(&[
        ("plugin.toml", MANIFEST),
        ("demo.wasm", wasm_bytes),
        ("plugin.sig", &sig_bytes),
    ]);
    (tarball, sig_bytes, public_key_b64, signing_key)
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
async fn install_rejects_an_empty_id_before_any_network_call() {
    // `plugin_runtime::valid_id("")` is vacuously true (its charset and
    // no-leading/trailing-hyphen checks all hold on an empty string), so
    // `plugin_install`'s id validation must also check for emptiness itself
    // -- otherwise an empty id reaches the registry fetch before being
    // caught only by the later defense-in-depth parent-directory assertion.
    // Point `--registry-url` at a reserved, unroutable address (TEST-NET-1,
    // RFC 5737) rather than a listening mock server: if validation ever
    // regressed to allow a network call through, this would hang/time out
    // or fail with a connection error instead of the fast, clean id-
    // validation error message asserted below.
    let plugins_dir = tempdir().unwrap();
    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "", "--out"])
        .arg(plugins_dir.path())
        .args([
            "--registry-url",
            "http://192.0.2.1:9/index.json",
            "--yes",
            "--force",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not a valid plugin id"),
        "stderr was: {stderr}"
    );
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

/// Regression test for the "unbounded read when Content-Length is absent"
/// finding: `RegistryIndex::fetch`'s `content_length()` pre-check does
/// nothing when the server never sends the header, so without a bounded
/// read the whole (oversized) body would be buffered before any size check
/// could fire. This server streams a chunked response with no
/// Content-Length header at all, well past `MAX_INDEX_RESPONSE_BYTES` (1
/// MiB), and the CLI must reject it quickly rather than hang trying to
/// buffer it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn search_rejects_an_oversized_index_response_with_no_content_length_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    let app = Router::new().route(
        "/index.json",
        get(|| async {
            // 20 chunks of 128 KiB = 2.5 MiB, more than double
            // MAX_INDEX_RESPONSE_BYTES, streamed with no known total length
            // so axum cannot set Content-Length.
            let chunk = vec![b'a'; 128 * 1024];
            let stream = futures_util::stream::iter(
                (0..20)
                    .map(move |_| Ok::<_, std::io::Error>(axum::body::Bytes::from(chunk.clone()))),
            );
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Body::from_stream(stream))
                .unwrap()
        }),
    );
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let index_url = format!("http://{addr}/index.json");

    let started = std::time::Instant::now();
    let output = Command::new(bearust_bin())
        .args(["plugin", "search", "anything", "--registry-url", &index_url])
        .output()
        .unwrap();
    let elapsed = started.elapsed();

    assert!(
        !output.status.success(),
        "an oversized, Content-Length-less index response should be rejected"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("size limit"),
        "expected a response-too-large error, got: {stderr}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "rejection should be prompt, not proportional to how much the server is willing to stream"
    );
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_writes_a_valid_signature_file_for_a_signed_plugin() {
    let wasm_bytes = b"pretend-wasm-bytes".to_vec();
    let (tarball, sig_bytes, public_key_b64, _signing_key) = build_signed_tarball(&wasm_bytes);
    let checksum = sha256_hex(&tarball);
    let index_url = spawn_mock_registry_with_signer(tarball, checksum, Some(public_key_b64)).await;

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
    let installed_dir = plugins_dir.path().join("demo-plugin");
    assert!(installed_dir.join("plugin.toml").exists());
    assert_eq!(
        std::fs::read(installed_dir.join("demo.wasm")).unwrap(),
        wasm_bytes
    );
    let installed_sig = installed_dir.join("plugin.sig");
    assert!(installed_sig.exists(), "plugin.sig was not installed");
    assert_eq!(
        std::fs::read(&installed_sig).unwrap(),
        sig_bytes,
        "installed plugin.sig bytes must exactly match the tarball's"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn install_rejects_a_signer_key_mismatch_and_writes_nothing() {
    let wasm_bytes = b"pretend-wasm-bytes".to_vec();
    let (tarball, _sig_bytes, _actual_public_key_b64, _signing_key) =
        build_signed_tarball(&wasm_bytes);
    let checksum = sha256_hex(&tarball);
    // A different, also validly generated key -- the index falsely declares
    // this as the signer even though the archive is signed by another key.
    let wrong_key = SigningKey::generate(&mut OsRng);
    let wrong_public_key_b64 =
        base64::engine::general_purpose::STANDARD.encode(wrong_key.verifying_key().to_bytes());
    let index_url =
        spawn_mock_registry_with_signer(tarball, checksum, Some(wrong_public_key_b64)).await;

    let plugins_dir = tempdir().unwrap();
    let output = Command::new(bearust_bin())
        .args(["plugin", "install", "demo-plugin", "--out"])
        .arg(plugins_dir.path())
        .args(["--registry-url", &index_url, "--yes"])
        .output()
        .unwrap();

    assert!(
        !output.status.success(),
        "install should fail on a signer key mismatch"
    );
    assert!(
        !plugins_dir.path().join("demo-plugin").exists(),
        "nothing should be written to the target directory on a signer mismatch"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("signer"),
        "expected a signer-mismatch error, got: {stderr}"
    );
}
