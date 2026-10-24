//! Signed registry indexes, registry revocations, and upgrades.

use axum::{extract::State, routing::get, Router};
use base64::Engine as _;
use ed25519_dalek::{Signer, SigningKey};
use flate2::{write::GzEncoder, Compression};
use rand::rngs::OsRng;
use serde_json::json;
use sha2::{Digest, Sha256};
use std::io::Write as _;
use std::process::Command;
use std::sync::{Arc, Mutex};
use tempfile::tempdir;

const MANIFEST: &[u8] = include_bytes!("fixtures/plugins/health_ok/plugin.toml");

fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn wasm() -> Vec<u8> {
    wat::parse_str(include_str!("fixtures/plugins/health_ok/health_ok.wat")).unwrap()
}

/// A signed bundle for the health-ok fixture; returns (tarball, signer key b64).
fn bundle(signer: &SigningKey) -> (Vec<u8>, String) {
    let manifest = bearust::plugin_runtime::PluginManifest::from_toml(MANIFEST).unwrap();
    let wasm = wasm();
    let signature = bearust::plugin_signing::sign(&manifest, &wasm, signer);
    let sig = toml::to_string(&signature).unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    for (path, contents) in [
        ("plugin.toml", MANIFEST.to_vec()),
        (manifest.module.as_str(), wasm.clone()),
        ("plugin.sig", sig.into_bytes()),
    ] {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, path, contents.as_slice())
            .unwrap();
    }
    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&builder.into_inner().unwrap()).unwrap();
    (
        encoder.finish().unwrap(),
        b64(&signer.verifying_key().to_bytes()),
    )
}

#[derive(Clone, Default)]
struct Registry {
    index: Arc<Mutex<String>>,
    signature: Arc<Mutex<Option<String>>>,
    tarball: Arc<Mutex<Vec<u8>>>,
}

impl Registry {
    /// Publish `version` of the bundle with optional revocations, signed by
    /// `registry_key` when given.
    fn publish(
        &self,
        base: &str,
        version: &str,
        tarball: Vec<u8>,
        plugin_signer: &str,
        revocations: serde_json::Value,
        registry_key: Option<&SigningKey>,
    ) {
        let mut index = json!({
            "entries": [{
                "id": "health-ok", "display_name": "Health", "description": "fixture",
                "version": version, "download_url": format!("{base}/bundle.tar.gz"),
                "sha256": hex::encode(Sha256::digest(&tarball)),
                "signer_public_key": plugin_signer,
            }]
        });
        if let serde_json::Value::Object(extra) = revocations {
            index.as_object_mut().unwrap().extend(extra);
        }
        let body = index.to_string();
        *self.signature.lock().unwrap() =
            registry_key.map(|key| b64(&key.sign(body.as_bytes()).to_bytes()));
        *self.index.lock().unwrap() = body;
        *self.tarball.lock().unwrap() = tarball;
    }
}

async fn serve(registry: Registry) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route(
            "/index.json",
            get(|State(r): State<Registry>| async move { r.index.lock().unwrap().clone() }),
        )
        .route(
            "/index.json.sig",
            get(|State(r): State<Registry>| async move {
                match r.signature.lock().unwrap().clone() {
                    Some(sig) => (axum::http::StatusCode::OK, sig),
                    None => (axum::http::StatusCode::NOT_FOUND, String::new()),
                }
            }),
        )
        .route(
            "/bundle.tar.gz",
            get(|State(r): State<Registry>| async move { r.tarball.lock().unwrap().clone() }),
        )
        .with_state(registry);
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    base
}

fn cli(args: &[&str], plugins: &std::path::Path) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_bearust"))
        .args(args)
        .arg("--out")
        .arg(plugins)
        .arg("--yes")
        .output()
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_index_revocation_and_upgrade() {
    let registry = Registry::default();
    let base = serve(registry.clone()).await;
    let url = format!("{base}/index.json");
    let registry_key = SigningKey::generate(&mut OsRng);
    let pinned = b64(&registry_key.verifying_key().to_bytes());
    let author = SigningKey::generate(&mut OsRng);
    let (tarball, author_b64) = bundle(&author);
    let plugins = tempdir().unwrap();
    let install = |extra: &[&str]| {
        let mut args = vec![
            "plugin",
            "install",
            "health-ok",
            "--registry-url",
            url.as_str(),
        ];
        args.extend_from_slice(extra);
        cli(&args, plugins.path())
    };

    // Unsigned index with a pinned key: refused.
    registry.publish(
        &base,
        "1.0.0",
        tarball.clone(),
        &author_b64,
        json!({}),
        None,
    );
    let out = install(&["--registry-key", &pinned]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("registry index signature"));
    // Signed by another key: refused.
    let rogue = SigningKey::generate(&mut OsRng);
    registry.publish(
        &base,
        "1.0.0",
        tarball.clone(),
        &author_b64,
        json!({}),
        Some(&rogue),
    );
    assert!(!install(&["--registry-key", &pinned]).status.success());
    // Properly signed: installed, with an install record.
    registry.publish(
        &base,
        "1.0.0",
        tarball.clone(),
        &author_b64,
        json!({}),
        Some(&registry_key),
    );
    let out = install(&["--registry-key", &pinned]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let record = bearust::plugin_registry::installed_record(plugins.path(), "health-ok").unwrap();
    assert_eq!(
        (record.version.as_str(), record.index_signed),
        ("1.0.0", true)
    );

    // Upgrade picks up a newer version.
    registry.publish(
        &base,
        "1.1.0",
        tarball.clone(),
        &author_b64,
        json!({}),
        Some(&registry_key),
    );
    let out = cli(
        &[
            "plugin",
            "upgrade",
            "--registry-url",
            &url,
            "--registry-key",
            &pinned,
        ],
        plugins.path(),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stdout).contains("health-ok: 1.0.0 -> 1.1.0"));
    assert_eq!(
        bearust::plugin_registry::installed_record(plugins.path(), "health-ok")
            .unwrap()
            .version,
        "1.1.0"
    );

    // A revoked release cannot be installed.
    registry.publish(
        &base,
        "1.1.0",
        tarball.clone(),
        &author_b64,
        json!({ "revoked": [{"id": "health-ok", "version": "1.1.0"}] }),
        Some(&registry_key),
    );
    let out = install(&["--registry-key", &pinned, "--force"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("revoked"));

    // Revoking the author's key is recorded and stops the installed plugin
    // from loading.
    let manager = bearust::plugin_runtime::PluginManager::new(bearust::config::PluginConfig {
        enabled: true,
        directory: plugins.path().to_path_buf(),
        ..Default::default()
    });
    assert_eq!(manager.reload_from_disk().unwrap().loaded, 1);
    registry.publish(
        &base,
        "1.1.0",
        tarball.clone(),
        &author_b64,
        json!({ "revoked_keys": [author_b64] }),
        Some(&registry_key),
    );
    let out = install(&["--registry-key", &pinned, "--force"]);
    assert!(String::from_utf8_lossy(&out.stderr).contains("revoked"));
    assert!(bearust::plugin_registry::load_revoked_keys(plugins.path()).contains(&author_b64));
    let summary = manager.reload_from_disk();
    let failed = summary.map(|s| s.failed).unwrap_or(1);
    assert_eq!(failed, 1, "revoked signer must not load");

    // Without a pinned key, revocations in an unsigned index are ignored.
    let fresh = tempdir().unwrap();
    registry.publish(
        &base,
        "1.1.0",
        tarball,
        &author_b64,
        json!({ "revoked_keys": [author_b64] }),
        None,
    );
    let out = cli(
        &["plugin", "install", "health-ok", "--registry-url", &url],
        fresh.path(),
    );
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(bearust::plugin_registry::load_revoked_keys(fresh.path()).is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dashboard_browses_installs_and_upgrades_from_the_registry() {
    use axum::body::{to_bytes, Body};
    use axum::http::{Request, StatusCode};
    use tower::util::ServiceExt;

    let registry = Registry::default();
    let base = serve(registry.clone()).await;
    let registry_key = SigningKey::generate(&mut OsRng);
    let author = SigningKey::generate(&mut OsRng);
    let (tarball, author_b64) = bundle(&author);
    registry.publish(
        &base,
        "1.0.0",
        tarball.clone(),
        &author_b64,
        json!({}),
        Some(&registry_key),
    );

    let dir = tempdir().unwrap();
    let plugins = tempdir().unwrap();
    let mut state =
        bearust::control_plane::build_state("sqlite::memory:", dir.path(), "setup-token")
            .await
            .unwrap();
    state.plugin_manager =
        bearust::plugin_runtime::PluginManager::new(bearust::config::PluginConfig {
            enabled: true,
            directory: plugins.path().to_path_buf(),
            registry_url: Some(format!("{base}/index.json")),
            registry_public_key: Some(b64(&registry_key.verifying_key().to_bytes())),
            ..Default::default()
        });
    let app = bearust::control_plane::router(state);
    let call =
        |method: &str, uri: &str, cookie: Option<String>, body: Option<serde_json::Value>| {
            let app = app.clone();
            let mut req = Request::builder()
                .method(method)
                .uri(uri)
                .header("content-type", "application/json");
            if let Some(cookie) = cookie {
                req = req.header("cookie", cookie);
            }
            let req = req
                .body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
                .unwrap();
            async move {
                let response = app.oneshot(req).await.unwrap();
                let status = response.status();
                let cookie = response
                    .headers()
                    .get("set-cookie")
                    .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
                let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
                (
                    status,
                    serde_json::from_slice::<serde_json::Value>(&body).unwrap_or_default(),
                    cookie,
                )
            }
        };
    call("POST", "/api/setup/initialize", None, Some(json!({
        "email": "admin@example.com", "password": "correct horse battery", "setup_token": "setup-token"
    }))).await;
    let (_, _, cookie) = call(
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "email": "admin@example.com", "password": "correct horse battery"
        })),
    )
    .await;

    let (status, listing, _) = call(
        "GET",
        "/api/plugins/registry?q=health",
        cookie.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(listing["index_signed"], true);
    assert_eq!(
        listing["entries"][0]["installed_version"],
        serde_json::Value::Null
    );

    let (status, installed, _) = call(
        "POST",
        "/api/plugins/registry/health-ok/install",
        cookie.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{installed}");
    assert_eq!(installed["plugin"]["trust_status"], "trusted");
    let (status, _, _) = call(
        "POST",
        "/api/plugins/registry/health-ok/install",
        cookie.clone(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);

    registry.publish(
        &base,
        "2.0.0",
        tarball,
        &author_b64,
        json!({}),
        Some(&registry_key),
    );
    let (_, listing, _) = call("GET", "/api/plugins/registry", cookie.clone(), None).await;
    assert_eq!(listing["entries"][0]["update_available"], true);
    let (status, upgraded, _) = call(
        "POST",
        "/api/plugins/registry/health-ok/install",
        cookie.clone(),
        Some(json!({"force": true})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(upgraded["version"], "2.0.0");

    // A tampered index (signature no longer matches) is refused.
    let tampered = registry
        .index
        .lock()
        .unwrap()
        .replace("fixture", "tampered");
    *registry.index.lock().unwrap() = tampered;
    let (status, error, _) = call("GET", "/api/plugins/registry", cookie, None).await;
    assert_eq!(status, StatusCode::BAD_GATEWAY);
    assert_eq!(error["code"], "registry_untrusted");
}
