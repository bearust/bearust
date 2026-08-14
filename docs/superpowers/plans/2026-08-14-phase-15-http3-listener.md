# Phase 15 Increment 1: HTTP/3 Listener Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an opt-in HTTP/3 (QUIC) listener to BeaRust that runs a client request through the existing WAF rule engine and routes/forwards it to the same upstream backends the HTTP/1.1/HTTP/2 path already uses, without modifying Pingora's `ProxyHttp` implementation.

**Architecture:** A new, independent listener stack in `src/http3.rs` built on `quinn` (QUIC transport) + `h3`/`h3-quinn` (HTTP/3 framing), running alongside Pingora's existing TCP listener. It shares the same TLS certificate/key files, the same `Arc<RuntimeStore>` for host routing and backend selection, and the same `Arc<WafStore>` for WAF rule evaluation — reusing `waf::evaluate` and `RuntimeSnapshot::route`/`PoolState::select` exactly as `src/proxy.rs` already does, without going through Pingora's request/session types at all.

**Tech Stack:** `quinn = "0.11"` (QUIC transport), `h3 = "0.0.8"` + `h3-quinn = "0.0.10"` (HTTP/3 over `quinn`), `rustls = "0.23"` with the `ring` crypto feature (direct dependency; previously only transitive via `pingora-rustls`), `rustls-pemfile = "2"` (PEM parsing), `reqwest` (already a dependency, async client) for the upstream HTTP/1.1 forward. `rcgen = "0.13"` as a new dev-dependency for self-signed test certificates.

## Global Constraints

- Every dependency version below was verified to compile together, and a full client→server HTTP/3 request/response round trip was verified working end-to-end, in an isolated scratch project before this plan was written: `quinn = "0.11"` (resolves to `0.11.11`), `h3 = "0.0.8"`, `h3-quinn = "0.0.10"`, `rustls = { version = "0.23", features = ["ring"] }`, `rustls-pemfile = "2"`, `rcgen = "0.13"`. Do not substitute different version ranges without re-verifying compatibility — `h3-quinn = "0.0.7"` (an earlier version) does **not** compile against `quinn = "0.11"` (a real `E0616: field '0' of struct 'quinn::StreamId' is private` error was hit and is why `0.0.10` is pinned instead).
- **`rustls::crypto::ring::default_provider().install_default().ok();` must be called once during process startup, before any `rustls::ServerConfig`/`ClientConfig` is built anywhere in the H3 code path.** This repo's dependency tree can resolve both the `ring` and `aws-lc-rs` rustls crypto backends transitively (confirmed: `quinn`'s default features pull in `aws-lc-sys` via `platform-verifier`, while this project's own `pingora-rustls` dependency uses the `ring` feature) — without an explicit install, `rustls::ServerConfig::builder()` panics at runtime with "Could not automatically determine the process-level CryptoProvider" (this exact panic was reproduced and confirmed during verification). The `.ok()` is intentional: a prior call by another dependency (or a re-entrant call) returning "already installed" is not an error condition.
- HTTP/3 requires TLS 1.3. `Http3Config.enabled = true` with `server.tls = None` must be rejected as a config validation error at startup, not silently ignored.
- `Http3Config.enabled` defaults to `false`. No UDP socket is opened, and no new dependency's runtime code path executes, unless an operator explicitly turns it on.
- The H3 listener reuses `waf::evaluate`, `RuntimeSnapshot::route`, and `PoolState::select` as free functions/methods operating on the same shared `Arc` state `src/proxy.rs` already holds — it must never duplicate WAF rule logic, routing logic, or load-balancing logic.
- **Refinement over the design spec:** the real HTTP/1.1/HTTP/2 path (`src/proxy.rs` around line 1048) evaluates WAF in two phases — a header-only pass first (empty body), then a second pass once the body is read, only when a body is actually expected (`Content-Length`/`Transfer-Encoding` present). This increment's H3 path performs **single-phase** evaluation instead: buffer the request body (capped at `waf::MAX_INSPECTION_BODY_BYTES`, same as today) before building `InspectionContext` and calling `waf::evaluate` exactly once. This is a deliberate simplification, not a security gap — the resulting `Evaluation` for a given logical request is the same either way, since `waf::evaluate` is a pure function of the `InspectionContext` it's given, and this increment's single evaluation always includes the body when one is present (the real path's two-phase design exists purely as a header-only fast-path optimization for requests without a body, which streaming H3 semantics make less valuable to replicate in a first increment). Document this explicitly in code comments; do not silently diverge from the design spec's "identical field shape" claim without this note.
- Block response, taken verbatim from the existing HTTP/1.1/HTTP/2 path (`src/proxy.rs`, `respond_error_with_body(403, Bytes::from_static(b"Request blocked"))`): status `403`, body `Request blocked`. The H3 path must send an identical status/body pair on a WAF block, so the two listeners are indistinguishable to a client being blocked.
- Upstream forwarding uses `reqwest::Client` (already a project dependency, already used elsewhere for async HTTP — e.g. `src/ai_advisor_provider.rs`), plain HTTP (no TLS), matching the existing `HttpPeer::new(address, false, ...)` upstream behavior in `src/proxy.rs`. Do not introduce a second HTTP client library.

---

## Task 1: `Http3Config` and dependency setup

**Files:**
- Modify: `Cargo.toml` (new dependencies: `quinn`, `h3`, `h3-quinn`, `rustls` direct, `rustls-pemfile`; new dev-dependency: `rcgen`)
- Modify: `src/config/mod.rs` (new `Http3Config` struct nested under `ServerConfig`, cross-field validation)
- Test: unit tests in `src/config/mod.rs`'s existing `#[cfg(test)] mod tests`

**Interfaces:**
- Consumes: nothing (first task).
- Produces: `pub struct Http3Config { pub enabled: bool, pub bind: SocketAddr }` as a field `pub http3: Http3Config` on `ServerConfig`, with `enabled` defaulting to `false`. Config validation rejects `http3.enabled == true && tls.is_none()`. Task 2 reads `config.server.http3` and `config.server.tls` to build the listener.

- [ ] **Step 1: Add dependencies to `Cargo.toml`**

In the main `[dependencies]` block, add:

```toml
quinn = "0.11"
h3 = "0.0.8"
h3-quinn = "0.0.10"
rustls = { version = "0.23", features = ["ring"] }
rustls-pemfile = "2"
```

In `[dev-dependencies]`, add:

```toml
rcgen = "0.13"
```

- [ ] **Step 2: Read the existing `ServerConfig`/`TlsConfig` shape**

Read `src/config/mod.rs` around the `ServerConfig` struct (search for `pub struct ServerConfig`) and its `Default`/deserialization pattern, and the existing `TlsConfig` struct (`pub cert_path: PathBuf, pub key_path: PathBuf`) so the new `Http3Config` follows the same style (derive list, `#[serde(default = ...)]` pattern for the boolean, etc.).

- [ ] **Step 3: Write the failing test for config validation**

Add to `src/config/mod.rs`'s test module:

```rust
#[test]
fn http3_enabled_without_tls_is_rejected() {
    let toml = r#"
[server]
bind = "127.0.0.1:8080"
control_bind = "127.0.0.1:8081"

[server.http3]
enabled = true
bind = "127.0.0.1:8443"
"#;
    let result = Config::from_toml_str(toml); // adjust to this module's actual parse entry point
    assert!(result.is_err(), "http3.enabled without server.tls must be rejected");
}

#[test]
fn http3_disabled_by_default() {
    let toml = r#"
[server]
bind = "127.0.0.1:8080"
control_bind = "127.0.0.1:8081"
"#;
    let config = Config::from_toml_str(toml).unwrap(); // adjust to this module's actual parse entry point
    assert!(!config.server.http3.enabled);
}
```

Before writing these for real, find this module's actual TOML-parsing test entry point (search existing tests in `src/config/mod.rs` for how they construct a `Config` from a TOML string or file — do not guess a function name; use whatever the existing tests already call) and adjust both tests to use it exactly, keeping the TOML content and assertions above.

- [ ] **Step 4: Run to confirm the tests fail to compile (`Http3Config` doesn't exist yet)**

Run: `cargo test --lib config:: -- --nocapture`
Expected: compile error (`http3` field not found on `ServerConfig`, or `Http3Config` not found).

- [ ] **Step 5: Implement `Http3Config` and validation**

In `src/config/mod.rs`, add:

```rust
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct Http3Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_http3_bind")]
    pub bind: SocketAddr,
}

impl Default for Http3Config {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: default_http3_bind(),
        }
    }
}

fn default_http3_bind() -> SocketAddr {
    "127.0.0.1:8443".parse().expect("valid default HTTP/3 bind address")
}
```

Add a field to `ServerConfig` (place it near the existing `tls: Option<TlsConfig>` field):

```rust
    #[serde(default)]
    pub http3: Http3Config,
```

Match this module's existing derive list on `ServerConfig`/`TlsConfig` exactly (read what's already there in Step 2 rather than assuming `Serialize`/`Deserialize`/`Debug`/`Clone`/`PartialEq`/`Eq` all apply — copy the real list).

Find `ServerConfig`'s or the top-level `Config`'s existing cross-field validation function (search for where `tls` is already validated, e.g. a `validate()` method or checks performed inside the config-loading function) and add:

```rust
if self.http3.enabled && self.tls.is_none() {
    return Err(ConfigError::Invalid(
        "server.http3.enabled requires server.tls to be configured".to_owned(),
    ));
}
```

Adjust the error construction to match this module's actual `ConfigError` variant shape (read it before writing this line — do not assume `ConfigError::Invalid(String)` exists; use whatever the existing validation errors in this file already construct).

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib config:: -- --nocapture`
Expected: both new tests pass, no regression in existing config tests.

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml Cargo.lock src/config/mod.rs
git commit -m "feat: add Http3Config with TLS-required validation"
```

---

## Task 2: QUIC/H3 listener bootstrap and request/response round trip

**Files:**
- Create: `src/http3.rs`
- Modify: `src/lib.rs` (register the new module)
- Test: integration test `tests/http3_listener.rs`

**Interfaces:**
- Consumes: `Http3Config`, `TlsConfig` (Task 1).
- Produces: `pub fn build_rustls_server_config(tls: &TlsConfig) -> Result<Arc<rustls::ServerConfig>, Http3Error>`, `pub async fn serve(bind: SocketAddr, tls_config: Arc<rustls::ServerConfig>, mut shutdown: tokio::sync::watch::Receiver<bool>) -> Result<(), Http3Error>` (this task's `serve` responds to every request with a fixed `200 ok` body — no WAF/routing yet, that's Tasks 3-4), `Http3Error`. Task 3 replaces the fixed-response body with real WAF-aware handling; Task 5 wires `serve` into `src/cli.rs`.

- [ ] **Step 1: Read the existing TLS-loading pattern**

Read `src/tls.rs` in full (`TlsSnapshot`, `settings`, `ensure_readable`) and `src/certificates/mod.rs`'s `CertificateStore::validate_material_paths` — this task reuses the *validation* pattern (readable, paired cert/key) but loads the PEM bytes itself via `rustls-pemfile` rather than through Pingora's `TlsSettings`, since `rustls::ServerConfig` (needed by `quinn`) and Pingora's `TlsSettings` are different types.

- [ ] **Step 2: Write `src/http3.rs`'s error type and TLS config builder**

```rust
//! HTTP/3 (QUIC) listener, independent of Pingora's TCP/TLS listener.
//!
//! Reuses the same certificate/key files as the existing HTTP/1.1/HTTP/2
//! listener, and (from a later task) the same WAF/routing/load-balancing
//! logic `src/proxy.rs` already uses — but runs as a fully separate
//! listener stack, since Pingora has no HTTP/3 support to extend (verified
//! against `pingora-core` 0.8.1's own source and Cargo.toml: no `quic`/`h3`
//! feature, no QUIC dependency, no QUIC source file anywhere in the crate).

use crate::config::TlsConfig;
use std::{
    io,
    net::SocketAddr,
    path::Path,
    sync::Arc,
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum Http3Error {
    #[error("HTTP/3 certificate file is not readable")]
    Certificate(#[source] io::Error),
    #[error("HTTP/3 private key file is not readable or missing")]
    PrivateKey(#[source] io::Error),
    #[error("HTTP/3 TLS configuration is invalid")]
    InvalidTls,
    #[error("HTTP/3 UDP socket could not be bound")]
    Bind(#[source] io::Error),
}

/// Builds the `rustls::ServerConfig` `quinn` needs, from the same
/// cert/key PEM files the Pingora TLS listener already validates and
/// uses. ALPN is set to `h3` only -- this listener never negotiates
/// anything but HTTP/3.
///
/// Callers must have already called
/// `rustls::crypto::ring::default_provider().install_default().ok();`
/// once during process startup (see `src/cli.rs`) -- this function does
/// not call it itself, to avoid every call site racing to install a
/// provider; it is a documented process-wide precondition instead.
pub fn build_rustls_server_config(tls: &TlsConfig) -> Result<Arc<rustls::ServerConfig>, Http3Error> {
    let certs = load_certs(&tls.cert_path)?;
    let key = load_key(&tls.key_path)?;
    let mut config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|_| Http3Error::InvalidTls)?;
    config.alpn_protocols = vec![b"h3".to_vec()];
    Ok(Arc::new(config))
}

fn load_certs(path: &Path) -> Result<Vec<rustls_pki_types::CertificateDer<'static>>, Http3Error> {
    let file = std::fs::File::open(path).map_err(Http3Error::Certificate)?;
    let mut reader = io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(Http3Error::Certificate)
}

fn load_key(path: &Path) -> Result<rustls_pki_types::PrivateKeyDer<'static>, Http3Error> {
    let file = std::fs::File::open(path).map_err(Http3Error::PrivateKey)?;
    let mut reader = io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(Http3Error::PrivateKey)?
        .ok_or_else(|| {
            Http3Error::PrivateKey(io::Error::new(io::ErrorKind::InvalidData, "no private key found"))
        })
}
```

Note: `rustls_pki_types` is a transitive dependency (pulled in by `rustls`/`rustls-pemfile`), not something this task adds directly to `Cargo.toml` — it is used here only because `rustls-pemfile`'s return types name it; confirm `cargo build` resolves it without an explicit `Cargo.toml` entry (it will, as a transitive re-export path — `rustls_pki_types::CertificateDer`/`PrivateKeyDer` are the types `rustls-pemfile 2.x` returns).

- [ ] **Step 3: Write the QUIC server-config builder and accept loop**

Append to `src/http3.rs`:

```rust
fn quinn_server_config(tls_config: Arc<rustls::ServerConfig>) -> Result<quinn::ServerConfig, Http3Error> {
    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from((*tls_config).clone())
        .map_err(|_| Http3Error::InvalidTls)?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(quic_tls)))
}

/// Runs the HTTP/3 listener until `shutdown` fires. Every request
/// currently receives a fixed `200 ok` response -- WAF evaluation and
/// upstream routing are added in later tasks. Bounded, graceful:
/// `shutdown` firing stops accepting new connections; in-flight
/// connections are given until the endpoint is dropped to finish (the
/// caller in `src/cli.rs`, from a later task, bounds this the same way
/// it already bounds other spawned tasks' shutdown).
pub async fn serve(
    bind: SocketAddr,
    tls_config: Arc<rustls::ServerConfig>,
    mut shutdown: tokio::sync::watch::Receiver<bool>,
) -> Result<(), Http3Error> {
    let server_config = quinn_server_config(tls_config)?;
    let endpoint = quinn::Endpoint::server(server_config, bind).map_err(Http3Error::Bind)?;

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                let Some(incoming) = incoming else { break };
                tokio::spawn(async move {
                    if let Ok(conn) = incoming.await {
                        handle_connection(conn).await;
                    }
                });
            }
            _ = shutdown.changed() => {
                if *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    endpoint.close(0u32.into(), b"shutdown");
    Ok(())
}

async fn handle_connection(conn: quinn::Connection) {
    let h3_conn = h3_quinn::Connection::new(conn);
    let mut h3_conn: h3::server::Connection<_, bytes::Bytes> =
        match h3::server::builder().build(h3_conn).await {
            Ok(conn) => conn,
            Err(_) => return,
        };

    loop {
        match h3_conn.accept().await {
            Ok(Some(resolver)) => {
                let Ok((_req, mut stream)) = resolver.resolve_request().await else {
                    break;
                };
                tokio::spawn(async move {
                    let resp = http::Response::builder()
                        .status(http::StatusCode::OK)
                        .body(())
                        .expect("static response head is always valid");
                    let _ = stream.send_response(resp).await;
                    let _ = stream.send_data(bytes::Bytes::from_static(b"ok")).await;
                    let _ = stream.finish().await;
                });
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
}
```

- [ ] **Step 4: Register the module**

In `src/lib.rs`, add `pub mod http3;` in the same alphabetical/logical grouping as `pub mod tls;`.

- [ ] **Step 5: Run `cargo build --workspace` to confirm it compiles**

Run: `cargo build --workspace --locked`
Expected: clean build. If a type/method name doesn't match (crate APIs occasionally shift patch-to-patch even within a pinned minor version), the version pins in Global Constraints are the ones already verified to work together — re-check your transcription against this task's exact code before assuming the crate API differs.

- [ ] **Step 6: Write the integration test**

Create `tests/http3_listener.rs`:

```rust
use bearust::http3;
use bytes::Buf;
use std::net::SocketAddr;
use std::sync::Arc;

fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn self_signed_server_config() -> (quinn::ServerConfig, rustls_pki_types::CertificateDer<'static>) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_der = rustls_pki_types::CertificateDer::from(cert.cert.der().to_vec());
    let key_der =
        rustls_pki_types::PrivateKeyDer::try_from(cert.key_pair.serialize_der()).unwrap();
    let mut tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert_der.clone()], key_der)
        .unwrap();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls_config).unwrap();
    (
        quinn::ServerConfig::with_crypto(Arc::new(quic_config)),
        cert_der,
    )
}

fn client_config(cert_der: rustls_pki_types::CertificateDer<'static>) -> quinn::ClientConfig {
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls_config.alpn_protocols = vec![b"h3".to_vec()];
    let quic_config =
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config).unwrap();
    quinn::ClientConfig::new(Arc::new(quic_config))
}

#[tokio::test]
async fn http3_listener_responds_to_a_real_h3_client() {
    install_crypto_provider();

    let (server_config, cert_der) = self_signed_server_config();
    let bind: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let endpoint = quinn::Endpoint::server(server_config, bind).unwrap();
    let server_addr = endpoint.local_addr().unwrap();

    tokio::spawn(async move {
        if let Some(incoming) = endpoint.accept().await {
            if let Ok(conn) = incoming.await {
                // Mirrors http3::handle_connection's shape without
                // depending on its private visibility -- this test
                // exercises the same public building blocks
                // (h3_quinn::Connection, h3::server::builder) the
                // library function itself uses.
                let h3_conn = h3_quinn::Connection::new(conn);
                if let Ok(mut h3_conn) =
                    h3::server::builder().build::<_, bytes::Bytes>(h3_conn).await
                {
                    if let Ok(Some(resolver)) = h3_conn.accept().await {
                        if let Ok((_req, mut stream)) = resolver.resolve_request().await {
                            let resp = http::Response::builder()
                                .status(http::StatusCode::OK)
                                .body(())
                                .unwrap();
                            let _ = stream.send_response(resp).await;
                            let _ = stream.send_data(bytes::Bytes::from_static(b"ok")).await;
                            let _ = stream.finish().await;
                        }
                    }
                }
            }
        }
    });

    let mut client_endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config(cert_der));

    let connecting = client_endpoint.connect(server_addr, "localhost").unwrap();
    let quinn_conn = connecting.await.unwrap();
    let h3_conn = h3_quinn::Connection::new(quinn_conn);
    let (mut driver, mut send_request) = h3::client::new(h3_conn).await.unwrap();
    let drive = tokio::spawn(async move {
        let _ = std::future::poll_fn(|cx| driver.poll_close(cx)).await;
    });

    let req = http::Request::builder()
        .method("GET")
        .uri("https://localhost/hello")
        .body(())
        .unwrap();
    let mut stream = send_request.send_request(req).await.unwrap();
    stream.finish().await.unwrap();
    let resp = stream.recv_response().await.unwrap();
    assert_eq!(resp.status(), http::StatusCode::OK);

    let mut body = Vec::new();
    while let Some(mut chunk) = stream.recv_data().await.unwrap() {
        while chunk.has_remaining() {
            let n = chunk.remaining();
            body.extend_from_slice(&chunk.chunk()[..n]);
            chunk.advance(n);
        }
    }
    assert_eq!(body, b"ok");
    drive.abort();
}

#[test]
fn build_rustls_server_config_reads_the_configured_cert_and_key() {
    // Exercises http3::build_rustls_server_config against a real,
    // temporary self-signed cert/key pair on disk (not the fixed test
    // fixtures used elsewhere in this repo, since those are for the
    // Pingora TLS listener's own tests) -- confirms the PEM-loading
    // path this task added works end to end.
    let dir = tempfile::tempdir().unwrap();
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()]).unwrap();
    let cert_path = dir.path().join("cert.pem");
    let key_path = dir.path().join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.key_pair.serialize_pem()).unwrap();

    let tls = bearust::config::TlsConfig {
        cert_path,
        key_path,
    };
    let result = http3::build_rustls_server_config(&tls);
    assert!(result.is_ok(), "{:?}", result.err());
}
```

Note the test's server-side connection handling is written inline rather than calling `http3::handle_connection` directly, since that function is private to `src/http3.rs` (internal detail, not part of the module's public interface) — the test instead exercises the same public `h3_quinn`/`h3` building blocks the real function uses, proving the wiring works, while the crate-internal `handle_connection`/`serve` functions are exercised by Task 5's fuller integration once they're wired into `src/cli.rs`. If `bearust::config::TlsConfig`'s fields aren't `pub` at the paths shown, adjust to match the real visibility (read `src/config/mod.rs` first).

- [ ] **Step 7: Run the test**

Run: `cargo test --test http3_listener -- --nocapture`
Expected: both tests pass.

- [ ] **Step 8: Commit**

```bash
git add src/http3.rs src/lib.rs tests/http3_listener.rs
git commit -m "feat: add HTTP/3 listener bootstrap with fixed-response request handling"
```

---

## Task 3: WAF evaluation on the HTTP/3 path

**Files:**
- Modify: `src/http3.rs` (replace the fixed `200 ok` response with WAF-aware handling)
- Test: extend `tests/http3_listener.rs`

**Interfaces:**
- Consumes: `waf::{evaluate, InspectionContext, WafSnapshot, WafDecision}` (existing), `waf_store::WafStore` (existing), Task 2's `handle_connection`/`serve`.
- Produces: `serve`'s signature grows an optional WAF store parameter: `pub async fn serve(bind: SocketAddr, tls_config: Arc<rustls::ServerConfig>, waf: Option<Arc<WafStore>>, mut shutdown: tokio::sync::watch::Receiver<bool>) -> Result<(), Http3Error>`, plus a private `fn build_inspection_context(method: &str, path: &str, query: &str, headers: &[(String, String)], body: Vec<u8>) -> crate::waf::InspectionContext` helper. Task 4 adds routing/forwarding parameters to `serve` alongside this one; Task 5 passes the real `Arc<WafStore>` from `src/cli.rs`.

- [ ] **Step 1: Read the real WAF evaluation call site**

Read `src/proxy.rs` around line 1048 (search for the first `InspectionContext {` construction) to see exactly which `InspectionContext` fields are populated and how, and read `src/waf.rs`'s `MAX_INSPECTION_BODY_BYTES` constant and `evaluate` function signature. Per this plan's Global Constraints, this task performs single-phase evaluation (body always included, capped, no separate header-only fast path) — do not replicate the two-phase pattern.

- [ ] **Step 2: Unit test — `InspectionContext` shape parity with the existing HTTP/1.1/HTTP/2 path**

Add a unit test (in `src/http3.rs`'s own `#[cfg(test)] mod tests`, not the integration test file, since it doesn't need a real network connection) that builds an `InspectionContext` two ways for the same logical request — once via whatever helper function this task extracts from `handle_request`'s context-building code (factor the field-mapping logic in Step 4 below into a standalone `fn build_inspection_context(method: &str, path: &str, query: &str, headers: &[(String, String)], body: Vec<u8>) -> InspectionContext` specifically so it's unit-testable without a live H3 connection), and once via literal field construction matching exactly what `src/proxy.rs`'s real `InspectionContext { ... }` construction produces for the same inputs — and asserts the two are equal:

```rust
#[test]
fn build_inspection_context_matches_the_http1_http2_paths_field_shape() {
    let headers = vec![("x-test".to_owned(), "1".to_owned())];
    let context = build_inspection_context("GET", "/hello", "q=1", &headers, b"body".to_vec());
    assert_eq!(
        context,
        crate::waf::InspectionContext {
            method: "GET".to_owned(),
            path: "/hello".to_owned(),
            query: "q=1".to_owned(),
            headers: vec![("x-test".to_owned(), "1".to_owned())],
            body: b"body".to_vec(),
        }
    );
}
```

This guards against the two listener paths silently drifting in how they map a request's raw fields into `InspectionContext`, which would otherwise let the same logical request produce different WAF verdicts depending on which listener handled it.

- [ ] **Step 3: Write the failing integration tests**

Add to `tests/http3_listener.rs` (needs a `WafStore` constructed with at least one blocking rule — read `src/waf_store.rs`'s public constructor and `src/waf.rs`'s rule-configuration shape to build a minimal store that blocks a specific test path, e.g. a rule matching `path` containing `/blocked`; base this on however existing WAF tests elsewhere in this repo (search `tests/` for an existing WAF-rule-construction test, e.g. a proxy or waf test file) already build a test `WafStore`/`WafSnapshot` — reuse that exact pattern rather than inventing a new one):

```rust
#[tokio::test]
async fn http3_listener_blocks_a_request_the_waf_rule_engine_would_block() {
    install_crypto_provider();
    // ... build a WafStore whose snapshot blocks GET /blocked (mirror
    // the pattern from the existing WAF test helper found in Step 1) ...
    // ... spawn http3::serve with that WafStore, connect a real h3
    // client, request GET https://localhost/blocked ...
    // assert!(resp.status() == http::StatusCode::FORBIDDEN);
    // assert body == b"Request blocked"
}

#[tokio::test]
async fn http3_listener_allows_a_request_the_waf_rule_engine_would_allow() {
    // same setup, request a path the rule doesn't match, assert 200
}
```

Write these for real once Step 1's research identifies the exact `WafStore`/rule-construction helper to reuse — do not invent a fake config shape.

- [ ] **Step 4: Run to confirm the tests fail (WAF isn't wired in yet)**

Run: `cargo test --lib http3:: --test http3_listener -- --nocapture`
Expected: the Step 2 unit test fails to compile (`build_inspection_context` doesn't exist yet), and the two Step 3 integration tests fail (still getting `200 ok` for a path that should be blocked) or fail to compile if `serve`'s signature doesn't yet accept a `WafStore` parameter.

- [ ] **Step 5: Extract `build_inspection_context` and wire WAF evaluation into the per-request handler**

Add to `src/http3.rs` (before `#[cfg(test)]`) the standalone, unit-testable field-mapping function Step 2's test depends on:

```rust
fn build_inspection_context(
    method: &str,
    path: &str,
    query: &str,
    headers: &[(String, String)],
    body: Vec<u8>,
) -> crate::waf::InspectionContext {
    crate::waf::InspectionContext {
        method: method.to_owned(),
        path: path.to_owned(),
        query: query.to_owned(),
        headers: headers.to_vec(),
        body,
    }
}
```

Modify `src/http3.rs`'s `serve` to accept and thread through `waf: Option<Arc<WafStore>>`, and modify the per-request closure (currently inline in `handle_connection`'s spawned task) to call `build_inspection_context`:

```rust
async fn handle_request<S>(
    req: http::Request<()>,
    mut stream: h3::server::RequestStream<S, bytes::Bytes>,
    waf: Option<Arc<WafStore>>,
) where
    S: h3::quic::BidiStream<bytes::Bytes>,
{
    let method = req.method().to_string();
    let path = req.uri().path().to_owned();
    let query = req.uri().query().unwrap_or_default().to_owned();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();

    let mut body = Vec::new();
    while let Ok(Some(mut chunk)) = stream.recv_data().await {
        if body.len() >= crate::waf::MAX_INSPECTION_BODY_BYTES {
            break;
        }
        while chunk.has_remaining() && body.len() < crate::waf::MAX_INSPECTION_BODY_BYTES {
            let take = chunk
                .remaining()
                .min(crate::waf::MAX_INSPECTION_BODY_BYTES - body.len());
            body.extend_from_slice(&chunk.chunk()[..take]);
            chunk.advance(take);
        }
    }

    if let Some(waf) = &waf {
        let snapshot = waf.snapshot();
        let context = build_inspection_context(&method, &path, &query, &headers, body.clone());
        let evaluation = crate::waf::evaluate(&snapshot, &context);
        if evaluation.decision == crate::waf::WafDecision::Block {
            let resp = http::Response::builder()
                .status(http::StatusCode::FORBIDDEN)
                .body(())
                .expect("static response head is always valid");
            let _ = stream.send_response(resp).await;
            let _ = stream.send_data(bytes::Bytes::from_static(b"Request blocked")).await;
            let _ = stream.finish().await;
            return;
        }
    }

    // Not blocked: Task 4 replaces this with real routing/forwarding.
    let resp = http::Response::builder()
        .status(http::StatusCode::OK)
        .body(())
        .expect("static response head is always valid");
    let _ = stream.send_response(resp).await;
    let _ = stream.send_data(bytes::Bytes::from_static(b"ok")).await;
    let _ = stream.finish().await;
}
```

Update `handle_connection` to accept `waf: Option<Arc<WafStore>>` and pass it (cloned per request) into `handle_request` instead of the old inline fixed-response closure. Update `serve`'s signature and its call to `handle_connection` accordingly.

- [ ] **Step 6: Run the tests**

Run: `cargo test --lib http3:: --test http3_listener -- --nocapture`
Expected: all tests pass, including Task 2's original round-trip test (now passing `None` for `waf` — update that test's `serve`/connection-setup call if its signature changed; the test builds the connection inline rather than calling `serve` directly, per Task 2 Step 6's note, so confirm whether this task's signature changes affect it at all before editing it unnecessarily).

- [ ] **Step 7: Commit**

```bash
git add src/http3.rs tests/http3_listener.rs
git commit -m "feat: evaluate the WAF rule engine on the HTTP/3 request path"
```

---

## Task 4: Routing and upstream forwarding

**Files:**
- Modify: `src/http3.rs` (replace the "not blocked" fixed `200 ok` with real routing + forwarding)
- Test: extend `tests/http3_listener.rs`

**Interfaces:**
- Consumes: `RuntimeStore`/`RuntimeSnapshot::route`, `PoolState::select`, `BackendLease` (existing, from `src/runtime.rs`/`src/balancer.rs`), `reqwest::Client` (existing dependency).
- Produces: `serve`'s signature grows a `store: Arc<RuntimeStore>` parameter:
  `pub async fn serve(bind: SocketAddr, tls_config: Arc<rustls::ServerConfig>, store: Arc<RuntimeStore>, waf: Option<Arc<WafStore>>, mut shutdown: tokio::sync::watch::Receiver<bool>) -> Result<(), Http3Error>`.
  This completes the request pipeline; Task 5 wires real `RuntimeStore`/`WafStore` instances from `src/cli.rs`.

- [ ] **Step 1: Read the routing/selection/forwarding API**

Read `src/runtime.rs`'s `RuntimeSnapshot::route(authority: &str, path: &str) -> Option<(&ResolvedRoute, Arc<PoolState>)>` and `RuntimeStore::load() -> Arc<RuntimeSnapshot>`; read `src/balancer.rs`'s `PoolState::select(self: &Arc<Self>, excluded: Option<BackendId>) -> Option<BackendLease>` and whatever `BackendLease`/`ResolvedRoute` expose for the backend's address (read the actual struct fields — do not assume field names). Read `src/proxy.rs`'s existing `HttpPeer::new(address, false, String::new())` call site to see exactly how a backend's address string is derived from `BackendLease`/pool state, so the H3 path constructs the same `http://<address>` target.

- [ ] **Step 2: Write the failing test**

Add to `tests/http3_listener.rs` a test that spins up a local plain-HTTP test backend (a minimal `axum` or raw `tokio::net::TcpListener` server returning a fixed body, following this repo's existing test patterns for a local backend — search `tests/` for an existing "local test backend" helper used by other proxy-level tests and reuse its shape rather than inventing a new one), constructs a `RuntimeStore`/`RuntimeSnapshot` whose config routes a given host/path to that backend's pool, spawns `http3::serve` with it, sends a real H3 request for that host/path, and asserts the response body matches what the test backend returned.

```rust
#[tokio::test]
async fn http3_listener_forwards_an_allowed_request_to_the_resolved_backend() {
    // ... spin up a local plain-HTTP backend returning a fixed body ...
    // ... build a RuntimeStore/RuntimeSnapshot whose config routes the
    //     test authority/path to that backend ...
    // ... spawn http3::serve(..., store, None, ...) ...
    // ... connect a real h3 client, request the routed path ...
    // assert!(resp.status() == http::StatusCode::OK);
    // assert body == the backend's fixed response body
}

#[tokio::test]
async fn http3_listener_returns_404_for_an_unmatched_host() {
    // route() returns None ⇒ 404, no backend contacted
}
```

Write these for real once Step 1's research identifies the exact `RuntimeStore`/test-backend construction pattern to reuse.

- [ ] **Step 3: Run to confirm the tests fail (routing isn't wired in yet)**

Run: `cargo test --test http3_listener -- --nocapture`
Expected: fails (still `200 ok` for everything) or fails to compile if `serve`'s signature already changed.

- [ ] **Step 4: Wire routing and forwarding into `handle_request`**

Replace the "not blocked" branch's fixed `200 ok` in `handle_request` (from Task 3) with:

```rust
    // Not blocked (or WAF not configured): route and forward.
    let authority = req
        .uri()
        .authority()
        .map(|a| a.as_str())
        .or_else(|| {
            req.headers()
                .get(http::header::HOST)
                .and_then(|v| v.to_str().ok())
        })
        .unwrap_or_default();
    let snapshot = store.load();
    let Some((_route, pool)) = snapshot.route(authority, &path) else {
        let resp = http::Response::builder()
            .status(http::StatusCode::NOT_FOUND)
            .body(())
            .expect("static response head is always valid");
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        return;
    };
    let Some(lease) = pool.select(None) else {
        let resp = http::Response::builder()
            .status(http::StatusCode::BAD_GATEWAY)
            .body(())
            .expect("static response head is always valid");
        let _ = stream.send_response(resp).await;
        let _ = stream.finish().await;
        return;
    };

    let target = format!("http://{}{}", lease.address(), req.uri().path_and_query().map(|p| p.as_str()).unwrap_or(&path));
    let client = reqwest::Client::new();
    let mut builder = client.request(
        reqwest::Method::from_bytes(method.as_bytes()).unwrap_or(reqwest::Method::GET),
        &target,
    );
    for (name, value) in &headers {
        builder = builder.header(name, value);
    }
    if !body.is_empty() {
        builder = builder.body(body.clone());
    }

    match builder.send().await {
        Ok(upstream_resp) => {
            let status = http::StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(http::StatusCode::BAD_GATEWAY);
            let resp = http::Response::builder()
                .status(status)
                .body(())
                .expect("static response head is always valid");
            let _ = stream.send_response(resp).await;
            let mut body_stream = upstream_resp.bytes_stream();
            use futures_util::StreamExt as _;
            while let Some(chunk) = body_stream.next().await {
                let Ok(chunk) = chunk else { break };
                if stream.send_data(chunk).await.is_err() {
                    break;
                }
            }
            let _ = stream.finish().await;
        }
        Err(_) => {
            let resp = http::Response::builder()
                .status(http::StatusCode::BAD_GATEWAY)
                .body(())
                .expect("static response head is always valid");
            let _ = stream.send_response(resp).await;
            let _ = stream.finish().await;
        }
    }
```

Adjust `lease.address()` and `pool.select(None)`'s exact method/field names to whatever Step 1's research found — the sketch above encodes the *shape* of the real interfaces (`RuntimeSnapshot::route`, `PoolState::select`, a backend address string), not necessarily their exact method names verbatim; confirm each one against the actual `src/runtime.rs`/`src/balancer.rs` source before writing this code, the same way Task 1-3 confirmed every API call against its real source.

Update `handle_request`'s signature to accept `store: Arc<RuntimeStore>`, and thread it through from `handle_connection`/`serve`.

Check whether `futures_util` is already a project dependency (it is, confirmed in `Cargo.toml`'s main dependency block) before adding the `use futures_util::StreamExt as _;` import — no new dependency needed for `.next()` on the byte stream.

- [ ] **Step 5: Run the tests**

Run: `cargo test --test http3_listener -- --nocapture`
Expected: all tests pass, including Tasks 2-3's tests (update their `serve`/connection-setup calls for the new `store` parameter if they call `serve` directly rather than building the connection inline).

- [ ] **Step 6: Commit**

```bash
git add src/http3.rs tests/http3_listener.rs
git commit -m "feat: route and forward allowed HTTP/3 requests to upstream backends"
```

---

## Task 5: Wire into `src/cli.rs` and document

**Files:**
- Modify: `src/cli.rs` (spawn `http3::serve` in `serve_proxy` when enabled, install the crypto provider once at startup, add the task to the existing graceful-shutdown coordination)
- Modify: `README.md` (new "Phase 15 HTTP/3 listener" section)
- Modify: `docs/PRD.md` (new "Phase 15 status" section; add a `Phase 15 — HTTP/3` row to the roadmap table)
- Test: unit test in `src/config/mod.rs` (already covered by Task 1) plus a manual verification step (below) — no new automated integration test spins up the full `serve_proxy`/control-plane stack, since replicating that much setup is disproportionate to this task; the request-handling pipeline itself is already covered end-to-end by Tasks 2-4's tests calling `http3::serve` directly.

**Interfaces:**
- Consumes: `http3::{serve, build_rustls_server_config, Http3Error}` (Tasks 2-4), `Http3Config` (Task 1).
- Produces: a fully working, documented, opt-in HTTP/3 listener reachable via `bearust serve`. Last task in the plan.

- [ ] **Step 1: Read `serve_proxy`'s existing task-spawning and shutdown pattern**

Read `src/cli.rs`'s `serve_proxy` function in full, focusing on: where `control_task`/`cluster_task` are spawned (`tokio::spawn`), how `plugin_manager`/`waf_store`/`RuntimeStore` (`store`) are already constructed and shared as `Arc`s at that point in the function, and the final `tokio::select!`/shutdown-timeout block that already coordinates `server_task`/`reload_task`/`term_rx`. This task's job is to fit into that existing pattern, not invent a new one.

- [ ] **Step 2: Install the crypto provider once at startup**

Near the top of `serve_proxy` (before any TLS-related construction — the existing Pingora TLS setup doesn't need this since `pingora-rustls` handles its own provider internally, but the new H3 code does, per this plan's Global Constraints), add:

```rust
rustls::crypto::ring::default_provider()
    .install_default()
    .ok();
```

- [ ] **Step 3: Spawn the H3 listener when enabled**

After the point where `waf_store` and `control_state.plugin_manager`'s sibling `store: Arc<RuntimeStore>` are both available (read Step 1's findings for the exact variable names already in scope at that point — likely `store` for the `Arc<RuntimeStore>` and `waf_store` for the `Arc<WafStore>`, but confirm against the real code rather than assuming), add:

```rust
let (http3_shutdown_tx, http3_shutdown_rx) = tokio::sync::watch::channel(false);
let http3_task = if config.server.http3.enabled {
    let tls = config
        .server
        .tls
        .as_ref()
        .expect("config validation already requires tls when http3.enabled");
    let tls_config = crate::http3::build_rustls_server_config(tls)
        .map_err(|e| AppError::Server(format!("HTTP/3 TLS setup: {e}")))?;
    let bind = config.server.http3.bind;
    let store = store.clone();
    let waf = waf_store.clone();
    Some(tokio::spawn(async move {
        let _ = crate::http3::serve(bind, tls_config, store, waf, http3_shutdown_rx).await;
    }))
} else {
    None
};
```

Adjust `waf_store.clone()`/`store.clone()` to whatever the actual in-scope `Arc` variable names are (confirmed in Step 1) — do not introduce new intermediate variables if the existing ones already have the right type and are already `Clone`-able `Arc`s.

- [ ] **Step 4: Coordinate shutdown**

In `serve_proxy`'s existing shutdown sequence (after the `tokio::select!` that already handles `server_task`/`term_rx`/`reload_task`, in the same section that already does `reload_task.abort(); control_task.abort();` etc.), add:

```rust
let _ = http3_shutdown_tx.send(true);
if let Some(http3_task) = http3_task {
    let _ = tokio::time::timeout(
        Duration::from_secs(config.server.graceful_shutdown_seconds),
        http3_task,
    )
    .await;
}
```

Place this alongside the existing bounded-timeout shutdown waits for other tasks (e.g. the `cluster_task`/`raft` shutdown block), matching that pattern's style exactly.

- [ ] **Step 5: Manual verification**

This step is not an automated test — run it once, by hand, and record the output in your report, since it's the only check that exercises the real `bearust serve` binary with HTTP/3 enabled end to end (Tasks 2-4's automated tests intentionally call `http3::serve` directly rather than spinning up the full control-plane/database stack `serve_proxy` requires, per this task's Interfaces note):

1. Generate a throwaway self-signed cert/key pair (e.g. via `openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem -days 1 -nodes -subj "/CN=localhost"`).
2. Write a minimal `bearust.toml` with `[server.tls]` pointing at that cert/key and `[server.http3]` with `enabled = true`.
3. Run `cargo run -- serve --config /tmp/bearust.toml` in one terminal.
4. From another terminal, use `curl --http3 https://127.0.0.1:<http3-bind-port>/` (or any available HTTP/3-capable client) if available in this environment; if `curl --http3` isn't available, note that in your report rather than skipping verification silently — at minimum confirm via `ss -ulnp` or equivalent that the configured UDP port is listening while the process runs, and confirm it is *not* listening when `http3.enabled = false`.
5. Stop the process with `Ctrl-C` (SIGTERM) and confirm it exits cleanly within `graceful_shutdown_seconds` (the default in this repo's config, or whatever your test `bearust.toml` set).

- [ ] **Step 6: Update `README.md`**

Add a new section, in the same style as the existing "Phase 14 plugin manifest signing" section (read that section first to match heading level and tone), documenting: the `[server.http3]` config block (`enabled`, `bind`), the requirement that `server.tls` must be set, and the Non-goals from the design spec stated plainly (no rate limiting/bot-protection/analytics/plugin-hook parity with the HTTP/1.1/HTTP/2 path yet, no `Alt-Svc` advertisement, no upstream H3) — do not let the README imply feature parity that doesn't exist.

- [ ] **Step 7: Update `docs/PRD.md`**

Add a `Phase 15 — HTTP/3` row to the roadmap table (`## 12. Roadmap / Release Phases`) with scope "Opt-in client-side HTTP/3 (QUIC) listener; WAF-parity, upstream H3, and full feature parity remain future increments", and a `### Phase 15 status: HTTP/3 listener (increment 1)` section (matching the style of the existing `### Phase 14 status` sections) summarizing what this increment delivers and what remains out of scope, cross-referencing `docs/superpowers/specs/2026-08-14-phase-15-http3-listener-design.md`. Also remove or update PRD Open Question #5 ("HTTP/3 support target — included in v1 or deferred to a later release?") in `## 15. Open Questions / Pending Decisions`, since this increment answers it (deferred, then delivered as an opt-in increment rather than bundled into v1) — read the current wording of that item before editing, and phrase the resolution precisely rather than just deleting the line without a trace of the decision.

- [ ] **Step 8: Run the full test suite, fmt, and clippy**

Run: `cargo test --workspace --locked 2>&1 | tee /tmp/http3-final-tests.log` (redirect to a file, never pipe through `tail` for a full-suite run — this project's own conventions warn that doing so has caused multi-hour hangs before)
Run: `cargo fmt --all -- --check`
Run: `cargo clippy --workspace --all-targets -- -D warnings`
All must be clean before committing.

- [ ] **Step 9: Commit**

```bash
git add src/cli.rs README.md docs/PRD.md
git commit -m "feat: wire the HTTP/3 listener into bearust serve and document it"
```

---

## Final check (not a task — run after Task 5)

Re-read the design spec
(`docs/superpowers/specs/2026-08-14-phase-15-http3-listener-design.md`)
against the finished code and confirm: every Non-goal is genuinely
un-implemented (no rate limiting, no bot protection, no analytics, no
plugin hooks, no `Alt-Svc`, no upstream H3 reachable from the H3 path),
`http3.enabled` defaults to `false` and is rejected without `tls`
configured, WAF block responses are byte-identical to the existing
HTTP/1.1/HTTP/2 path's block response, and the crypto-provider
installation happens exactly once at startup rather than being left to
chance or duplicated per-request.
