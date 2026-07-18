# BeaRust Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a production-usable HTTP/1.1 and WebSocket reverse proxy with host/path routing, round-robin and least-connections balancing, active health checks, validated hot reload, CLI operations, and Docker delivery.

**Architecture:** BeaRust is one modular Rust binary built on Pingora 0.8.1. Immutable runtime snapshots are published through `ArcSwap`; each request retains its starting snapshot while new requests see validated reloads. Routing, backend selection, probing, proxy callbacks, CLI lifecycle, and observability remain separate modules with explicit interfaces.

**Tech Stack:** Rust 1.84+, edition 2021; Pingora 0.8.1; Tokio; Clap; Serde/TOML; ArcSwap; tracing; Docker Compose; GitHub Actions.

## Global Constraints

- Linux x86_64 and ARM64 are the supported Phase 1 runtime targets.
- Downstream and upstream traffic is HTTP/1.1 only; HTTP/2 and TLS are deferred to Phase 2.
- Request and response bodies stream without whole-body buffering.
- WebSocket upgrade and bidirectional passthrough are required.
- Routing is exact normalized host followed by segment-aware longest path prefix.
- The only balancing algorithms are `round_robin` and `least_connections`; weighted balancing is rejected.
- A request may fail over once only before any bytes are sent upstream and is never retried after transmission starts.
- A new backend is ineligible until it reaches the configured consecutive-success threshold.
- Invalid reloads leave the active runtime snapshot unchanged.
- `X-Request-ID` accepts only 1–128 characters from `[A-Za-z0-9._:-]`; otherwise BeaRust generates a UUID.
- Production logs are JSON and never include request or response bodies.
- Production containers run as a non-root user.
- Every implementation task follows red-green-refactor TDD and ends in a focused commit.

---

## File Map

The implementation creates these focused units:

- `Cargo.toml`: package metadata and pinned dependency families.
- `rust-toolchain.toml`: minimum reproducible Rust toolchain.
- `src/lib.rs`: public module surface used by integration tests.
- `src/main.rs`: thin executable entry point.
- `src/config/mod.rs`: TOML types, defaults, loading, and validation orchestration.
- `src/config/error.rs`: actionable configuration error types.
- `src/router.rs`: normalized host and segment-aware longest-prefix routing.
- `src/balancer.rs`: backend state, health eligibility, round-robin, least-connections, and in-flight guards.
- `src/health.rs`: pure threshold state machine, TCP/HTTP probes, and worker supervision.
- `src/runtime.rs`: immutable runtime construction, `ArcSwap` publication, and state-preserving reload.
- `src/proxy.rs`: Pingora `ProxyHttp` callbacks, forwarding headers, peer selection, errors, and request completion.
- `src/reload.rs`: PID-file safety and Unix signal helpers.
- `src/cli.rs`: Clap command model and command dispatch.
- `src/observability.rs`: JSON/development subscriber setup and request-ID validation.
- `tests/support/mod.rs`: reusable local HTTP/WebSocket backend processes and free-port helpers.
- `tests/config_validation.rs`: public configuration validation contract.
- `tests/routing.rs`: public routing behavior.
- `tests/load_balancing.rs`: balancing and lease cleanup behavior.
- `tests/health_failover.rs`: probes, eligibility, `503`, and recovery.
- `tests/proxy_http.rs`: streaming, forwarding headers, `404`, failover safety, and request IDs.
- `tests/websocket.rs`: WebSocket upgrade and bidirectional messages.
- `tests/reload.rs`: valid/invalid reload and active-request continuity.
- `tests/shutdown.rs`: graceful termination behavior.
- `config/bearust.example.toml`: runnable example.
- `Dockerfile`, `Dockerfile.dev`: production and development images.
- `docker-compose.yml`, `docker-compose.dev.yml`: production and hot-reload development stacks.
- `.env.example`: image/config path and log defaults.
- `.github/workflows/ci.yml`: formatting, lint, test, and image build.
- `README.md`, `DEVELOPMENT.md`, `DEPLOY.md`: user, contributor, and operator documentation.
- `LICENSE-MIT`, `LICENSE-APACHE`: dual-license texts.

---

### Task 1: Bootstrap the Crate and Validated TOML Configuration

**Files:**
- Create: `Cargo.toml`
- Create: `rust-toolchain.toml`
- Create: `src/lib.rs`
- Create: `src/config/mod.rs`
- Create: `src/config/error.rs`
- Create: `tests/config_validation.rs`
- Create: `tests/fixtures/valid.toml`
- Create: `config/bearust.example.toml`

**Interfaces:**
- Produces: `config::load(path: &Path) -> Result<Config, ConfigError>`.
- Produces: `Config::parse(input: &str) -> Result<Config, ConfigError>`.
- Produces: `Config`, `ServerConfig`, `HealthConfig`, `PoolConfig`, `BackendConfig`, `RouteConfig`, `Algorithm`, and `HealthCheckKind`.
- `Config` and every nested type are `Clone + Debug + Deserialize + PartialEq`.

- [ ] **Step 1: Create package metadata and a compiling library shell**

Use this dependency baseline in `Cargo.toml`:

```toml
[package]
name = "bearust"
version = "0.1.0"
edition = "2021"
rust-version = "1.84"
license = "MIT OR Apache-2.0"
description = "Open source reverse proxy and load balancer"

[dependencies]
arc-swap = "1.7"
async-trait = "0.1"
clap = { version = "4.5", features = ["derive"] }
http = "1"
nix = { version = "0.29", features = ["process", "signal"] }
pingora-core = "0.8.1"
pingora-error = "0.8.1"
pingora-http = "0.8.1"
pingora-proxy = "0.8.1"
serde = { version = "1", features = ["derive"] }
thiserror = "2"
tokio = { version = "1", features = ["macros", "net", "rt-multi-thread", "signal", "sync", "time"] }
toml = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "fmt", "json"] }
uuid = { version = "1", features = ["v4"] }

[dev-dependencies]
axum = { version = "0.8", features = ["ws"] }
futures-util = "0.3"
reqwest = { version = "0.12", default-features = false, features = ["stream"] }
tempfile = "3"
tokio-tungstenite = "0.27"

[profile.release]
lto = "thin"
strip = true
```

Create `rust-toolchain.toml`:

```toml
[toolchain]
channel = "1.84.1"
components = ["clippy", "rustfmt"]
profile = "minimal"
```

Create `src/lib.rs`:

```rust
pub mod config;
```

- [ ] **Step 2: Write failing configuration contract tests**

In `tests/config_validation.rs`, cover a valid fixture and one focused test per invariant. Use this pattern, expanding the table to include duplicate route names, duplicate pool names, missing pool references, empty pools, unsupported algorithms, zero timeouts/thresholds, invalid backend addresses, missing HTTP health paths, non-slash paths, and duplicate normalized host/path pairs:

```rust
use bearust::config::{Algorithm, Config, HealthCheckKind};

const VALID: &str = include_str!("fixtures/valid.toml");

#[test]
fn parses_valid_configuration_and_defaults() {
    let config = Config::parse(VALID).expect("valid fixture");
    assert_eq!(config.server.bind.to_string(), "127.0.0.1:18080");
    assert_eq!(config.server.graceful_shutdown_seconds, 30);
    assert_eq!(config.health.healthy_threshold, 2);
    assert_eq!(config.upstream_pools[0].algorithm, Algorithm::LeastConnections);
    assert_eq!(
        config.upstream_pools[0].backends[0].health_check,
        HealthCheckKind::Http
    );
}

#[test]
fn rejects_route_that_references_missing_pool() {
    let invalid = VALID.replace("upstream_pool = \"api\"", "upstream_pool = \"missing\"");
    let error = Config::parse(&invalid).unwrap_err().to_string();
    assert!(error.contains("routes[0].upstream_pool"));
    assert!(error.contains("missing"));
}

#[test]
fn rejects_weight_field_in_phase_one() {
    let invalid = VALID.replace(
        "address = \"127.0.0.1:19001\"",
        "address = \"127.0.0.1:19001\"\nweight = 2",
    );
    assert!(Config::parse(&invalid).unwrap_err().to_string().contains("weight"));
}
```

- [ ] **Step 3: Run the tests and verify the red state**

Run:

```bash
cargo test --test config_validation
```

Expected: compilation fails because `bearust::config` types and `Config::parse` do not exist.

- [ ] **Step 4: Implement exact configuration types, defaults, and validation**

Define these public shapes in `src/config/mod.rs`:

```rust
#[derive(Clone, Debug, serde::Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub server: ServerConfig,
    #[serde(default)]
    pub health: HealthConfig,
    pub upstream_pools: Vec<PoolConfig>,
    pub routes: Vec<RouteConfig>,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    RoundRobin,
    LeastConnections,
}

#[derive(Clone, Copy, Debug, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum HealthCheckKind {
    Tcp,
    Http,
}
```

Use strongly typed `SocketAddr` for `server.bind` and backend addresses, `PathBuf` for `pid_file`, and `u64` seconds for serialized time values. Add defaults exactly matching the design: graceful shutdown `30`, PID file `./bearust.pid`, health interval `10`, health timeout `2`, unhealthy threshold `3`, healthy threshold `2`, connect timeout `3`, and request timeout `30`. Apply `#[serde(deny_unknown_fields)]` to every configuration struct so `weight` and misspelled fields fail parsing.

Define errors in `src/config/error.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("cannot read configuration {path}: {source}")]
    Read {
        path: std::path::PathBuf,
        source: std::io::Error,
    },
    #[error("invalid TOML: {0}")]
    Parse(#[from] toml::de::Error),
    #[error("{field}: {message}")]
    Validation { field: String, message: String },
}
```

Implement `Config::parse` as `toml::from_str` followed by `validate()`. Keep validation helpers small: `validate_server`, `validate_health`, `validate_pools`, and `validate_routes`. Normalize route hosts during validation using the router-independent helper `normalize_config_host`: lowercase, trim one trailing dot, parse bracketed IPv6 correctly, and remove a numeric port. Do not silently repair invalid paths.

- [ ] **Step 5: Add the runnable fixture and example**

Make `tests/fixtures/valid.toml` bind to `127.0.0.1:18080`, use pool `api` with `least_connections`, and include HTTP backend `127.0.0.1:19001` with `/health`. Make `config/bearust.example.toml` contain two backends and two routes, with comments explaining supported algorithms and checks.

- [ ] **Step 6: Run formatting, lint, and configuration tests**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --test config_validation
```

Expected: all commands exit `0`; the test binary reports all configuration tests passed.

- [ ] **Step 7: Commit the validated configuration slice**

```bash
git add Cargo.toml Cargo.lock rust-toolchain.toml src/lib.rs src/config tests/config_validation.rs tests/fixtures/valid.toml config/bearust.example.toml
git commit -m "feat: add validated TOML configuration"
```

---

### Task 2: Implement Host and Segment-Aware Path Routing

**Files:**
- Create: `src/router.rs`
- Modify: `src/lib.rs`
- Test: `tests/routing.rs`

**Interfaces:**
- Consumes: `config::RouteConfig`.
- Produces: `Router::new(routes: &[RouteConfig]) -> Router`.
- Produces: `Router::route(&self, authority: &str, path: &str) -> Option<&ResolvedRoute>`.
- Produces: `normalize_host(authority: &str) -> Option<String>`.
- `ResolvedRoute` exposes `name: String`, `host: String`, `path_prefix: String`, and `upstream_pool: String`.

- [ ] **Step 1: Write failing routing tests**

Create `tests/routing.rs` with explicit cases:

```rust
use bearust::{
    config::{Config, RouteConfig},
    router::{normalize_host, Router},
};

fn router(routes: Vec<RouteConfig>) -> Router {
    Router::new(&routes)
}

#[test]
fn normalizes_dns_host_case_trailing_dot_and_port() {
    assert_eq!(
        normalize_host("API.Example.COM.:8080").as_deref(),
        Some("api.example.com")
    );
}

#[test]
fn chooses_longest_segment_aware_prefix() {
    let config = Config::parse(include_str!("fixtures/routes.toml")).unwrap();
    let router = router(config.routes);
    assert_eq!(router.route("api.example.com", "/api/users").unwrap().name, "users");
    assert_eq!(router.route("api.example.com", "/apiv2"), None);
}

#[test]
fn rejects_unknown_host() {
    let config = Config::parse(include_str!("fixtures/routes.toml")).unwrap();
    assert!(router(config.routes).route("other.example.com", "/api").is_none());
}
```

Add `tests/fixtures/routes.toml` with `/`, `/api`, and `/api/users` routes for the same host.

- [ ] **Step 2: Run the routing test and verify failure**

Run:

```bash
cargo test --test routing
```

Expected: compilation fails because module `router` is not exported.

- [ ] **Step 3: Implement normalization and indexed route matching**

In `src/router.rs`, group routes by normalized host and sort each host’s vector by descending prefix length. Implement boundary matching exactly:

```rust
fn path_matches(prefix: &str, path: &str) -> bool {
    prefix == "/"
        || path == prefix
        || path
            .strip_prefix(prefix)
            .is_some_and(|remaining| remaining.starts_with('/'))
}
```

Use `http::uri::Authority` where possible and a dedicated bracketed-IPv6 branch. Return `None` for empty or syntactically invalid authority values. `Router::route` must not allocate except for host normalization.

Export the module in `src/lib.rs`:

```rust
pub mod config;
pub mod router;
```

- [ ] **Step 4: Run routing and configuration regression tests**

Run:

```bash
cargo test --test routing
cargo test --test config_validation
cargo clippy --all-targets -- -D warnings
```

Expected: all commands exit `0`.

- [ ] **Step 5: Commit routing**

```bash
git add src/lib.rs src/router.rs tests/routing.rs tests/fixtures/routes.toml
git commit -m "feat: route by host and longest path prefix"
```

---

### Task 3: Implement Concurrent Backend Selection

**Files:**
- Create: `src/balancer.rs`
- Modify: `src/lib.rs`
- Test: `tests/load_balancing.rs`

**Interfaces:**
- Consumes: `PoolConfig`, `BackendConfig`, and `Algorithm`.
- Produces: `PoolState::new(config: &PoolConfig) -> PoolState`.
- Produces: `PoolState::select(&Arc<Self>, excluded: Option<BackendId>) -> Option<BackendLease>`.
- Produces: `PoolState::set_healthy(id: BackendId, healthy: bool)`.
- `BackendId` is a stable newtype over `usize`.
- `BackendLease` exposes `id()`, `address() -> SocketAddr`, and decrements in-flight count on `Drop`.

- [ ] **Step 1: Write failing round-robin and least-connections tests**

Create `tests/load_balancing.rs`:

```rust
use std::sync::Arc;
use bearust::{balancer::PoolState, config::Config};

fn pool(algorithm: &str) -> Arc<PoolState> {
    let text = include_str!("fixtures/valid.toml")
        .replace("algorithm = \"least_connections\"", &format!("algorithm = \"{algorithm}\""));
    let mut config = Config::parse(&text).unwrap();
    config.upstream_pools[0].backends.push(config.upstream_pools[0].backends[0].clone());
    config.upstream_pools[0].backends[1].address = "127.0.0.1:19002".parse().unwrap();
    let pool = Arc::new(PoolState::new(&config.upstream_pools[0]));
    pool.set_healthy(0.into(), true);
    pool.set_healthy(1.into(), true);
    pool
}

#[test]
fn round_robin_rotates_healthy_backends() {
    let pool = pool("round_robin");
    let selected: Vec<_> = (0..4)
        .map(|_| pool.select(None).unwrap().address())
        .collect();
    assert_eq!(selected[0], selected[2]);
    assert_eq!(selected[1], selected[3]);
    assert_ne!(selected[0], selected[1]);
}

#[test]
fn least_connections_prefers_lower_inflight_and_drop_releases_count() {
    let pool = pool("least_connections");
    let held = pool.select(None).unwrap();
    let other = pool.select(None).unwrap();
    assert_ne!(held.id(), other.id());
    drop(held);
    drop(other);
    assert_eq!(pool.total_inflight(), 0);
}

#[test]
fn exclusion_prevents_immediate_failover_to_same_backend() {
    let pool = pool("round_robin");
    let first = pool.select(None).unwrap();
    let second = pool.select(Some(first.id())).unwrap();
    assert_ne!(first.id(), second.id());
}
```

Add concurrency tests using `std::thread::scope` that perform 10,000 selections and end with `total_inflight() == 0`.

- [ ] **Step 2: Run the balancing test and verify failure**

Run:

```bash
cargo test --test load_balancing
```

Expected: compilation fails because `balancer` does not exist.

- [ ] **Step 3: Implement atomic state and RAII leases**

Use this internal model:

```rust
struct BackendState {
    id: BackendId,
    address: std::net::SocketAddr,
    healthy: std::sync::atomic::AtomicBool,
    inflight: std::sync::atomic::AtomicUsize,
}

pub struct PoolState {
    name: String,
    algorithm: Algorithm,
    backends: Vec<Arc<BackendState>>,
    cursor: std::sync::atomic::AtomicUsize,
}

pub struct BackendLease {
    backend: Arc<BackendState>,
}
```

`select` first filters healthy, non-excluded backends. Round-robin uses `fetch_add(1, Relaxed)`. Least-connections reads all in-flight counters, finds the minimum, and uses the same rotating cursor among ties. Increment the chosen backend before returning its lease. `Drop` uses `fetch_sub(1, AcqRel)` and debug-asserts that the prior value was non-zero.

Implement `From<usize> for BackendId`, `BackendId: Copy + Eq + Hash`, `PoolState::backend_ids`, `PoolState::backend_address`, `PoolState::is_healthy`, and `PoolState::total_inflight` to support health workers and tests.

- [ ] **Step 4: Run focused and concurrent tests**

Run:

```bash
cargo test --test load_balancing
cargo test --test routing
cargo clippy --all-targets -- -D warnings
```

Expected: all commands exit `0`, including the 10,000-selection cleanup test.

- [ ] **Step 5: Commit balancing**

```bash
git add src/lib.rs src/balancer.rs tests/load_balancing.rs
git commit -m "feat: add concurrent backend balancing"
```

---

### Task 4: Add Thresholded TCP and HTTP Health Checks

**Files:**
- Create: `src/health.rs`
- Modify: `src/lib.rs`
- Modify: `src/balancer.rs`
- Test: `tests/health_failover.rs`
- Create: `tests/support/mod.rs`

**Interfaces:**
- Consumes: `Arc<PoolState>`, `HealthConfig`, and backend check definitions.
- Produces: `HealthTracker::new(healthy_threshold, unhealthy_threshold)`.
- Produces: `HealthTracker::record(success: bool) -> Option<HealthTransition>`.
- Produces: `probe_tcp(address, timeout) -> bool`.
- Produces: `probe_http(address, path, timeout) -> bool`.
- Produces: `HealthSupervisor::start(pools, config).await -> Result<HealthSupervisor, HealthError>`.
- Produces: `HealthSupervisor::shutdown(self).await`.

- [ ] **Step 1: Write the pure state-machine tests**

Add these cases to `tests/health_failover.rs`:

```rust
use bearust::health::{HealthState, HealthTracker, HealthTransition};

#[test]
fn new_backend_requires_success_threshold() {
    let mut tracker = HealthTracker::new(2, 3);
    assert_eq!(tracker.state(), HealthState::Probing);
    assert_eq!(tracker.record(true), None);
    assert_eq!(tracker.record(true), Some(HealthTransition::BecameHealthy));
}

#[test]
fn healthy_backend_requires_consecutive_failures() {
    let mut tracker = HealthTracker::new(1, 3);
    tracker.record(true);
    assert_eq!(tracker.record(false), None);
    assert_eq!(tracker.record(true), None);
    assert_eq!(tracker.record(false), None);
    assert_eq!(tracker.record(false), None);
    assert_eq!(tracker.record(false), Some(HealthTransition::BecameUnhealthy));
}
```

- [ ] **Step 2: Run the test and verify failure**

Run:

```bash
cargo test --test health_failover
```

Expected: compilation fails because module `health` does not exist.

- [ ] **Step 3: Implement the threshold state machine**

Implement `HealthState::{Probing, Healthy, Unhealthy}` and `HealthTransition::{BecameHealthy, BecameUnhealthy}`. On success, reset failures; on failure, reset successes. Only emit a transition when state changes. Thresholds are `std::num::NonZeroU32` internally.

- [ ] **Step 4: Write failing async probe tests**

In `tests/support/mod.rs`, provide:

```rust
pub async fn spawn_http_backend(
    health_status: Arc<AtomicU16>,
    response_body: &'static str,
) -> TestServer;

pub struct TestServer {
    pub address: SocketAddr,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
}
```

Use an Axum listener bound to `127.0.0.1:0`; `/health` returns the atomic status and all other paths return `response_body`. Add tests that prove TCP success, refused-port failure, HTTP `204` success, HTTP `503` failure, and timeout failure.

- [ ] **Step 5: Implement probes and the supervisor**

`probe_tcp` wraps `TcpStream::connect` in `tokio::time::timeout`. `probe_http` opens a `TcpStream`, writes a minimal HTTP/1.1 request with `Connection: close`, reads only enough bytes to parse the status line, accepts `200..=299`, and enforces the same overall timeout. This avoids introducing a second production HTTP client.

`HealthSupervisor` owns a `CancellationToken` equivalent built from `tokio::sync::watch`; spawn one task per backend. The first probe runs immediately, then uses `tokio::time::interval`. After every transition, call `pool.set_healthy` and emit a tracing event. Shutdown sends cancellation and joins every task.

- [ ] **Step 6: Add an end-to-end eligibility transition test**

Start one backend with status `503`, start the supervisor with 10 ms intervals and thresholds of one, assert selection returns `None`, flip status to `204`, wait with a bounded retry loop, assert the pool becomes selectable, flip back to `503`, and assert it leaves rotation. The whole test must use a one-second timeout to prevent hangs.

- [ ] **Step 7: Run health and balancing regressions**

Run:

```bash
cargo test --test health_failover
cargo test --test load_balancing
cargo clippy --all-targets -- -D warnings
```

Expected: all commands exit `0`.

- [ ] **Step 8: Commit health checking**

```bash
git add src/lib.rs src/health.rs src/balancer.rs tests/health_failover.rs tests/support
git commit -m "feat: add active backend health checks"
```

---

### Task 5: Build Atomic Runtime Snapshots and State-Preserving Reload

**Files:**
- Create: `src/runtime.rs`
- Modify: `src/lib.rs`
- Modify: `src/router.rs`
- Modify: `src/health.rs`
- Test: `tests/reload.rs`

**Interfaces:**
- Consumes: validated `Config`.
- Produces: `RuntimeSnapshot::build(config, previous) -> Result<RuntimeSnapshot, RuntimeError>`.
- Produces: `RuntimeSnapshot::route(authority, path) -> Option<(&ResolvedRoute, Arc<PoolState>)>`.
- Produces: `RuntimeStore::new(snapshot)`, `RuntimeStore::load() -> Arc<RuntimeSnapshot>`.
- Produces: `RuntimeStore::reload(path).await -> Result<ReloadOutcome, RuntimeError>`.
- `ReloadOutcome` contains old and new generation numbers.

- [ ] **Step 1: Write failing snapshot and reload tests**

In `tests/reload.rs`, test generation publication and rejection:

```rust
#[tokio::test]
async fn invalid_reload_keeps_current_generation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let store = RuntimeStore::from_path(&path).await.unwrap();
    let before = store.load();

    std::fs::write(&path, "[server]\nbind = \"broken\"").unwrap();
    assert!(store.reload(&path).await.is_err());
    assert_eq!(store.load().generation(), before.generation());
    assert!(Arc::ptr_eq(&store.load(), &before));
}
```

Also test that a successful reload increments generation, an `Arc` held before reload remains usable, unchanged backend identity retains health, and changed health definitions reset to probing.

- [ ] **Step 2: Run the reload test and verify failure**

Run:

```bash
cargo test --test reload
```

Expected: compilation fails because `runtime` does not exist.

- [ ] **Step 3: Implement immutable snapshots and atomic publication**

Use this shape:

```rust
pub struct RuntimeSnapshot {
    generation: u64,
    config: Arc<Config>,
    router: Router,
    pools: HashMap<String, Arc<PoolState>>,
}

pub struct RuntimeStore {
    current: arc_swap::ArcSwap<RuntimeSnapshot>,
    reload_lock: tokio::sync::Mutex<()>,
    health: tokio::sync::Mutex<HealthSupervisor>,
}
```

Build the complete candidate snapshot and replacement supervisor before `ArcSwap::store`. Serialize reloads with `reload_lock`. Use a backend identity key containing pool name, address, health kind, and health path. Copy health eligibility only when that identity is unchanged. After publication, stop the old supervisor outside the atomic critical section.

If candidate construction or worker startup fails, shut down candidate workers and return without publishing.

- [ ] **Step 4: Run reload, health, routing, and balancing tests**

Run:

```bash
cargo test --test reload
cargo test --test health_failover
cargo test --test routing
cargo test --test load_balancing
```

Expected: all commands exit `0`.

- [ ] **Step 5: Commit runtime snapshots**

```bash
git add src/lib.rs src/runtime.rs src/router.rs src/health.rs tests/reload.rs
git commit -m "feat: publish atomic runtime snapshots"
```

---

### Task 6: Integrate Pingora Proxying and Forwarding Semantics

**Files:**
- Create: `src/proxy.rs`
- Create: `src/observability.rs`
- Modify: `src/lib.rs`
- Modify: `src/runtime.rs`
- Create: `tests/proxy_http.rs`
- Create: `tests/websocket.rs`

**Interfaces:**
- Consumes: `Arc<RuntimeStore>`.
- Produces: `BeaRustProxy::new(runtime: Arc<RuntimeStore>)`.
- Produces: `RequestContext` containing snapshot, matched route, backend lease, request ID, start time, and `upstream_started`.
- Implements: `pingora_proxy::ProxyHttp<CTX = RequestContext>`.
- Produces: `validated_request_id(value: Option<&[u8]>) -> String`.

- [ ] **Step 1: Write failing request-ID and forwarding-header unit tests**

Create direct tests for:

```rust
#[test]
fn accepts_only_bounded_safe_request_ids() {
    assert_eq!(validated_request_id(Some(b"abc-123:_.")), "abc-123:_.");
    assert_ne!(validated_request_id(Some(b"has space")), "has space");
    assert_ne!(validated_request_id(Some(&vec![b'a'; 129])), "a".repeat(129));
}
```

Test header mutation with an initial `X-Forwarded-For: 10.0.0.1`, client `192.0.2.10`, and expected result `10.0.0.1, 192.0.2.10`; assert `X-Forwarded-Proto: http`, preserved `Host`, and the chosen request ID.

- [ ] **Step 2: Run the proxy test and verify failure**

Run:

```bash
cargo test --test proxy_http
```

Expected: compilation fails because `proxy` and `observability` do not exist.

- [ ] **Step 3: Implement request context and Pingora callbacks**

Implement these callbacks against Pingora 0.8.1:

```rust
#[async_trait::async_trait]
impl pingora_proxy::ProxyHttp for BeaRustProxy {
    type CTX = RequestContext;

    fn new_ctx(&self) -> Self::CTX;

    async fn request_filter(
        &self,
        session: &mut pingora_proxy::Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<bool>;

    async fn upstream_peer(
        &self,
        session: &mut pingora_proxy::Session,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<Box<pingora_core::upstreams::peer::HttpPeer>>;

    async fn upstream_request_filter(
        &self,
        session: &mut pingora_proxy::Session,
        upstream_request: &mut pingora_http::RequestHeader,
        ctx: &mut Self::CTX,
    ) -> pingora_core::Result<()>;

    async fn logging(
        &self,
        session: &mut pingora_proxy::Session,
        error: Option<&pingora_core::Error>,
        ctx: &mut Self::CTX,
    );
}
```

At `request_filter`, load exactly one snapshot, route the request, and return a plain `404` through `session.respond_error(404)` when unmatched. At `upstream_peer`, select a backend lease; return plain `503` when none is eligible. Construct `HttpPeer::new(address, false, String::new())` because Phase 1 upstreams are cleartext.

Store the lease in context until `logging` runs. Apply connection and request timeouts from the selected pool to the peer. Configure Pingora retries to one additional peer only when its failure context proves no upstream write began; otherwise return the original failure.

At `upstream_request_filter`, preserve `Host`, update forwarded headers, and mark `upstream_started = true` immediately before Pingora writes upstream headers. WebSocket upgrades remain on Pingora’s normal streaming path.

- [ ] **Step 4: Write local-process HTTP proxy integration tests**

Extend `tests/support/mod.rs` with `spawn_bearust(config_path) -> TestProcess`, which launches `CARGO_BIN_EXE_bearust`, waits for its listener with a bounded TCP loop, captures stdout/stderr, and kills the child in `Drop`.

In `tests/proxy_http.rs`, add tests for:

- host/path routing to distinct backend bodies;
- `404` for unknown host;
- `503` when all checks fail;
- a 2 MiB streamed body whose backend observes chunks before the client finishes sending;
- forwarding headers and generated request ID;
- one pre-send connection failover;
- no retry when the first backend closes after reading request headers.

Every request uses an explicit `Host` header and a five-second test timeout.

- [ ] **Step 5: Write WebSocket integration test**

Start an Axum WebSocket echo backend, connect through BeaRust using `tokio_tungstenite::connect_async` with the routed `Host`, send text and binary frames in both directions, assert equality, then close cleanly.

- [ ] **Step 6: Run proxy and WebSocket tests**

Run:

```bash
cargo test --test proxy_http --test websocket
cargo clippy --all-targets -- -D warnings
```

Expected: HTTP integration cases pass; WebSocket text, binary, ping/pong, and close behavior pass.

- [ ] **Step 7: Commit proxy behavior**

```bash
git add src/lib.rs src/proxy.rs src/observability.rs src/runtime.rs tests/proxy_http.rs tests/websocket.rs tests/support
git commit -m "feat: proxy HTTP and WebSocket traffic"
```

---

### Task 7: Add CLI, PID Safety, Reload Signal, and Graceful Shutdown

**Files:**
- Create: `src/main.rs`
- Create: `src/cli.rs`
- Create: `src/reload.rs`
- Modify: `src/lib.rs`
- Modify: `src/proxy.rs`
- Test: `tests/cli.rs`
- Test: `tests/reload.rs`
- Create: `tests/shutdown.rs`

**Interfaces:**
- Produces: `cli::Cli` with `Serve`, `Validate`, and `Reload` subcommands.
- Produces: `reload::PidFileGuard::acquire(path) -> Result<PidFileGuard, PidError>`.
- Produces: `reload::signal_reload(path) -> Result<(), PidError>`.
- Produces: `cli::run(cli) -> Result<(), AppError>`.

- [ ] **Step 1: Write failing CLI contract tests**

In `tests/cli.rs`, execute the compiled binary and assert:

```rust
#[test]
fn validate_accepts_valid_file_without_opening_listener() {
    let output = Command::new(env!("CARGO_BIN_EXE_bearust"))
        .args(["validate", "--config", "tests/fixtures/valid.toml"])
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("configuration is valid"));
}

#[test]
fn validate_reports_actionable_invalid_field() {
    // Write a temp config with upstream_pool = "missing".
    // Assert non-zero status and stderr containing routes[0].upstream_pool.
}
```

Also assert `--version`, missing files, stale PID replacement, live PID rejection, and reload of a nonexistent process.

- [ ] **Step 2: Run CLI tests and verify failure**

Run:

```bash
cargo test --test cli
```

Expected: Cargo reports no binary target or the subcommands are unimplemented.

- [ ] **Step 3: Implement Clap commands and PID-file safety**

Use this command model:

```rust
#[derive(clap::Parser)]
#[command(name = "bearust", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(clap::Subcommand)]
pub enum Command {
    Serve {
        #[arg(long, default_value = "bearust.toml")]
        config: PathBuf,
        #[arg(long, default_value_t = false)]
        json_logs: bool,
    },
    Validate {
        #[arg(long, default_value = "bearust.toml")]
        config: PathBuf,
    },
    Reload {
        #[arg(long, default_value = "./bearust.pid")]
        pid_file: PathBuf,
    },
}
```

`PidFileGuard::acquire` uses create-new semantics. If a file exists, parse its positive PID and call `kill(pid, None)` to test liveness. Reject a live PID; remove and replace a stale or malformed file. Write the current PID, flush it, and remove only the same owned file on `Drop`. `signal_reload` reads a positive PID, verifies it is live, and sends `SIGHUP`.

- [ ] **Step 4: Wire Pingora service startup and signal handling**

`main.rs` only parses and reports errors:

```rust
fn main() {
    if let Err(error) = bearust::cli::run(bearust::cli::Cli::parse()) {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
```

For `serve`, load the initial runtime, acquire its configured PID file, initialize logging, create `pingora_core::server::Server`, create `http_proxy_service`, call `add_tcp(config.server.bind)`, add the service, and bootstrap it.

Install a Unix `SIGHUP` task that calls `RuntimeStore::reload` and logs success/failure. Integrate `SIGINT`/`SIGTERM` with Pingora graceful shutdown; stop accepting connections, wait up to `graceful_shutdown_seconds`, then shut down health workers. Ensure signal tasks stop when the server exits.

- [ ] **Step 5: Add process-level reload and shutdown tests**

Extend `tests/reload.rs` to start the binary, hold a slow request, replace the file with a second valid route/backend, run `bearust reload --pid-file ...`, and prove:

- the slow request completes through the old backend;
- a new request reaches the new backend;
- an invalid subsequent config leaves the new backend active.

In `tests/shutdown.rs`, hold a backend response for 200 ms, send `SIGTERM`, prove new connections are rejected, prove the active request completes, and prove the process exits successfully before a two-second bound.

- [ ] **Step 6: Run lifecycle tests**

Run:

```bash
cargo test --test cli --test reload --test shutdown
cargo test --test proxy_http --test websocket
cargo clippy --all-targets -- -D warnings
```

Expected: every command exits `0`; no child process remains after tests.

- [ ] **Step 7: Commit lifecycle operations**

```bash
git add src/main.rs src/cli.rs src/reload.rs src/lib.rs src/proxy.rs tests/cli.rs tests/reload.rs tests/shutdown.rs
git commit -m "feat: add CLI reload and graceful shutdown"
```

---

### Task 8: Complete Structured Observability and Error Hygiene

**Files:**
- Modify: `src/observability.rs`
- Modify: `src/proxy.rs`
- Modify: `src/health.rs`
- Modify: `src/runtime.rs`
- Create: `tests/observability.rs`

**Interfaces:**
- Consumes: proxy request context and lifecycle events.
- Produces: `observability::init(json: bool, filter: &str) -> Result<(), InitError>`.
- Produces stable event names: `request_complete`, `health_transition`, `reload_complete`, `reload_rejected`, `server_start`, and `server_stop`.

- [ ] **Step 1: Write failing log-contract tests**

Start BeaRust with `--json-logs` and `RUST_LOG=info`, make one successful request and one unmatched request, then parse every stdout line as JSON. Assert `request_complete` contains `request_id`, `route`, `upstream`, `status`, and `latency_ms`; assert the unmatched request has status `404` and no internal error body. Send a body containing `super-secret-body` and assert that string never appears in stdout or stderr.

- [ ] **Step 2: Run observability test and verify failure**

Run:

```bash
cargo test --test observability
```

Expected: failure because stable JSON fields/events are incomplete.

- [ ] **Step 3: Implement stable structured events**

Initialize `tracing_subscriber` with `EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into())`. Use `.json().flatten_event(true)` in production mode and compact formatting otherwise.

Emit:

```rust
tracing::info!(
    event = "request_complete",
    request_id = %ctx.request_id,
    route = ctx.route_name.as_deref().unwrap_or(""),
    upstream = ctx.upstream.map(|a| a.to_string()).as_deref().unwrap_or(""),
    status = session.response_written().map(|h| h.status.as_u16()).unwrap_or(0),
    latency_ms = ctx.started.elapsed().as_millis() as u64,
    error_category = error.map(classify_error).unwrap_or(""),
);
```

Use fixed error categories: `routing`, `no_healthy_upstream`, `connect`, `timeout`, `upstream`, `client`, and `internal`. Never record headers wholesale or any body bytes. Log health only on transitions and reload once per attempt.

- [ ] **Step 4: Run log and full regression tests**

Run:

```bash
cargo test --test observability
cargo test
cargo fmt --check
cargo clippy --all-targets -- -D warnings
```

Expected: all commands exit `0`.

- [ ] **Step 5: Commit observability**

```bash
git add src/observability.rs src/proxy.rs src/health.rs src/runtime.rs tests/observability.rs
git commit -m "feat: add structured operational logging"
```

---

### Task 9: Add Containers, CI, Licenses, and Operator Documentation

**Files:**
- Create: `Dockerfile`
- Create: `Dockerfile.dev`
- Create: `docker-compose.yml`
- Create: `docker-compose.dev.yml`
- Create: `.dockerignore`
- Create: `.env.example`
- Create: `.github/workflows/ci.yml`
- Create: `LICENSE-MIT`
- Create: `LICENSE-APACHE`
- Create: `README.md`
- Create: `DEVELOPMENT.md`
- Create: `DEPLOY.md`
- Modify: `.gitignore`

**Interfaces:**
- Production image command: `bearust serve --config /etc/bearust/bearust.toml --json-logs`.
- Production ports: proxy `8080`.
- Production config mount: `./config/bearust.toml:/etc/bearust/bearust.toml:ro`.
- Development port: proxy `8080`.

- [ ] **Step 1: Write container smoke-test expectations**

Add `scripts/smoke-test.sh` with:

```bash
#!/usr/bin/env bash
set -euo pipefail

docker compose up -d --build
trap 'docker compose down --remove-orphans' EXIT

container_id="$(docker compose ps -q bearust)"
for _ in $(seq 1 30); do
  if test "$(docker inspect --format '{{.State.Health.Status}}' "$container_id")" = "healthy"; then
    exit 0
  fi
  sleep 1
done

docker compose logs bearust
exit 1
```

- [ ] **Step 2: Create the production and development images**

Use a Rust `1.84.1-bookworm` builder, install only `clang`, `cmake`, `make`, `perl`, and `pkg-config`, build with `cargo build --release --locked`, then copy the binary into `debian:bookworm-slim`. Create UID/GID `10001`, install `ca-certificates` and `netcat-openbsd`, copy `/usr/local/bin/bearust`, create `/run/bearust`, set it as `WORKDIR`, and run as `bearust`.

The production health check is:

```dockerfile
HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
  CMD-SHELL test -s /run/bearust/bearust.pid \
    && kill -0 "$(cat /run/bearust/bearust.pid)" \
    && nc -z 127.0.0.1 8080
```

`Dockerfile.dev` uses the same Rust version, installs `cargo-watch`, sets `/app`, and runs:

```dockerfile
CMD ["cargo", "watch", "-x", "run -- serve --config /etc/bearust/bearust.toml"]
```

- [ ] **Step 3: Create Compose configurations**

`docker-compose.yml` must:

- build `Dockerfile`;
- publish `${BEARUST_PORT:-8080}:8080`;
- mount `${BEARUST_CONFIG:-./config/bearust.example.toml}` read-only;
- set `RUST_LOG=${RUST_LOG:-info}`;
- set `working_dir: /run/bearust`, matching the example’s relative PID file;
- use `read_only: true`, `tmpfs: [/tmp, /run/bearust]`, `cap_drop: [ALL]`, and `security_opt: [no-new-privileges:true]`;
- restart `unless-stopped`.

`docker-compose.dev.yml` mounts the repository and Cargo caches, publishes `8080`, sets `RUST_LOG=debug`, and uses the development image.

- [ ] **Step 4: Add CI and exact verification jobs**

Create `.github/workflows/ci.yml` triggered on pushes and pull requests with:

```yaml
jobs:
  rust:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@1.84.1
        with:
          components: rustfmt, clippy
      - uses: Swatinem/rust-cache@v2
      - run: cargo fmt --check
      - run: cargo clippy --all-targets -- -D warnings
      - run: cargo test --locked
  container:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: docker compose config
      - run: docker build -t bearust:test .
      - run: docker run --rm bearust:test --version
```

- [ ] **Step 5: Write user and operator documentation**

`README.md` includes `docs/logo.png`, the Phase 1 feature list and exclusions, a five-minute Compose quick start, one curl example with `Host`, configuration reference, reload command, test commands, roadmap link, and license statement.

`DEVELOPMENT.md` documents native prerequisites, the missing-local-Rust fallback through `docker compose -f docker-compose.dev.yml`, test layout, formatting/linting commands, and focused TDD workflow.

`DEPLOY.md` documents non-root container operation, read-only config mount, port mapping, `SIGHUP` reload, graceful shutdown, log fields, backend health semantics, `404`/`503` troubleshooting, and rollback to the previous image/config.

Copy the canonical MIT and Apache-2.0 license texts into their respective files. Extend `.gitignore` with `/target`, `*.pid`, `.env`, and editor/OS artifacts while retaining `.superpowers/`.

- [ ] **Step 6: Run final native and container verification**

Run:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
docker compose config
docker build -t bearust:test .
docker run --rm bearust:test --version
bash scripts/smoke-test.sh
```

Expected: every command exits `0`; the image reports version `0.1.0`; the smoke test reaches a healthy validation state and cleans up its containers.

- [ ] **Step 7: Commit delivery assets**

```bash
git add Dockerfile Dockerfile.dev docker-compose.yml docker-compose.dev.yml .dockerignore .env.example .github .gitignore LICENSE-MIT LICENSE-APACHE README.md DEVELOPMENT.md DEPLOY.md scripts/smoke-test.sh
git commit -m "docs: add Phase 1 deployment and operations"
```

---

### Task 10: Run the Phase 1 Acceptance Gate

**Files:**
- Modify only files required to correct acceptance failures.
- Record no generated build artifacts.

**Interfaces:**
- Consumes all prior tasks.
- Produces a verified Phase 1 working tree and evidence for completion.

- [ ] **Step 1: Run the complete quality gate from a clean process state**

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
docker compose config
docker build -t bearust:phase1 .
docker run --rm bearust:phase1 --version
```

Expected: all commands exit `0`, all tests pass, and the image prints `bearust 0.1.0`.

- [ ] **Step 2: Run the operator acceptance scenario**

Start two labeled test backends, configure one round-robin route and one least-connections route, start BeaRust through Compose, then verify:

```bash
curl --fail --header 'Host: api.example.com' http://127.0.0.1:8080/v1/whoami
curl --fail --header 'Host: api.example.com' http://127.0.0.1:8080/v1/whoami
curl --fail --header 'Host: unknown.example.com' \
  --output /dev/null --write-out '%{http_code}\n' \
  http://127.0.0.1:8080/
```

Expected: the first two responses demonstrate backend rotation and the unknown host prints `404`. Stop both backends and expect `503`; restart one backend and wait for its healthy threshold, then expect `200`.

- [ ] **Step 3: Verify reload continuity**

Hold a slow request open, change only its route’s upstream pool in TOML, run:

```bash
docker compose exec -T bearust bearust reload --pid-file /run/bearust/bearust.pid
```

Expected: the held request completes through the old backend; a new request reaches the replacement backend. Repeat with invalid TOML and prove new requests continue using the last valid snapshot.

- [ ] **Step 4: Verify graceful shutdown and cleanup**

Run:

```bash
docker compose stop -t 30 bearust
docker compose down --remove-orphans
git status --short
```

Expected: active traffic finishes inside 30 seconds, containers are removed, and Git reports no generated or modified files.

- [ ] **Step 5: Commit only if acceptance required corrections**

If and only if tracked files changed to fix a verified failure:

```bash
git add <exact corrected files>
git commit -m "fix: satisfy Phase 1 acceptance gate"
```

If no correction was needed, do not create an empty commit.
