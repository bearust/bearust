# Phase 13G: Custom Load-Balancing Hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `balance.select`, the plugin system's first backend-selection hook: a plugin can pick which upstream backend serves a request, for pools whose `algorithm` is set to `plugin`.

**Architecture:** A new `Algorithm::Plugin` config variant opts a pool in per-pool. `upstream_peer` (already `async fn`) builds a bounded candidate list + request metadata, calls the plugin via `spawn_blocking` (13E's pattern, not 13F's `block_in_place` — no synchronous-trait-method constraint here), and falls back to the pool's existing `RoundRobin`-equivalent selection on any failure or invalid pick.

**Tech Stack:** Rust, wasmtime 27.0.0, pingora-proxy 0.8.1, tokio `spawn_blocking`.

## Global Constraints

- Reuse `abi_version: 2` and the existing alloc/write/call/read/dealloc guest memory convention — no new ABI version.
- `balance.select` capability requires `abi_version: 2`, exactly like the other four data-carrying capabilities.
- Exactly one active `balance.select` plugin across the whole proxy: the lowest-ID (BTreeMap key order) enabled plugin declaring the capability — same selection rule as every other capability. Every pool with `algorithm: plugin` is routed through that same plugin.
- `MAX_BALANCE_CANDIDATES: usize = 128` — the candidate list sent to the plugin is capped at this many backends.
- `MIN_BALANCE_INPUT_BYTES: usize = 49_152` (48 KiB) — the manifest-validation floor a `balance.select` plugin's `max_output_bytes` must meet. Fits comfortably under the default `PluginPolicy::max_output_bytes` ceiling (64 KiB) — unlike Phase 13F, this phase does **not** require raising any config ceiling.
- The plugin can only ever pick a backend the host already knows about and currently considers healthy — the host validates the plugin's `backend_id` via `select_specific` before ever leasing it. It can never violate the failover-exclusion invariant (`excluded_backend_id`): the host enforces that, never trusting the plugin.
- Fail-open on every error class: no plugin manager, no active plugin, disabled plugin, trap, fuel exhaustion, timeout, malformed output, a `spawn_blocking` join failure, or a `backend_id` that's unhealthy/excluded/nonexistent. Every failure path falls back to `pool.select(excluded)` (the pool's existing `RoundRobin`/`LeastConnections` logic — for a `Plugin`-configured pool, `select()`'s `Algorithm::Plugin` arm behaves identically to `RoundRobin`), logs `tracing::warn!(event = "balance_select_failed", reason = ...)`, and increments `record_balance_failure()`.
- Pools whose `algorithm` isn't `Plugin` are completely unaffected by any code in this plan — no plugin invocation, no metrics touched, behavior identical to today.
- New Prometheus counters: `bearust_plugins_balance_invocations_total`, `bearust_plugins_balance_applied_total`, `bearust_plugins_balance_failures_total`.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace --locked` must all be clean before any task is considered done.
- Design spec: `docs/superpowers/specs/2026-08-12-phase-13g-load-balancing-hooks-design.md` (read this first if anything below is ambiguous — it is the source of truth this plan implements).
- **Layering refinement over the spec** (decided during plan-writing, not a spec change): `PoolState::candidates()` returns a new balancer-local type, `balancer::BackendSnapshot { id: BackendId, address: SocketAddr, healthy: bool, inflight: usize }` — **not** the plugin SDK's `BackendCandidate` type directly. `src/balancer.rs` has no dependency on `bearust_plugin_sdk` today (it doesn't know about the plugin system at all, same as it doesn't know about WAF or transforms), and this plan preserves that separation. `src/proxy.rs` converts each `BackendSnapshot` into `bearust_plugin_sdk::BackendCandidate` when building the wire request.

---

## Task 1: SDK wire types

**Files:**
- Modify: `crates/bearust-plugin-sdk/src/lib.rs`

**Interfaces:**
- Produces: `bearust_plugin_sdk::BackendCandidate { id: u64, address: String, healthy: bool, inflight: u32 }`, `bearust_plugin_sdk::LoadBalanceRequest { pool: String, method: String, path: String, query: String, headers: Vec<(String, String)>, backends: Vec<BackendCandidate>, excluded_backend_id: Option<u64> }`, `bearust_plugin_sdk::LoadBalanceResult { backend_id: u64 }` — all `Debug + Clone + Serialize + Deserialize + PartialEq + Eq`, consumed by Task 4 (`src/plugin_runtime.rs`) and Task 5 (`src/proxy.rs`).

- [ ] **Step 1: Write the failing round-trip tests**

Add to the `#[cfg(test)] mod tests` block in `crates/bearust-plugin-sdk/src/lib.rs`, at the end of the existing tests:

```rust
    #[test]
    fn load_balance_request_round_trips() {
        let value = LoadBalanceRequest {
            pool: "api".into(),
            method: "GET".into(),
            path: "/orders".into(),
            query: String::new(),
            headers: vec![("host".into(), "example.com".into())],
            backends: vec![
                BackendCandidate {
                    id: 0,
                    address: "127.0.0.1:19001".into(),
                    healthy: true,
                    inflight: 2,
                },
                BackendCandidate {
                    id: 1,
                    address: "127.0.0.1:19002".into(),
                    healthy: false,
                    inflight: 0,
                },
            ],
            excluded_backend_id: Some(1),
        };
        let bytes = encode(&value);
        let decoded: LoadBalanceRequest = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn load_balance_result_round_trips() {
        let value = LoadBalanceResult { backend_id: 0 };
        let bytes = encode(&value);
        let decoded: LoadBalanceResult = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }
```

- [ ] **Step 2: Run the tests to verify they fail to compile**

Run: `cargo test -p bearust-plugin-sdk load_balance_request_round_trips`
Expected: FAIL — `LoadBalanceRequest`/`BackendCandidate`/`LoadBalanceResult` are not yet defined.

- [ ] **Step 3: Add the wire types**

Add to `crates/bearust-plugin-sdk/src/lib.rs`, at the end of the file (after the existing `TransformResponseResult` struct):

```rust
/// One upstream backend as a `balance.select` plugin sees it: a live
/// snapshot from the host, never plugin-supplied. `id` is the backend's
/// stable index within its pool (`balancer::BackendId`, widened to `u64`
/// for the wire format); `address` is `host:port`; `healthy` mirrors the
/// host's current live health-check state; `inflight` is the backend's
/// current in-flight request count (as `LeastConnections` already uses
/// internally).
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BackendCandidate {
    pub id: u64,
    pub address: String,
    pub healthy: bool,
    pub inflight: u32,
}

/// Input to `bearust_balance_select`. `pool` names the upstream pool this
/// selection is for (a single active plugin may serve several
/// `algorithm: plugin` pools; this field lets it branch per pool).
/// `method`/`path`/`query`/`headers` share the same
/// `MAX_NORMALIZED_METADATA_BYTES`/`MAX_NORMALIZED_HEADERS`/
/// `MAX_NORMALIZED_FIELD_BYTES` budget `waf_detect_request` and
/// `transform_request` already use. `backends` is capped at
/// `MAX_BALANCE_CANDIDATES` (128) entries by the host before this struct
/// is built. `excluded_backend_id` is set when this call is a failover
/// retry -- the backend that just failed on this same request. The host
/// enforces this exclusion itself (`PoolState::select_specific`) rather
/// than trusting the plugin to honor it.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct LoadBalanceRequest {
    pub pool: String,
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub backends: Vec<BackendCandidate>,
    pub excluded_backend_id: Option<u64>,
}

/// Output of `bearust_balance_select`. The host leases `backend_id`
/// directly if it names a backend that is currently healthy and isn't
/// `excluded_backend_id` -- otherwise the whole call is treated as a
/// failure and the host falls back to its own deterministic selection.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct LoadBalanceResult {
    pub backend_id: u64,
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p bearust-plugin-sdk`
Expected: PASS — all tests in the crate, including the two new ones.

- [ ] **Step 5: Commit**

```bash
git add crates/bearust-plugin-sdk/src/lib.rs
git commit -m "feat: add BackendCandidate/LoadBalanceRequest/LoadBalanceResult wire types to the plugin SDK"
```

---

## Task 2: Observability counters

**Files:**
- Modify: `src/observability.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `PluginMetrics::record_balance_invocation()`, `record_balance_applied()`, `record_balance_failure()` — consumed by Task 5 (`src/proxy.rs`).

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `src/observability.rs`, directly after `transform_response_metrics_render_as_counters`:

```rust
    #[test]
    fn balance_metrics_render_as_counters() {
        let metrics = PluginMetrics::default();
        metrics.record_balance_invocation();
        metrics.record_balance_invocation();
        metrics.record_balance_applied();
        metrics.record_balance_failure();
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_balance_invocations_total 2"));
        assert!(output.contains("bearust_plugins_balance_applied_total 1"));
        assert!(output.contains("bearust_plugins_balance_failures_total 1"));
    }
```

- [ ] **Step 2: Run the test to verify it fails to compile**

Run: `cargo test balance_metrics_render_as_counters`
Expected: FAIL — `record_balance_invocation` and friends don't exist yet.

- [ ] **Step 3: Add the fields, methods, and render blocks**

In `src/observability.rs`, add three fields to `PluginMetrics` directly after `transform_response_failures: AtomicU64,`:

```rust
    balance_invocations: AtomicU64,
    balance_applied: AtomicU64,
    balance_failures: AtomicU64,
```

Add three methods directly after `record_transform_response_failure`:

```rust
    /// A `balance.select` plugin call was attempted (regardless of
    /// outcome).
    pub fn record_balance_invocation(&self) {
        self.balance_invocations.fetch_add(1, Ordering::Relaxed);
    }

    /// A `balance.select` plugin call succeeded and its returned
    /// `backend_id` was valid (healthy, not excluded) and leased.
    pub fn record_balance_applied(&self) {
        self.balance_applied.fetch_add(1, Ordering::Relaxed);
    }

    /// A `balance.select` plugin call failed: trap, timeout, fuel
    /// exhaustion, malformed output, a `spawn_blocking` join failure, or a
    /// `backend_id` that named an unhealthy, excluded, or nonexistent
    /// backend.
    pub fn record_balance_failure(&self) {
        self.balance_failures.fetch_add(1, Ordering::Relaxed);
    }
```

Add three render blocks in `render_prometheus`, directly after the existing `bearust_plugins_transform_response_failures_total` block and before the final `output` return:

```rust
        output.push_str("# TYPE bearust_plugins_balance_invocations_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_balance_invocations_total {}\n",
            self.balance_invocations.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_balance_applied_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_balance_applied_total {}\n",
            self.balance_applied.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_balance_failures_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_balance_failures_total {}\n",
            self.balance_failures.load(Ordering::Relaxed)
        ));
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test balance_metrics_render_as_counters`
Expected: PASS

- [ ] **Step 5: Run the full observability test suite**

Run: `cargo test --lib observability`
Expected: PASS — no regressions to the existing counter tests.

- [ ] **Step 6: Commit**

```bash
git add src/observability.rs
git commit -m "feat: add balance.select plugin observability counters"
```

---

## Task 3: `Algorithm::Plugin` and `PoolState` selection primitives

**Files:**
- Modify: `src/config/mod.rs`
- Modify: `src/balancer.rs`
- Modify: `tests/load_balancing.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `config::Algorithm::Plugin` (new enum variant), `balancer::BackendSnapshot { id: BackendId, address: SocketAddr, healthy: bool, inflight: usize }`, `PoolState::algorithm(&self) -> Algorithm`, `PoolState::candidates(&self) -> Vec<BackendSnapshot>`, `PoolState::select_specific(self: &Arc<Self>, id: BackendId, excluded: Option<BackendId>) -> Option<BackendLease>` — all consumed by Task 5 (`src/proxy.rs`).

- [ ] **Step 1: Write the failing tests**

In `tests/load_balancing.rs`, replace the top import:

```rust
use bearust::{balancer::PoolState, config::Config};
```

with:

```rust
use bearust::{
    balancer::PoolState,
    config::{Algorithm, Config},
};
```

Then add, at the end of the file:

```rust

#[test]
fn plugin_algorithm_falls_back_to_round_robin_selection() {
    let pool = pool("plugin");
    let selected: Vec<_> = (0..4)
        .map(|_| pool.select(None).unwrap().address())
        .collect();
    assert_eq!(selected[0], selected[2]);
    assert_eq!(selected[1], selected[3]);
    assert_ne!(selected[0], selected[1]);
}

#[test]
fn algorithm_accessor_reports_the_configured_algorithm() {
    let pool = pool("plugin");
    assert_eq!(pool.algorithm(), Algorithm::Plugin);
    let pool = pool("round_robin");
    assert_eq!(pool.algorithm(), Algorithm::RoundRobin);
}

#[test]
fn candidates_reflects_live_health_and_inflight_state() {
    let pool = pool("round_robin");
    pool.set_healthy(1.into(), false);
    let held = pool.select(Some(1.into())).unwrap();
    let candidates = pool.candidates();
    assert_eq!(candidates.len(), 2);
    let zero = candidates.iter().find(|c| c.id == 0.into()).unwrap();
    assert!(zero.healthy);
    assert_eq!(zero.inflight, 1);
    let one = candidates.iter().find(|c| c.id == 1.into()).unwrap();
    assert!(!one.healthy);
    assert_eq!(one.inflight, 0);
    drop(held);
}

#[test]
fn select_specific_rejects_an_unhealthy_backend() {
    let pool = pool("round_robin");
    pool.set_healthy(0.into(), false);
    assert!(pool.select_specific(0.into(), None).is_none());
}

#[test]
fn select_specific_rejects_the_excluded_backend() {
    let pool = pool("round_robin");
    assert!(pool.select_specific(0.into(), Some(0.into())).is_none());
}

#[test]
fn select_specific_rejects_a_nonexistent_backend() {
    let pool = pool("round_robin");
    assert!(pool.select_specific(99.into(), None).is_none());
}

#[test]
fn select_specific_accepts_a_valid_pick_and_increments_inflight() {
    let pool = pool("round_robin");
    let lease = pool.select_specific(0.into(), None).unwrap();
    assert_eq!(lease.id(), 0.into());
    assert_eq!(pool.total_inflight(), 1);
    drop(lease);
    assert_eq!(pool.total_inflight(), 0);
}
```

- [ ] **Step 2: Run the tests to verify they fail to compile**

Run: `cargo test --test load_balancing`
Expected: FAIL — `Algorithm::Plugin`, `pool.algorithm()`, `pool.candidates()`, and `pool.select_specific(...)` don't exist yet.

- [ ] **Step 3: Add the `Plugin` variant to `Algorithm`**

In `src/config/mod.rs`, replace:

```rust
pub enum Algorithm {
    RoundRobin,
    LeastConnections,
}
```

with:

```rust
pub enum Algorithm {
    RoundRobin,
    LeastConnections,
    Plugin,
}
```

- [ ] **Step 4: Add the `Algorithm::Plugin` arm to `PoolState::select`**

In `src/balancer.rs`, replace:

```rust
        let selected = match self.algorithm {
            Algorithm::RoundRobin => (0..self.backends.len())
```

with:

```rust
        let selected = match self.algorithm {
            // A `Plugin`-configured pool's primary selection happens in
            // `src/proxy.rs::apply_load_balancer_plugin`, called before
            // `select()`. This arm is `select()`'s role as that path's
            // deterministic fallback -- identical to `RoundRobin` so a
            // `Plugin` pool never has "no algorithm" to fall back to.
            Algorithm::RoundRobin | Algorithm::Plugin => (0..self.backends.len())
```

- [ ] **Step 5: Add `BackendSnapshot`, `algorithm()`, `candidates()`, and `select_specific()`**

Add to `src/balancer.rs`, directly after the `BackendLease` struct definition (before `impl PoolState`):

```rust
/// A read-only snapshot of one backend's current state, as reported to a
/// `balance.select` plugin (via `src/proxy.rs`, which converts this into
/// the plugin SDK's `BackendCandidate` wire type). Deliberately not the
/// SDK type itself -- `balancer.rs` has no dependency on the plugin
/// system, matching how it also doesn't know about WAF or transforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BackendSnapshot {
    pub id: BackendId,
    pub address: SocketAddr,
    pub healthy: bool,
    pub inflight: usize,
}
```

Add to `impl PoolState` in `src/balancer.rs`, directly after the `request_timeout()` method (before the closing `}` of `impl PoolState`):

```rust

    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// A read-only snapshot of every backend in this pool, for a
    /// `balance.select` plugin to choose among. Pure; does not affect
    /// selection state.
    pub fn candidates(&self) -> Vec<BackendSnapshot> {
        self.backends
            .iter()
            .map(|backend| BackendSnapshot {
                id: backend.id,
                address: backend.address,
                healthy: backend.healthy.load(Ordering::Acquire),
                inflight: backend.inflight.load(Ordering::Acquire),
            })
            .collect()
    }

    /// Leases `id` directly if it names a backend in this pool that is
    /// currently healthy and isn't `excluded` -- `None` on any of those
    /// three failures. Used to apply a `balance.select` plugin's pick;
    /// the caller falls back to `select()` when this returns `None`.
    pub fn select_specific(
        self: &Arc<Self>,
        id: BackendId,
        excluded: Option<BackendId>,
    ) -> Option<BackendLease> {
        if Some(id) == excluded {
            return None;
        }
        let backend = self.backends.get(id.0)?;
        if !backend.healthy.load(Ordering::Acquire) {
            return None;
        }
        backend.inflight.fetch_add(1, Ordering::AcqRel);
        Some(BackendLease {
            backend: Arc::clone(backend),
        })
    }
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `cargo test --test load_balancing`
Expected: PASS — all tests in the file, including the six new ones.

- [ ] **Step 7: Run the full workspace fmt/clippy/test gate for this task**

Run: `cargo fmt --all -- --check`
Expected: PASS

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, no warnings

Run: `cargo test --workspace --locked` (allow up to 5 minutes)
Expected: PASS, 0 failed

- [ ] **Step 8: Commit**

```bash
git add src/config/mod.rs src/balancer.rs tests/load_balancing.rs
git commit -m "feat: add Algorithm::Plugin and PoolState selection primitives for balance.select"
```

---

## Task 4: Capability wiring in `plugin_runtime.rs`

**Files:**
- Modify: `src/plugin_runtime.rs`
- Modify: `tests/plugin_runtime.rs`
- Create: `tests/fixtures/plugins/balance_select_v2/plugin.toml`
- Create: `tests/fixtures/plugins/balance_select_v2/balance_select_v2.wat`
- Create: `tests/fixtures/plugins/balance_select_v2/README.md`

**Interfaces:**
- Consumes: `bearust_plugin_sdk::{LoadBalanceRequest, LoadBalanceResult}` (Task 1).
- Produces: `CompiledPlugin::balance_select(&self, request: &bearust_plugin_sdk::LoadBalanceRequest) -> Result<bearust_plugin_sdk::LoadBalanceResult, PluginError>`, `PluginManager::balance_select_plugin(&self) -> Option<Arc<CompiledPlugin>>` — both consumed by Task 5 (`src/proxy.rs`).

### Part A — the fixture

- [ ] **Step 1: Create the fixture manifest**

Create `tests/fixtures/plugins/balance_select_v2/plugin.toml`:

```toml
id = "balance-select-v2"
display_name = "Deterministic backend selector"
abi_version = 2
module = "balance_select_v2.wasm"
capabilities = ["balance.select"]

[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 49152
```

- [ ] **Step 2: Create the fixture WAT module**

Create `tests/fixtures/plugins/balance_select_v2/balance_select_v2.wat`. This ignores the host-supplied input and always returns the fixed JSON literal `{"backend_id":0}` (16 bytes), proving the alloc/write/call/read/dealloc round trip end to end, exactly like `transform_response_v2`'s fixture proves it for the response-body hook:

```wat
;; Deterministic Phase 13G fixture. Build with:
;;   wat2wasm balance_select_v2.wat -o balance_select_v2.wasm
;;
;; The test suite parses this WAT with the pinned `wat` dev dependency, so the
;; generated binary and any compiler cache are intentionally not checked in.
;;
;; Ignores the JSON the host writes as input and always returns the fixed
;; JSON literal `{"backend_id":0}` (16 bytes) stored at memory offset 0,
;; proving the host's alloc/write/call/read/dealloc round trip end to end.
;; Every abi_version: 2 module must also export bearust_health_check_v2
;; regardless of its declared capabilities (an existing Phase 13B
;; requirement); this fixture is never health-checked in tests, so that
;; export is a trivial stub.
(module
  (memory (export "memory") 1)
  (global $heap_ptr (mut i32) (i32.const 1024))
  (data (i32.const 0) "{\22backend_id\22:0}")

  (func (export "bearust_abi_version") (result i32)
    i32.const 2)

  (func (export "bearust_alloc") (param $len i32) (result i32)
    (local $ptr i32)
    global.get $heap_ptr
    local.set $ptr
    global.get $heap_ptr
    local.get $len
    i32.add
    global.set $heap_ptr
    local.get $ptr)

  (func (export "bearust_dealloc") (param $ptr i32) (param $len i32)
    nop)

  (func (export "bearust_health_check_v2") (param $ptr i32) (param $len i32) (result i64)
    i64.const 0)

  (func (export "bearust_balance_select") (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
      (i64.extend_i32_u (i32.const 16)))))
```

- [ ] **Step 3: Create the fixture README**

Create `tests/fixtures/plugins/balance_select_v2/README.md`:

```markdown
# Deterministic backend selector fixture

Local-only, no-import WASM fixture for the Phase 13G `balance.select`
acceptance tests. Exports `bearust_alloc`/`bearust_dealloc`/
`bearust_balance_select` per the memory convention in
`docs/superpowers/specs/2026-08-12-phase-13g-load-balancing-hooks-design.md`,
plus a trivial `bearust_health_check_v2` stub (required unconditionally of
every `abi_version: 2` module, independent of declared capabilities). It
ignores the host-supplied input and always returns the fixed
`{"backend_id":0}`, so the test suite can assert an exact outcome while
still exercising the full alloc/write/call/read/dealloc round trip.

The checked-in WAT source is preferred over a generated binary for the same
reproducibility reasons as `tests/fixtures/plugins/health_ok/`.
```

### Part B — `src/plugin_runtime.rs`

- [ ] **Step 4: Write the failing manifest-validation and export tests**

Add to `tests/plugin_runtime.rs`, directly after `transform_response_capability_rejects_output_limit_below_the_transform_response_input_floor`:

```rust
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
```

Add to `tests/plugin_runtime.rs`, at the end of the file:

```rust

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
```

- [ ] **Step 5: Run the new tests to verify they fail to compile**

Run: `cargo test --test plugin_runtime balance_select`
Expected: FAIL — none of `"balance.select"`, `MIN_BALANCE_INPUT_BYTES`, `balance_select`, or `balance_select_plugin` exist yet.

- [ ] **Step 6: Extend `ALLOWED_CAPABILITIES` and add the new floor constant**

In `src/plugin_runtime.rs`, replace:

```rust
const ALLOWED_CAPABILITIES: [&str; 5] = [
    "health_check",
    "notify.waf_block",
    "waf.detect",
    "transform.request",
    "transform.response",
];
```

with:

```rust
const ALLOWED_CAPABILITIES: [&str; 6] = [
    "health_check",
    "notify.waf_block",
    "waf.detect",
    "transform.request",
    "transform.response",
    "balance.select",
];
```

Add directly after the `MIN_TRANSFORM_RESPONSE_INPUT_BYTES` constant and its doc comment:

```rust
/// `balance.select` carries the same bounded request metadata
/// (`MAX_NORMALIZED_METADATA_BYTES`/`MAX_NORMALIZED_HEADERS`/
/// `MAX_NORMALIZED_FIELD_BYTES`) `waf_detect_request`/`transform_request`
/// already use -- roughly 24 KiB worst case with escaping overhead --
/// plus up to `MAX_BALANCE_CANDIDATES` (128, enforced in
/// `src/proxy.rs::load_balance_request`) backend candidates at their JSON
/// worst case (`{"id":18446744073709551615,"address":
/// "255.255.255.255:65535","healthy":false,"inflight":4294967295}`, ~99
/// bytes each, ~13 KiB total for 128 of them). Combined worst case is
/// roughly 38 KiB; this floor gives comfortable headroom above that while
/// staying under the default 64 KiB `PluginPolicy::max_output_bytes`
/// ceiling -- unlike Phase 13F's `transform.response`, this capability
/// does not require raising that ceiling. Deliberately its own constant,
/// not shared with any existing floor.
const MIN_BALANCE_INPUT_BYTES: usize = 49_152;
```

- [ ] **Step 7: Add `has_balance_select` to `CompiledPlugin` and wire it through `compile`**

In `src/plugin_runtime.rs`, replace the `CompiledPlugin` struct's field list:

```rust
pub struct CompiledPlugin {
    engine: Engine,
    scheduler: Arc<EpochScheduler>,
    module: Module,
    limits: PluginLimits,
    abi_version: u32,
    has_health_check: bool,
    has_notify_waf_block: bool,
    has_waf_detect: bool,
    has_transform_request: bool,
    has_transform_response: bool,
}
```

with:

```rust
pub struct CompiledPlugin {
    engine: Engine,
    scheduler: Arc<EpochScheduler>,
    module: Module,
    limits: PluginLimits,
    abi_version: u32,
    has_health_check: bool,
    has_notify_waf_block: bool,
    has_waf_detect: bool,
    has_transform_request: bool,
    has_transform_response: bool,
    has_balance_select: bool,
}
```

Replace the whole `let (has_health_check, ..., has_transform_response) = match manifest.abi_version { ... };` block in `PluginEngine::compile` (and the `Ok(CompiledPlugin { ... })` construction right after it) with:

```rust
        let (
            has_health_check,
            has_notify_waf_block,
            has_waf_detect,
            has_transform_request,
            has_transform_response,
            has_balance_select,
        ) = match manifest.abi_version {
            1 => {
                let has_health_check =
                    match instance.get_typed_func::<(), i32>(&mut store, "bearust_health_check") {
                        Ok(_) => true,
                        Err(_)
                            if instance
                                .get_export(&mut store, "bearust_health_check")
                                .is_none() =>
                        {
                            false
                        }
                        Err(_) => return Err(PluginError::AbiMismatch),
                    };
                (has_health_check, false, false, false, false, false)
            }
            2 => {
                // abi_version 2: bearust_health_check is not part of this ABI.
                // Require the memory-convention exports and the guest's linear
                // memory instead, all with exact typed signatures.
                instance
                    .get_memory(&mut store, "memory")
                    .ok_or(PluginError::AbiMismatch)?;
                instance
                    .get_typed_func::<i32, i32>(&mut store, "bearust_alloc")
                    .map_err(|_| PluginError::AbiMismatch)?;
                instance
                    .get_typed_func::<(i32, i32), ()>(&mut store, "bearust_dealloc")
                    .map_err(|_| PluginError::AbiMismatch)?;
                instance
                    .get_typed_func::<(i32, i32), i64>(&mut store, "bearust_health_check_v2")
                    .map_err(|_| PluginError::AbiMismatch)?;
                let has_notify_waf_block = if manifest
                    .capabilities
                    .iter()
                    .any(|c| c == "notify.waf_block")
                {
                    instance
                        .get_typed_func::<(i32, i32), i32>(&mut store, "bearust_notify_waf_block")
                        .map_err(|_| PluginError::AbiMismatch)?;
                    true
                } else {
                    false
                };
                let has_waf_detect = if manifest.capabilities.iter().any(|c| c == "waf.detect") {
                    instance
                        .get_typed_func::<(i32, i32), i64>(&mut store, "bearust_waf_detect")
                        .map_err(|_| PluginError::AbiMismatch)?;
                    true
                } else {
                    false
                };
                let has_transform_request = if manifest
                    .capabilities
                    .iter()
                    .any(|c| c == "transform.request")
                {
                    instance
                        .get_typed_func::<(i32, i32), i64>(&mut store, "bearust_transform_request")
                        .map_err(|_| PluginError::AbiMismatch)?;
                    true
                } else {
                    false
                };
                let has_transform_response = if manifest
                    .capabilities
                    .iter()
                    .any(|c| c == "transform.response")
                {
                    instance
                        .get_typed_func::<(i32, i32), i64>(&mut store, "bearust_transform_response")
                        .map_err(|_| PluginError::AbiMismatch)?;
                    true
                } else {
                    false
                };
                let has_balance_select = if manifest
                    .capabilities
                    .iter()
                    .any(|c| c == "balance.select")
                {
                    instance
                        .get_typed_func::<(i32, i32), i64>(&mut store, "bearust_balance_select")
                        .map_err(|_| PluginError::AbiMismatch)?;
                    true
                } else {
                    false
                };
                (
                    false,
                    has_notify_waf_block,
                    has_waf_detect,
                    has_transform_request,
                    has_transform_response,
                    has_balance_select,
                )
            }
            _ => return Err(PluginError::AbiMismatch),
        };

        Ok(CompiledPlugin {
            engine: self.engine.clone(),
            scheduler: Arc::clone(&self.scheduler),
            module,
            limits,
            abi_version: manifest.abi_version,
            has_health_check,
            has_notify_waf_block,
            has_waf_detect,
            has_transform_request,
            has_transform_response,
            has_balance_select,
        })
```

- [ ] **Step 8: Add `CompiledPlugin::balance_select`**

Add to `src/plugin_runtime.rs`, directly after the `transform_response` method (inside `impl CompiledPlugin`):

```rust
    /// Invokes the `balance.select` capability's entry point on an
    /// `abi_version: 2` plugin that declared it. Returns the plugin's
    /// chosen `backend_id` or a `PluginError` for any host-detected
    /// failure (trap, timeout, fuel exhaustion, malformed export/output,
    /// or an out-of-bounds pointer). Never panics: every guest-controlled
    /// pointer/length is bounds-checked exactly as in `health_check`'s v2
    /// path. The caller (`src/proxy.rs::apply_load_balancer_plugin`) is
    /// responsible for validating the returned `backend_id` against the
    /// pool's live health/exclusion state -- this method has no knowledge
    /// of either.
    pub fn balance_select(
        &self,
        request: &bearust_plugin_sdk::LoadBalanceRequest,
    ) -> Result<bearust_plugin_sdk::LoadBalanceResult, PluginError> {
        if !self.has_balance_select {
            return Err(PluginError::AbiMismatch);
        }
        let started = Instant::now();
        let _scheduler = Arc::clone(&self.scheduler);
        let mut store = new_store(&self.engine, &self.limits)?;
        store
            .set_fuel(self.limits.fuel)
            .map_err(|_| PluginError::FuelExhausted)?;
        store.set_epoch_deadline(epoch_ticks(self.limits.invocation_timeout_ms));

        let instance = Instance::new(&mut store, &self.module, &[])
            .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
        let memory = instance
            .get_memory(&mut store, "memory")
            .ok_or(PluginError::AbiMismatch)?;
        let alloc = instance
            .get_typed_func::<i32, i32>(&mut store, "bearust_alloc")
            .map_err(|_| PluginError::AbiMismatch)?;
        let dealloc = instance
            .get_typed_func::<(i32, i32), ()>(&mut store, "bearust_dealloc")
            .map_err(|_| PluginError::AbiMismatch)?;
        let select = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "bearust_balance_select")
            .map_err(|_| PluginError::AbiMismatch)?;

        let input = bearust_plugin_sdk::encode(request);
        let input_len: i32 = input
            .len()
            .try_into()
            .map_err(|_| PluginError::MemoryLimit)?;
        let input_ptr = alloc
            .call(&mut store, input_len)
            .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
        write_guest_bytes(&memory, &mut store, input_ptr, &input, &self.limits)?;

        let packed = select
            .call(&mut store, (input_ptr, input_len))
            .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
        dealloc
            .call(&mut store, (input_ptr, input_len))
            .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
        let (out_ptr, out_len) = bearust_plugin_sdk::unpack(packed);
        let bytes = read_guest_bytes(&memory, &store, out_ptr, out_len, &self.limits)?;
        dealloc
            .call(&mut store, (out_ptr, out_len))
            .map_err(|error| map_runtime_error(&error, started, &self.limits))?;

        bearust_plugin_sdk::decode(&bytes).map_err(|_| PluginError::Trap)
    }
```

- [ ] **Step 9: Extend `PluginManifest::validate`**

In `src/plugin_runtime.rs`, replace:

```rust
        if self.abi_version != 2
            && self.capabilities.iter().any(|c| {
                c == "notify.waf_block"
                    || c == "waf.detect"
                    || c == "transform.request"
                    || c == "transform.response"
            })
        {
            return Err(PluginError::InvalidManifest);
        }
```

with:

```rust
        if self.abi_version != 2
            && self.capabilities.iter().any(|c| {
                c == "notify.waf_block"
                    || c == "waf.detect"
                    || c == "transform.request"
                    || c == "transform.response"
                    || c == "balance.select"
            })
        {
            return Err(PluginError::InvalidManifest);
        }
```

Add directly after the existing `transform.response` floor check:

```rust
        if self.capabilities.iter().any(|c| c == "balance.select")
            && self.limits.max_output_bytes < MIN_BALANCE_INPUT_BYTES
        {
            return Err(PluginError::InvalidManifest);
        }
```

- [ ] **Step 10: Add `PluginManager::balance_select_plugin`**

Add to `src/plugin_runtime.rs`, directly after the `transform_response_plugin` method (inside `impl PluginManager`):

```rust

    /// Returns the compiled plugin currently acting as the active
    /// load-balancing selector, if any: the first (lowest plugin ID)
    /// enabled plugin whose manifest declared `balance.select`. Mirrors
    /// `transform_response_plugin()`'s selection rule exactly -- at most
    /// one plugin is ever treated as the active selector; any other
    /// plugin also declaring the capability is simply never selected.
    pub fn balance_select_plugin(&self) -> Option<Arc<CompiledPlugin>> {
        self.current
            .load_full()
            .plugins
            .values()
            .find_map(|record| {
                if !record.status.enabled {
                    return None;
                }
                let compiled = record.compiled.as_ref()?;
                compiled.has_balance_select.then(|| Arc::clone(compiled))
            })
    }
```

- [ ] **Step 11: Run the plugin_runtime tests to verify they pass**

Run: `cargo test --test plugin_runtime`
Expected: PASS — all tests, including the new `balance_select_*` and `v2_*_balance_select_*` ones.

- [ ] **Step 12: Run the full workspace fmt/clippy/test gate for this task**

Run: `cargo fmt --all -- --check`
Expected: PASS

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, no warnings

Run: `cargo test --workspace --locked` (allow up to 5 minutes)
Expected: PASS, 0 failed

- [ ] **Step 13: Commit**

```bash
git add src/plugin_runtime.rs tests/plugin_runtime.rs tests/fixtures/plugins/balance_select_v2/
git commit -m "feat: add balance.select plugin capability, export validation, and invocation"
```

---

## Task 5: Wire the balancer plugin into `src/proxy.rs`

**Files:**
- Modify: `src/proxy.rs`

**Interfaces:**
- Consumes: `bearust_plugin_sdk::{BackendCandidate, LoadBalanceRequest, LoadBalanceResult}` (Task 1), `PluginManager::balance_select_plugin()`/`CompiledPlugin::balance_select()` (Task 4), `balancer::{BackendSnapshot, PoolState}` additions (Task 3), `PluginMetrics::record_balance_{invocation,applied,failure}()` (Task 2).
- Produces: nothing consumed by later tasks — this is the last capability-wiring task.

- [ ] **Step 1: Write the failing tests for the pure helper function and the full async flow**

Add to `src/proxy.rs`'s `#[cfg(test)] mod tests` block. First, extend the existing `use super::{...}` import list to include the two new names (`apply_load_balancer_plugin`, `load_balance_request`):

```rust
    use super::{
        accumulate_response_chunk, apply_load_balancer_plugin, apply_transform_plugin,
        apply_transform_response_plugin, apply_waf_detector, error_status,
        invoke_analytics_changed, is_valid_transform_headers, load_balance_request,
        reassert_protected_request_headers, should_buffer_response_for_transform,
        waf_block_event, RequestContext, RESPONSE_BODY_TRANSFORM_CAP_BYTES,
    };
```

Add the following block at the end of the test module (after the last existing test, before the closing `}` of `mod tests`):

```rust

    fn balance_manager(enabled: bool) -> Arc<PluginManager> {
        let root = tempdir().unwrap();
        let plugin = root.path().join("balance-select-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/balance_select_v2/plugin.toml"),
        )
        .unwrap();
        let module = wat::parse_str(include_str!(
            "../tests/fixtures/plugins/balance_select_v2/balance_select_v2.wat"
        ))
        .unwrap();
        fs::write(plugin.join("balance_select_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();
        if !enabled {
            manager.set_enabled("balance-select-v2", false).unwrap();
        }
        manager
    }

    fn sample_pool() -> Arc<crate::balancer::PoolState> {
        use crate::config::{Algorithm, BackendConfig, HealthCheckKind, PoolConfig};
        let config = PoolConfig {
            name: "api".into(),
            algorithm: Algorithm::Plugin,
            connect_timeout_seconds: 3,
            request_timeout_seconds: 30,
            backends: vec![
                BackendConfig {
                    address: "127.0.0.1:19001".parse().unwrap(),
                    health_check: HealthCheckKind::Tcp,
                    health_path: None,
                },
                BackendConfig {
                    address: "127.0.0.1:19002".parse().unwrap(),
                    health_check: HealthCheckKind::Tcp,
                    health_path: None,
                },
            ],
        };
        let pool = Arc::new(crate::balancer::PoolState::new(&config));
        pool.set_healthy(0.into(), true);
        pool.set_healthy(1.into(), true);
        pool
    }

    #[test]
    fn load_balance_request_reports_pool_name_and_bounded_candidates() {
        let pool = sample_pool();
        let header = sample_request_header();
        let request = load_balance_request(&pool, &header, None);
        assert_eq!(request.pool, "api");
        assert_eq!(request.method, "GET");
        assert_eq!(request.backends.len(), 2);
        assert!(request.backends.iter().all(|b| b.healthy));
        assert_eq!(request.excluded_backend_id, None);
    }

    #[test]
    fn load_balance_request_reports_the_excluded_backend() {
        let pool = sample_pool();
        let header = sample_request_header();
        let request = load_balance_request(&pool, &header, Some(1.into()));
        assert_eq!(request.excluded_backend_id, Some(1));
    }

    #[tokio::test]
    async fn a_successful_balance_selection_leases_the_chosen_backend() {
        let manager = balance_manager(true);
        let pool = sample_pool();
        let header = sample_request_header();
        let lease = apply_load_balancer_plugin(Some(&manager), &pool, &header, None)
            .await
            .expect("fixture always returns backend_id 0");
        assert_eq!(lease.id(), 0.into());
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_balance_invocations_total 1"));
        assert!(output.contains("bearust_plugins_balance_applied_total 1"));
    }

    #[tokio::test]
    async fn no_balancer_configured_returns_none() {
        let manager = PluginManager::new(PluginConfig::default());
        let pool = sample_pool();
        let header = sample_request_header();
        let lease = apply_load_balancer_plugin(Some(&manager), &pool, &header, None).await;
        assert!(lease.is_none());
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_balance_invocations_total 0"));
    }

    #[tokio::test]
    async fn a_disabled_balancer_returns_none() {
        let manager = balance_manager(false);
        let pool = sample_pool();
        let header = sample_request_header();
        let lease = apply_load_balancer_plugin(Some(&manager), &pool, &header, None).await;
        assert!(lease.is_none());
    }

    #[tokio::test]
    async fn no_plugin_manager_returns_none() {
        let pool = sample_pool();
        let header = sample_request_header();
        let lease = apply_load_balancer_plugin(None, &pool, &header, None).await;
        assert!(lease.is_none());
    }

    #[tokio::test]
    async fn a_pick_naming_an_unhealthy_backend_fails_open_and_counts_a_failure() {
        let manager = balance_manager(true);
        let pool = sample_pool();
        let header = sample_request_header();
        // The fixture always picks backend 0; marking it unhealthy makes
        // select_specific reject the pick.
        pool.set_healthy(0.into(), false);
        let lease = apply_load_balancer_plugin(Some(&manager), &pool, &header, None).await;
        assert!(lease.is_none());
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_balance_failures_total 1"));
        assert!(output.contains("bearust_plugins_balance_applied_total 0"));
    }

    #[tokio::test]
    async fn a_trapping_balancer_fails_open_and_counts_a_failure() {
        let root = tempdir().unwrap();
        let plugin = root.path().join("balance-select-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/balance_select_v2/plugin.toml"),
        )
        .unwrap();
        // Same shape as the checked-in fixture, but traps on every call.
        let wat = r#"(module
            (memory (export "memory") 1)
            (global $heap_ptr (mut i32) (i32.const 1024))
            (func (export "bearust_abi_version") (result i32) i32.const 2)
            (func (export "bearust_alloc") (param $len i32) (result i32)
                (local $ptr i32)
                global.get $heap_ptr
                local.set $ptr
                global.get $heap_ptr
                local.get $len
                i32.add
                global.set $heap_ptr
                local.get $ptr)
            (func (export "bearust_dealloc") (param i32 i32) nop)
            (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
            (func (export "bearust_balance_select") (param i32 i32) (result i64) unreachable))"#;
        let module = wat::parse_str(wat).unwrap();
        fs::write(plugin.join("balance_select_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();

        let pool = sample_pool();
        let header = sample_request_header();
        let lease = apply_load_balancer_plugin(Some(&manager), &pool, &header, None).await;
        assert!(lease.is_none());
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_balance_failures_total 1"));
        assert!(output.contains("bearust_plugins_balance_applied_total 0"));
    }
```

`sample_request_header()` already exists in this test module (added in an earlier phase) — reuse it as-is, do not redefine it.

- [ ] **Step 2: Run the tests to verify they fail to compile**

Run: `cargo test --lib proxy::tests`
Expected: FAIL — none of `load_balance_request`, `apply_load_balancer_plugin`, or `MAX_BALANCE_CANDIDATES` exist yet.

- [ ] **Step 3: Add the module-level constant and the two helper functions**

Add to `src/proxy.rs`, directly after the `apply_transform_response_plugin` function (i.e. after its closing `}`, before the `should_buffer_response_for_transform`/whatever follows -- place it as its own new section, e.g. directly before `impl ProxyHttp for BearustProxy`):

```rust
/// Backend candidates sent to a `balance.select` plugin are capped at this
/// many entries -- an operator-scale bound (pool size), not an
/// attacker-controlled one, but bounded defensively all the same, the same
/// way `MAX_NORMALIZED_HEADERS` bounds header count.
const MAX_BALANCE_CANDIDATES: usize = 128;

/// Converts a pool's current candidate snapshot and the downstream
/// request's bounded metadata into the wire shape a `balance.select`
/// plugin receives. `method`/`path`/`query`/`headers` share the same
/// `MAX_NORMALIZED_METADATA_BYTES`/`MAX_NORMALIZED_HEADERS` budget
/// `waf_detect_request`/`transform_request` already use (this function's
/// shape mirrors `transform_request(header: &RequestHeader)` exactly,
/// with the pool name and candidate list added); `backends` is capped at
/// `MAX_BALANCE_CANDIDATES`. Pure and side-effect free.
fn load_balance_request(
    pool: &Arc<crate::balancer::PoolState>,
    header: &RequestHeader,
    excluded: Option<BackendId>,
) -> bearust_plugin_sdk::LoadBalanceRequest {
    let mut remaining = crate::waf::MAX_NORMALIZED_METADATA_BYTES;
    let method = bounded_metadata(header.method.as_str(), &mut remaining);
    let path = bounded_metadata(header.uri.path(), &mut remaining);
    let query = bounded_metadata(header.uri.query().unwrap_or(""), &mut remaining);
    let headers = header
        .headers
        .iter()
        .take(crate::waf::MAX_NORMALIZED_HEADERS)
        .map(|(name, value)| {
            (
                bounded_metadata(name.as_str(), &mut remaining),
                bounded_metadata(&String::from_utf8_lossy(value.as_bytes()), &mut remaining),
            )
        })
        .collect();
    let backends = pool
        .candidates()
        .into_iter()
        .take(MAX_BALANCE_CANDIDATES)
        .map(|snapshot| bearust_plugin_sdk::BackendCandidate {
            id: snapshot.id.index() as u64,
            address: snapshot.address.to_string(),
            healthy: snapshot.healthy,
            inflight: snapshot.inflight as u32,
        })
        .collect();
    bearust_plugin_sdk::LoadBalanceRequest {
        pool: pool.name().to_string(),
        method,
        path,
        query,
        headers,
        backends,
        excluded_backend_id: excluded.map(|id| id.index() as u64),
    }
}

/// Runs the registered `balance.select` plugin (if any) against `pool`'s
/// current candidates and `header`'s bounded metadata, returning a lease
/// on its chosen backend if the pick is valid, or `None` on any failure --
/// the caller falls back to `pool.select(excluded)`. Synchronous from the
/// caller's point of view but offloads the blocking wasmtime call via
/// `spawn_blocking` so it never blocks the shared async runtime. Fails
/// open (`None`) on every error class: no balancer configured, no plugin
/// currently declaring the capability, a disabled plugin, a
/// trap/timeout/fuel exhaustion, malformed output, a `spawn_blocking` join
/// failure, or a returned `backend_id` that names an unhealthy, excluded,
/// or nonexistent backend.
async fn apply_load_balancer_plugin(
    plugin_manager: Option<&Arc<PluginManager>>,
    pool: &Arc<crate::balancer::PoolState>,
    header: &RequestHeader,
    excluded: Option<BackendId>,
) -> Option<crate::balancer::BackendLease> {
    let manager = plugin_manager?;
    let selector = manager.balance_select_plugin()?;
    let metrics = manager.metrics();
    metrics.record_balance_invocation();
    let request = load_balance_request(pool, header, excluded);
    let outcome = tokio::task::spawn_blocking(move || selector.balance_select(&request)).await;
    match outcome {
        Ok(Ok(result)) => {
            let Ok(index) = usize::try_from(result.backend_id) else {
                tracing::warn!(
                    event = "balance_select_failed",
                    reason = "backend_id_out_of_range"
                );
                metrics.record_balance_failure();
                return None;
            };
            match pool.select_specific(index.into(), excluded) {
                Some(lease) => {
                    metrics.record_balance_applied();
                    Some(lease)
                }
                None => {
                    tracing::warn!(
                        event = "balance_select_failed",
                        reason = "invalid_backend_id"
                    );
                    metrics.record_balance_failure();
                    None
                }
            }
        }
        Ok(Err(error)) => {
            tracing::warn!(event = "balance_select_failed", reason = error.code());
            metrics.record_balance_failure();
            None
        }
        Err(_join_error) => {
            tracing::warn!(event = "balance_select_failed", reason = "join_error");
            metrics.record_balance_failure();
            None
        }
    }
}
```

- [ ] **Step 4: Wire it into `upstream_peer`**

In `src/proxy.rs`, replace:

```rust
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let snapshot = ctx.snapshot.as_ref().expect("request_filter must run");
        let route = ctx.route.as_ref().expect("route must be set");
        let Some(pool) = snapshot.pool(&route.upstream_pool) else {
            return Err(pingora_core::Error::explain(
                ErrorType::HTTPStatus(503),
                "upstream pool unavailable",
            ));
        };
        let Some(lease) = pool.select(ctx.excluded_backend) else {
            return Err(pingora_core::Error::explain(
                ErrorType::HTTPStatus(503),
                "no healthy upstream",
            ));
        };
```

with:

```rust
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        let snapshot = ctx.snapshot.as_ref().expect("request_filter must run");
        let route = ctx.route.as_ref().expect("route must be set");
        let Some(pool) = snapshot.pool(&route.upstream_pool) else {
            return Err(pingora_core::Error::explain(
                ErrorType::HTTPStatus(503),
                "upstream pool unavailable",
            ));
        };
        let plugin_lease = if pool.algorithm() == crate::config::Algorithm::Plugin {
            apply_load_balancer_plugin(
                self.plugin_manager.as_ref(),
                &pool,
                session.req_header(),
                ctx.excluded_backend,
            )
            .await
        } else {
            None
        };
        let Some(lease) = plugin_lease.or_else(|| pool.select(ctx.excluded_backend)) else {
            return Err(pingora_core::Error::explain(
                ErrorType::HTTPStatus(503),
                "no healthy upstream",
            ));
        };
```

- [ ] **Step 5: Run the proxy tests to verify they pass**

Run: `cargo test --lib proxy::tests`
Expected: PASS — all tests in the module, including the new ones.

- [ ] **Step 6: Run the full workspace fmt/clippy/test gate**

Run: `cargo fmt --all -- --check`
Expected: PASS

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, no warnings

Run: `cargo test --workspace --locked` (allow up to 5 minutes)
Expected: PASS, 0 failed

- [ ] **Step 7: Commit**

```bash
git add src/proxy.rs
git commit -m "feat: apply the balance.select plugin verdict in upstream_peer"
```

---

## Task 6: Documentation and final acceptance gate

**Files:**
- Modify: `docs/PRD.md`

**Interfaces:**
- Consumes: nothing new — this task only documents what Tasks 1–5 built.

- [ ] **Step 1: Add the Phase 13G status section to the PRD**

Append to the end of `docs/PRD.md` (directly after the existing Phase 13F status section's closing paragraph):

```markdown

### Phase 13G status: custom load-balancing hook

Phase 13G is complete and adds the plugin system's first backend-selection
hook: a plugin can pick which upstream backend serves a request, for pools
whose `algorithm` is set to `plugin`. This is strictly opt-in per pool --
`RoundRobin`/`LeastConnections` pools are completely unaffected by anything
in this phase, with no plugin invocation and no metrics touched for them.

The hook runs inside `upstream_peer`, which was already `async fn`, so it
reuses Phase 13E's `spawn_blocking` pattern rather than Phase 13F's
`block_in_place` workaround -- there's no synchronous-trait-method
constraint here. When a `Plugin`-configured pool's `upstream_peer` runs, the
host builds a bounded `LoadBalanceRequest` from the pool's current
candidate snapshot (each backend's id, address, live health flag, and
in-flight count, capped at `MAX_BALANCE_CANDIDATES` = 128) plus the
request's bounded method/path/query/headers (the same
`MAX_NORMALIZED_METADATA_BYTES`/`MAX_NORMALIZED_HEADERS` budget
`waf.detect`/`transform.request` already use), and invokes the plugin.

The plugin's returned `backend_id` is never trusted outright: the host
validates it via `PoolState::select_specific`, which only leases a backend
that is currently healthy and isn't the backend that just failed on a
failover retry (`excluded_backend_id`). On any failure -- no plugin
configured, disabled, a trap, fuel exhaustion, a timeout, malformed output,
a `spawn_blocking` join failure, or an invalid `backend_id` -- the host
falls back to `pool.select(excluded)`. `PoolState::select`'s `Algorithm::
Plugin` arm behaves identically to `RoundRobin`, so this fallback needed no
new selection logic: a `Plugin`-configured pool always has a deterministic,
healthy pick available, even if its plugin is completely broken.

Exactly one active `balance.select` plugin serves the whole proxy (lowest
enabled plugin ID, same rule as every other capability), not one plugin per
pool; the request payload's `pool` field lets a single plugin branch its
logic across several `algorithm: plugin` pools if it manages more than one.
Per-pool plugin assignment remains a possible future increment.

The new manifest-validation floor, `MIN_BALANCE_INPUT_BYTES` (48 KiB),
comfortably fits under the default 64 KiB `PluginPolicy::max_output_bytes`
ceiling -- unlike Phase 13F's `transform.response`, this capability required
no config ceiling change.

Three new Prometheus counters (`bearust_plugins_balance_invocations_total`,
`bearust_plugins_balance_applied_total`,
`bearust_plugins_balance_failures_total`) surface plugin activity on the
existing plugin metrics endpoint. No new host import, capability, or
resource-limit bypass was added; every guest-controlled pointer/length is
bounds-checked identically to the Phase 13B health-check path.
```

- [ ] **Step 2: Run the final full acceptance gate**

Run: `cargo fmt --all -- --check`
Expected: PASS

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, no warnings

Run: `cargo test --workspace --locked` (allow up to 5 minutes)
Expected: PASS, 0 failed

- [ ] **Step 3: Commit**

```bash
git add docs/PRD.md
git commit -m "docs: mark phase 13g load-balancing hook complete"
```
