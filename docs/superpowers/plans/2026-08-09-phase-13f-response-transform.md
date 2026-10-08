# Phase 13F: Response Body Transform Hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add `transform.response`, the plugin system's first response-mutating hook: a plugin can rewrite the full response body (headers untouched) before it reaches the downstream client.

**Architecture:** Override two currently-unused `pingora_proxy::ProxyHttp` methods on `BearustProxy` — `response_filter` (async, strips `Content-Length` and marks eligibility) and `response_body_filter` (sync, buffers the body up to a 1 MiB cap and invokes the plugin via `tokio::task::block_in_place` at `end_of_stream`). Mirrors Phase 13E's ABI/memory/selection/fail-open conventions exactly; adds no new ABI version.

**Tech Stack:** Rust, wasmtime 27.0.0, pingora-proxy 0.8.1, tokio (multi-thread runtime, `rt-multi-thread` feature already enabled), base64 0.22.

## Global Constraints

- Reuse `abi_version: 2` and the existing alloc/write/call/read/dealloc guest memory convention — no new ABI version.
- `transform.response` capability requires `abi_version: 2`, exactly like `notify.waf_block`, `waf.detect`, `transform.request`.
- Response body buffering cap: `RESPONSE_BODY_TRANSFORM_CAP_BYTES = 1024 * 1024` (1 MiB). Bodies over this cap skip the plugin and stream through unmodified — fail open, no plugin invocation, no metrics touched.
- Compressed responses (`Content-Encoding` present and not `identity`) always skip the plugin — fail open, no plugin invocation, no metrics touched.
- **No header mutation of any kind** in this capability. Confirmed via `pingora-proxy 0.8.1`'s `proxy_h1.rs`: response headers are written to the downstream client before the body (and thus the plugin's output) is known, so header replacement based on plugin output is not buildable. `response_filter` only ever removes `Content-Length` when eligible; nothing else in this feature touches response headers.
- `MIN_TRANSFORM_RESPONSE_INPUT_BYTES = 1_572_864` (1.5 MiB) — the manifest-validation floor a `transform.response` plugin's `max_output_bytes` must meet.
- `plugins.max_output_bytes`'s hard config-validation ceiling is raised from `1024 * 1024` (1 MiB) to `2 * 1024 * 1024` (2 MiB) in `src/config/mod.rs` — required because the new floor (1.5 MiB) exceeds the old ceiling; without this change `transform.response` could never be enabled under any configuration.
- Exactly one active `transform.response` plugin: the lowest-ID (BTreeMap key order) enabled plugin declaring the capability — identical selection rule to every other capability.
- Every guest-controlled pointer/length is bounds-checked identically to the Phase 13B health-check path (`bounded_guest_range`, `write_guest_bytes`, `read_guest_bytes` — reused unchanged).
- Fail-open on every error class: no plugin manager, no active plugin, disabled plugin, trap, fuel exhaustion, timeout, malformed/oversized output, base64 decode failure, `tokio::task::block_in_place` panic. Every failure path returns the original buffered body unchanged, logs `tracing::warn!(event = "transform_response_failed", reason = ...)`, and increments `record_transform_response_failure()`.
- New Prometheus counters: `bearust_plugins_transform_response_invocations_total`, `bearust_plugins_transform_response_applied_total`, `bearust_plugins_transform_response_failures_total` — kept distinct from Phase 13E's request-side trio.
- `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace --locked` must all be clean before any task is considered done.
- Design spec: `docs/superpowers/specs/2026-08-09-phase-13f-response-transform-design.md` (read this first if anything below is ambiguous — it is the source of truth this plan implements).

---

## Task 1: SDK wire types

**Files:**
- Modify: `crates/bearust-plugin-sdk/src/lib.rs`

**Interfaces:**
- Produces: `bearust_plugin_sdk::TransformResponseRequest { status: u16, body: String }`, `bearust_plugin_sdk::TransformResponseResult { body: String }` — both `Debug + Clone + Serialize + Deserialize + PartialEq + Eq`, consumed by Task 3 (`src/plugin_runtime.rs`) and Task 4 (`src/proxy.rs`).

- [ ] **Step 1: Write the failing round-trip tests**

Add to the `#[cfg(test)] mod tests` block in `crates/bearust-plugin-sdk/src/lib.rs`, directly after the existing `transform_response_round_trips` test:

```rust
    #[test]
    fn transform_response_request_round_trips() {
        let value = TransformResponseRequest {
            status: 200,
            body: "aGVsbG8=".into(),
        };
        let bytes = encode(&value);
        let decoded: TransformResponseRequest = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn transform_response_result_round_trips() {
        let value = TransformResponseResult {
            body: "d29ybGQ=".into(),
        };
        let bytes = encode(&value);
        let decoded: TransformResponseResult = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }
```

- [ ] **Step 2: Run the tests to verify they fail to compile**

Run: `cargo test -p bearust-plugin-sdk transform_response_request_round_trips`
Expected: FAIL — `TransformResponseRequest`/`TransformResponseResult` are not yet defined.

- [ ] **Step 3: Add the wire types**

Add to `crates/bearust-plugin-sdk/src/lib.rs`, directly after the existing `TransformResponse` struct definition:

```rust
/// Input to `bearust_transform_response`. `status` is context only (not
/// mutable). `body` is the full response body the host buffered, base64
/// encoded to avoid the ~4x JSON-array expansion `WafDetectRequest::body`
/// (a `Vec<u8>`) incurs -- matching the ~4/3 base64 overhead
/// `MIN_TRANSFORM_RESPONSE_INPUT_BYTES` is sized around. There is no
/// `headers` field: unlike `TransformRequest`, this hook cannot mutate
/// headers -- pingora already sends response headers to the downstream
/// client by the time this hook's body decision is known (see
/// `docs/superpowers/specs/2026-08-09-phase-13f-response-transform-design.md`).
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformResponseRequest {
    pub status: u16,
    pub body: String,
}

/// Output of `bearust_transform_response`. The host replaces the buffered
/// response body wholesale with the base64-decoded `body` on success.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformResponseResult {
    pub body: String,
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p bearust-plugin-sdk`
Expected: PASS — all tests in the crate, including the two new ones.

- [ ] **Step 5: Commit**

```bash
git add crates/bearust-plugin-sdk/src/lib.rs
git commit -m "feat: add TransformResponseRequest/TransformResponseResult wire types to the plugin SDK"
```

---

## Task 2: Observability counters

**Files:**
- Modify: `src/observability.rs`

**Interfaces:**
- Consumes: nothing from earlier tasks.
- Produces: `PluginMetrics::record_transform_response_invocation()`, `record_transform_response_applied()`, `record_transform_response_failure()` — consumed by Task 4 (`src/proxy.rs`).

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block in `src/observability.rs`, directly after `transform_metrics_render_as_counters`:

```rust
    #[test]
    fn transform_response_metrics_render_as_counters() {
        let metrics = PluginMetrics::default();
        metrics.record_transform_response_invocation();
        metrics.record_transform_response_invocation();
        metrics.record_transform_response_applied();
        metrics.record_transform_response_failure();
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_transform_response_invocations_total 2"));
        assert!(output.contains("bearust_plugins_transform_response_applied_total 1"));
        assert!(output.contains("bearust_plugins_transform_response_failures_total 1"));
    }
```

- [ ] **Step 2: Run the test to verify it fails to compile**

Run: `cargo test transform_response_metrics_render_as_counters`
Expected: FAIL — `record_transform_response_invocation` and friends don't exist yet.

- [ ] **Step 3: Add the fields, methods, and render blocks**

In `src/observability.rs`, add three fields to `PluginMetrics` directly after `transform_failures: AtomicU64,`:

```rust
    transform_response_invocations: AtomicU64,
    transform_response_applied: AtomicU64,
    transform_response_failures: AtomicU64,
```

Add three methods directly after `record_transform_failure`:

```rust
    /// A `transform.response` plugin call was attempted (regardless of
    /// outcome).
    pub fn record_transform_response_invocation(&self) {
        self.transform_response_invocations
            .fetch_add(1, Ordering::Relaxed);
    }

    /// A `transform.response` plugin call succeeded and its returned body
    /// was applied to the outbound response.
    pub fn record_transform_response_applied(&self) {
        self.transform_response_applied.fetch_add(1, Ordering::Relaxed);
    }

    /// A `transform.response` plugin call failed: trap, timeout, fuel
    /// exhaustion, malformed export/output, output exceeding the body
    /// bound, a base64 decode failure, or a `block_in_place` panic.
    pub fn record_transform_response_failure(&self) {
        self.transform_response_failures
            .fetch_add(1, Ordering::Relaxed);
    }
```

Add three render blocks in `render_prometheus`, directly after the existing `bearust_plugins_transform_failures_total` block and before the final `output` return:

```rust
        output.push_str("# TYPE bearust_plugins_transform_response_invocations_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_transform_response_invocations_total {}\n",
            self.transform_response_invocations.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_transform_response_applied_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_transform_response_applied_total {}\n",
            self.transform_response_applied.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_transform_response_failures_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_transform_response_failures_total {}\n",
            self.transform_response_failures.load(Ordering::Relaxed)
        ));
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test transform_response_metrics_render_as_counters`
Expected: PASS

- [ ] **Step 5: Run the full observability test suite**

Run: `cargo test --lib observability`
Expected: PASS — no regressions to the existing counter tests.

- [ ] **Step 6: Commit**

```bash
git add src/observability.rs
git commit -m "feat: add transform.response plugin observability counters"
```

---

## Task 3: Capability wiring in `plugin_runtime.rs` and the config ceiling fix

**Files:**
- Modify: `src/plugin_runtime.rs`
- Modify: `src/config/mod.rs`
- Modify: `tests/config_validation.rs`
- Modify: `tests/plugin_runtime.rs`
- Create: `tests/fixtures/plugins/transform_response_v2/plugin.toml`
- Create: `tests/fixtures/plugins/transform_response_v2/transform_response_v2.wat`
- Create: `tests/fixtures/plugins/transform_response_v2/README.md`

**Interfaces:**
- Consumes: `bearust_plugin_sdk::TransformResponseRequest`/`TransformResponseResult` (Task 1).
- Produces: `CompiledPlugin::transform_response(&self, request: &bearust_plugin_sdk::TransformResponseRequest) -> Result<bearust_plugin_sdk::TransformResponseResult, PluginError>`, `PluginManager::transform_response_plugin(&self) -> Option<Arc<CompiledPlugin>>` — both consumed by Task 4 (`src/proxy.rs`). `MIN_TRANSFORM_RESPONSE_INPUT_BYTES: usize = 1_572_864` is a private module constant (not exported), referenced only within this file.

### Part A — the fixture

- [ ] **Step 1: Create the fixture manifest**

Create `tests/fixtures/plugins/transform_response_v2/plugin.toml`:

```toml
id = "transform-response-v2"
display_name = "Deterministic response body transformer"
abi_version = 2
module = "transform_response_v2.wasm"
capabilities = ["transform.response"]

[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1572864
```

- [ ] **Step 2: Create the fixture WAT module**

Create `tests/fixtures/plugins/transform_response_v2/transform_response_v2.wat`. This ignores the host-supplied input and always returns the fixed JSON literal `{"body":"aGVsbG8="}` (19 bytes; `aGVsbG8=` base64-decodes to `hello`), proving the alloc/write/call/read/dealloc round trip end to end, exactly like `transform_request_v2`'s fixture proves it for the request-side hook:

```wat
;; Deterministic Phase 13F fixture. Build with:
;;   wat2wasm transform_response_v2.wat -o transform_response_v2.wasm
;;
;; The test suite parses this WAT with the pinned `wat` dev dependency, so the
;; generated binary and any compiler cache are intentionally not checked in.
;;
;; Ignores the JSON the host writes as input and always returns the fixed
;; JSON literal `{"body":"aGVsbG8="}` (19 bytes; base64 for "hello") stored
;; at memory offset 0, proving the host's alloc/write/call/read/dealloc
;; round trip end to end. Every abi_version: 2 module must also export
;; bearust_health_check_v2 regardless of its declared capabilities (an
;; existing Phase 13B requirement); this fixture is never health-checked in
;; tests, so that export is a trivial stub.
(module
  (memory (export "memory") 1)
  (global $heap_ptr (mut i32) (i32.const 1024))
  (data (i32.const 0) "{\22body\22:\22aGVsbG8=\22}")

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

  (func (export "bearust_transform_response") (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
      (i64.extend_i32_u (i32.const 19)))))
```

- [ ] **Step 3: Create the fixture README**

Create `tests/fixtures/plugins/transform_response_v2/README.md`:

```markdown
# Deterministic response body transformer fixture

Local-only, no-import WASM fixture for the Phase 13F `transform.response`
acceptance tests. Exports `bearust_alloc`/`bearust_dealloc`/
`bearust_transform_response` per the memory convention in
`docs/superpowers/specs/2026-08-09-phase-13f-response-transform-design.md`,
plus a trivial `bearust_health_check_v2` stub (required unconditionally of
every `abi_version: 2` module, independent of declared capabilities). It
ignores the host-supplied input and always returns the fixed body
`aGVsbG8=` (base64 for `hello`), so the test suite can assert an exact
outcome while still exercising the full alloc/write/call/read/dealloc round
trip.

The checked-in WAT source is preferred over a generated binary for the same
reproducibility reasons as `tests/fixtures/plugins/health_ok/`.
```

### Part B — `src/plugin_runtime.rs`

- [ ] **Step 4: Write the failing manifest-validation and export tests**

Add to `tests/plugin_runtime.rs`, directly after `transform_capability_rejects_output_limit_below_the_transform_input_floor` (around line 426):

```rust
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
```

Add to `tests/plugin_runtime.rs`, directly after `v2_missing_transform_export_is_abi_mismatch` (around line 656):

```rust
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
```

Add to `tests/plugin_runtime.rs`, directly after `v2_out_of_bounds_alloc_pointer_is_trap_on_the_transform_input_write` (around line 736):

```rust
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
```

Add to `tests/plugin_runtime.rs`, directly after `v2_malformed_transform_output_is_trap` (around line 759):

```rust
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
```

Add to `tests/plugin_runtime.rs`, at the end of the file (directly after `transform_plugin_is_none_when_disabled`):

```rust

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
    manager
        .set_enabled("transform-response-v2", false)
        .unwrap();
    assert!(manager.transform_response_plugin().is_none());
}
```

- [ ] **Step 5: Run the new tests to verify they fail to compile**

Run: `cargo test --test plugin_runtime transform_response`
Expected: FAIL — none of `"transform.response"`, `MIN_TRANSFORM_RESPONSE_INPUT_BYTES`, `transform_response`, or `transform_response_plugin` exist yet.

- [ ] **Step 6: Extend `ALLOWED_CAPABILITIES` and add the new floor constant**

In `src/plugin_runtime.rs`, replace:

```rust
const ALLOWED_CAPABILITIES: [&str; 4] = [
    "health_check",
    "notify.waf_block",
    "waf.detect",
    "transform.request",
];
```

with:

```rust
const ALLOWED_CAPABILITIES: [&str; 5] = [
    "health_check",
    "notify.waf_block",
    "waf.detect",
    "transform.request",
    "transform.response",
];
```

Add directly after the `MIN_TRANSFORM_INPUT_BYTES` constant and its doc comment:

```rust
/// `transform.response` carries the full buffered response body (capped at
/// 1 MiB by `src/proxy.rs::RESPONSE_BODY_TRANSFORM_CAP_BYTES`) as a base64
/// string in both directions -- no headers field, unlike
/// `transform.request` (see the Phase 13F design spec's Non-goals: pingora
/// sends response headers to the client before this hook's body decision
/// is known, so header mutation isn't buildable here). Base64 inflates the
/// 1 MiB cap by ~4/3 (~1.33 MiB) with no JSON-escaping overhead (base64's
/// alphabet needs none), plus trivial JSON structural overhead for
/// `{"status":...,"body":"..."}`. This floor gives comfortable headroom
/// above that worst case while staying under the 2 MiB
/// `plugins.max_output_bytes` config ceiling (see
/// `src/config/mod.rs::PluginConfig::validate`, raised from 1 MiB by this
/// same phase). Deliberately its own constant -- not shared with
/// `MIN_TRANSFORM_INPUT_BYTES` (headers only, no body, request side).
const MIN_TRANSFORM_RESPONSE_INPUT_BYTES: usize = 1_572_864;
```

- [ ] **Step 7: Add `has_transform_response` to `CompiledPlugin` and wire it through `compile`**

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
}
```

Replace the whole `let (has_health_check, has_notify_waf_block, has_waf_detect, has_transform_request) = match manifest.abi_version { ... };` block in `PluginEngine::compile` (and the `Ok(CompiledPlugin { ... })` construction right after it) with:

```rust
        let (
            has_health_check,
            has_notify_waf_block,
            has_waf_detect,
            has_transform_request,
            has_transform_response,
        ) = match manifest.abi_version {
            1 => {
                let has_health_check = match instance
                    .get_typed_func::<(), i32>(&mut store, "bearust_health_check")
                {
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
                (has_health_check, false, false, false, false)
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
                        .get_typed_func::<(i32, i32), i32>(
                            &mut store,
                            "bearust_notify_waf_block",
                        )
                        .map_err(|_| PluginError::AbiMismatch)?;
                    true
                } else {
                    false
                };
                let has_waf_detect = if manifest.capabilities.iter().any(|c| c == "waf.detect")
                {
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
                        .get_typed_func::<(i32, i32), i64>(
                            &mut store,
                            "bearust_transform_request",
                        )
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
                        .get_typed_func::<(i32, i32), i64>(
                            &mut store,
                            "bearust_transform_response",
                        )
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
        })
```

- [ ] **Step 8: Add `CompiledPlugin::transform_response`**

Add to `src/plugin_runtime.rs`, directly after the `transform` method (inside `impl CompiledPlugin`):

```rust
    /// Invokes the `transform.response` capability's entry point on an
    /// `abi_version: 2` plugin that declared it. Returns the plugin's
    /// replacement body or a `PluginError` for any host-detected failure
    /// (trap, timeout, fuel exhaustion, malformed export/output, or an
    /// out-of-bounds pointer). Never panics: every guest-controlled
    /// pointer/length is bounds-checked exactly as in `health_check`'s v2
    /// path.
    pub fn transform_response(
        &self,
        request: &bearust_plugin_sdk::TransformResponseRequest,
    ) -> Result<bearust_plugin_sdk::TransformResponseResult, PluginError> {
        if !self.has_transform_response {
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
        let transform = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "bearust_transform_response")
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

        let packed = transform
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
            && self
                .capabilities
                .iter()
                .any(|c| c == "notify.waf_block" || c == "waf.detect" || c == "transform.request")
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
            })
        {
            return Err(PluginError::InvalidManifest);
        }
```

Add directly after the existing `transform.request` floor check (`if self.capabilities.iter().any(|c| c == "transform.request") ... `):

```rust
        if self.capabilities.iter().any(|c| c == "transform.response")
            && self.limits.max_output_bytes < MIN_TRANSFORM_RESPONSE_INPUT_BYTES
        {
            return Err(PluginError::InvalidManifest);
        }
```

- [ ] **Step 10: Add `PluginManager::transform_response_plugin`**

Add to `src/plugin_runtime.rs`, directly after the `transform_plugin` method (inside `impl PluginManager`):

```rust
    /// Returns the compiled plugin currently acting as the active response
    /// transformer, if any: the first (lowest plugin ID) enabled plugin
    /// whose manifest declared `transform.response`. Mirrors
    /// `transform_plugin()`'s selection rule exactly -- at most one plugin
    /// is ever treated as the active transformer; any other plugin also
    /// declaring the capability is simply never selected.
    pub fn transform_response_plugin(&self) -> Option<Arc<CompiledPlugin>> {
        self.current
            .load_full()
            .plugins
            .values()
            .find_map(|record| {
                if !record.status.enabled {
                    return None;
                }
                let compiled = record.compiled.as_ref()?;
                compiled
                    .has_transform_response
                    .then(|| Arc::clone(compiled))
            })
    }
```

- [ ] **Step 11: Run the plugin_runtime tests to verify they pass**

Run: `cargo test --test plugin_runtime`
Expected: PASS — all tests, including the new `transform_response_*` and `v2_*_transform_response_*` ones.

### Part C — the config ceiling fix

- [ ] **Step 12: Update the failing config-validation boundary test**

In `tests/config_validation.rs`, replace the line `"max_output_bytes = 1048577",` (in the `for replacement in [...]` list inside `parses_plugin_configuration_and_rejects_invalid_limits`) with:

```rust
        "max_output_bytes = 2097153",
```

- [ ] **Step 13: Run the config test to verify it fails**

Run: `cargo test --test config_validation parses_plugin_configuration_and_rejects_invalid_limits`
Expected: FAIL — `2097153` is currently accepted because the ceiling is still `1024 * 1024`.

- [ ] **Step 14: Raise the ceiling**

In `src/config/mod.rs`, replace:

```rust
        check_limit!(
            "plugins.max_output_bytes",
            self.max_output_bytes,
            1024 * 1024usize
        );
```

with:

```rust
        // Raised from 1 MiB to 2 MiB in Phase 13F: a `transform.response`
        // plugin's manifest-validation floor
        // (`plugin_runtime::MIN_TRANSFORM_RESPONSE_INPUT_BYTES`, 1.5 MiB)
        // would otherwise be impossible to satisfy under any configuration.
        check_limit!(
            "plugins.max_output_bytes",
            self.max_output_bytes,
            2 * 1024 * 1024usize
        );
```

- [ ] **Step 15: Run the config test to verify it passes**

Run: `cargo test --test config_validation`
Expected: PASS — all tests in the file.

- [ ] **Step 16: Run the full workspace fmt/clippy/test gate for this task**

Run: `cargo fmt --all -- --check`
Expected: PASS

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, no warnings

Run: `cargo test --workspace --locked` (allow up to 5 minutes)
Expected: PASS, 0 failed

- [ ] **Step 17: Commit**

```bash
git add src/plugin_runtime.rs src/config/mod.rs tests/config_validation.rs tests/plugin_runtime.rs tests/fixtures/plugins/transform_response_v2/
git commit -m "feat: add transform.response plugin capability, export validation, and invocation"
```

---

## Task 4: Wire the transformer into `src/proxy.rs`

**Files:**
- Modify: `src/proxy.rs`

**Interfaces:**
- Consumes: `bearust_plugin_sdk::{TransformResponseRequest, TransformResponseResult}` (Task 1), `PluginManager::transform_response_plugin()`/`CompiledPlugin::transform_response()` (Task 3), `PluginMetrics::record_transform_response_{invocation,applied,failure}()` (Task 2).
- Produces: nothing consumed by later tasks — this is the last capability-wiring task.

- [ ] **Step 1: Write the failing tests for the pure helper functions**

Add to `src/proxy.rs`'s `#[cfg(test)] mod tests` block. First, extend the existing `use super::{...}` import list (around line 1233) to include the four new names:

```rust
    use super::{
        accumulate_response_chunk, apply_transform_plugin, apply_transform_response_plugin,
        apply_waf_detector, error_status, invoke_analytics_changed, is_valid_transform_headers,
        reassert_protected_request_headers, should_buffer_response_for_transform,
        waf_block_event, RequestContext, RESPONSE_BODY_TRANSFORM_CAP_BYTES,
    };
```

Change the existing `use pingora_http::RequestHeader;` import (around line 1238) to:

```rust
    use pingora_http::{RequestHeader, ResponseHeader};
```

Add the following block at the end of the test module (after the last existing test, before the closing `}` of `mod tests`):

```rust

    fn transform_response_manager(enabled: bool) -> Arc<PluginManager> {
        let root = tempdir().unwrap();
        let plugin = root.path().join("transform-response-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/transform_response_v2/plugin.toml"),
        )
        .unwrap();
        let module = wat::parse_str(include_str!(
            "../tests/fixtures/plugins/transform_response_v2/transform_response_v2.wat"
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
        if !enabled {
            manager
                .set_enabled("transform-response-v2", false)
                .unwrap();
        }
        manager
    }

    fn sample_response_header(status: u16) -> ResponseHeader {
        ResponseHeader::build(status, None).unwrap()
    }

    #[test]
    fn eligible_when_a_transformer_is_enabled_and_no_content_encoding() {
        let manager = transform_response_manager(true);
        let response = sample_response_header(200);
        assert!(should_buffer_response_for_transform(
            Some(&manager),
            &response
        ));
    }

    #[test]
    fn eligible_when_content_encoding_is_identity() {
        let manager = transform_response_manager(true);
        let mut response = sample_response_header(200);
        response.insert_header("content-encoding", "identity").unwrap();
        assert!(should_buffer_response_for_transform(
            Some(&manager),
            &response
        ));
    }

    #[test]
    fn ineligible_without_a_plugin_manager() {
        let response = sample_response_header(200);
        assert!(!should_buffer_response_for_transform(None, &response));
    }

    #[test]
    fn ineligible_when_no_transformer_is_configured() {
        let manager = PluginManager::new(PluginConfig::default());
        let response = sample_response_header(200);
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &response
        ));
    }

    #[test]
    fn ineligible_when_the_transformer_is_disabled() {
        let manager = transform_response_manager(false);
        let response = sample_response_header(200);
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &response
        ));
    }

    #[test]
    fn ineligible_when_the_response_is_compressed() {
        let manager = transform_response_manager(true);
        let mut response = sample_response_header(200);
        response.insert_header("content-encoding", "gzip").unwrap();
        assert!(!should_buffer_response_for_transform(
            Some(&manager),
            &response
        ));
    }

    #[test]
    fn accumulate_response_chunk_appends_within_cap() {
        let mut ctx = RequestContext {
            transform_response_buffering: true,
            ..RequestContext::default()
        };
        let overflow = accumulate_response_chunk(&mut ctx, b"hello");
        assert!(overflow.is_none());
        assert_eq!(ctx.transform_response_buffer, b"hello");
        assert!(ctx.transform_response_buffering);
    }

    #[test]
    fn accumulate_response_chunk_aborts_buffering_past_the_cap() {
        let mut ctx = RequestContext {
            transform_response_buffering: true,
            transform_response_buffer: vec![0u8; RESPONSE_BODY_TRANSFORM_CAP_BYTES - 2],
            ..RequestContext::default()
        };
        let overflow =
            accumulate_response_chunk(&mut ctx, b"abcd").expect("chunk exceeds the cap");
        assert_eq!(overflow.len(), RESPONSE_BODY_TRANSFORM_CAP_BYTES - 2 + 4);
        assert!(!ctx.transform_response_buffering);
        assert!(ctx.transform_response_buffer.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_successful_response_transform_replaces_the_body() {
        let manager = transform_response_manager(true);
        let body = apply_transform_response_plugin(Some(&manager), 200, b"original".to_vec());
        assert_eq!(body, b"hello");
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_response_invocations_total 1"));
        assert!(output.contains("bearust_plugins_transform_response_applied_total 1"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn no_response_transformer_configured_leaves_body_unchanged() {
        let manager = PluginManager::new(PluginConfig::default());
        let body = apply_transform_response_plugin(Some(&manager), 200, b"original".to_vec());
        assert_eq!(body, b"original");
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_response_invocations_total 0"));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_disabled_response_transformer_leaves_body_unchanged() {
        let manager = transform_response_manager(false);
        let body = apply_transform_response_plugin(Some(&manager), 200, b"original".to_vec());
        assert_eq!(body, b"original");
    }

    #[test]
    fn no_plugin_manager_leaves_response_body_unchanged() {
        let body = apply_transform_response_plugin(None, 200, b"original".to_vec());
        assert_eq!(body, b"original");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_trapping_response_transformer_fails_open_and_counts_a_failure() {
        let root = tempdir().unwrap();
        let plugin = root.path().join("transform-response-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/transform_response_v2/plugin.toml"),
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
            (func (export "bearust_transform_response") (param i32 i32) (result i64) unreachable))"#;
        let module = wat::parse_str(wat).unwrap();
        fs::write(plugin.join("transform_response_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            max_output_bytes: 2 * 1024 * 1024,
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();

        let body = apply_transform_response_plugin(Some(&manager), 200, b"original".to_vec());
        assert_eq!(body, b"original");
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_response_failures_total 1"));
        assert!(output.contains("bearust_plugins_transform_response_applied_total 0"));
    }
```

- [ ] **Step 2: Run the tests to verify they fail to compile**

Run: `cargo test --lib proxy::tests`
Expected: FAIL — none of `RESPONSE_BODY_TRANSFORM_CAP_BYTES`, `should_buffer_response_for_transform`, `accumulate_response_chunk`, `apply_transform_response_plugin`, or `RequestContext::transform_response_*` fields exist yet.

- [ ] **Step 3: Add imports and the CTX fields**

In `src/proxy.rs`, change the `use std::{...}` import (line 22) from:

```rust
use std::{collections::HashMap, sync::Arc, time::Instant};
```

to:

```rust
use base64::Engine as _;
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};
```

Add three fields to `RequestContext` (directly after `pub rate_limit_decision: Option<RateLimitDecision>,`):

```rust
    pub transform_response_buffering: bool,
    pub transform_response_buffer: Vec<u8>,
    pub transform_response_status: u16,
```

Add the matching defaults to `impl Default for RequestContext` (directly after `rate_limit_decision: None,`):

```rust
            transform_response_buffering: false,
            transform_response_buffer: Vec::new(),
            transform_response_status: 0,
```

- [ ] **Step 4: Add the module-level constant and the three helper functions**

Add to `src/proxy.rs`, directly after the `apply_transform_plugin` function (i.e. after its closing `}`, before `reassert_protected_request_headers`):

```rust
/// Response bodies larger than this are never handed to a
/// `transform.response` plugin -- fail open to unmodified passthrough
/// instead. Bounds per-request proxy memory from a single large upstream
/// response; matches the design spec's chosen cap for Bearust's typical
/// API/JSON/HTML traffic.
const RESPONSE_BODY_TRANSFORM_CAP_BYTES: usize = 1024 * 1024;

/// Whether `response`'s body should be buffered for a `transform.response`
/// plugin: a plugin must be enabled and currently declaring the
/// capability, and the response must not be compressed -- a plugin would
/// otherwise receive opaque bytes it cannot meaningfully transform, and
/// could be misused to launder a compressed payload past any future
/// response inspection. Pure and side-effect free.
fn should_buffer_response_for_transform(
    plugin_manager: Option<&Arc<PluginManager>>,
    response: &ResponseHeader,
) -> bool {
    let Some(manager) = plugin_manager else {
        return false;
    };
    if manager.transform_response_plugin().is_none() {
        return false;
    }
    match response
        .headers
        .get("content-encoding")
        .and_then(|value| value.to_str().ok())
    {
        None => true,
        Some(value) => value.is_empty() || value.eq_ignore_ascii_case("identity"),
    }
}

/// Accumulates `chunk` into `ctx`'s response body buffer, bounded by
/// `RESPONSE_BODY_TRANSFORM_CAP_BYTES`. Returns `Some(overflow_bytes)` if
/// the cap was exceeded -- the combined prefix-so-far plus this chunk,
/// ready to be emitted as-is -- with `ctx.transform_response_buffering`
/// left `false` (buffering aborted, no further chunks are accumulated).
/// Returns `None` if the chunk fit within the cap (buffering continues,
/// nothing should be emitted yet).
fn accumulate_response_chunk(ctx: &mut RequestContext, chunk: &[u8]) -> Option<Vec<u8>> {
    let remaining =
        RESPONSE_BODY_TRANSFORM_CAP_BYTES.saturating_sub(ctx.transform_response_buffer.len());
    if chunk.len() > remaining {
        ctx.transform_response_buffer
            .extend_from_slice(&chunk[..remaining]);
        let mut overflow = std::mem::take(&mut ctx.transform_response_buffer);
        overflow.extend_from_slice(&chunk[remaining..]);
        ctx.transform_response_buffering = false;
        return Some(overflow);
    }
    ctx.transform_response_buffer.extend_from_slice(chunk);
    None
}

/// Runs the registered `transform.response` plugin (if any) against the
/// fully buffered response `body` and returns its replacement on success,
/// or `body` unchanged on any failure. Synchronous from the caller's point
/// of view -- `response_body_filter` is not an `async fn`, unlike the
/// request-side hooks -- but offloads the blocking wasmtime call via
/// `tokio::task::block_in_place` so it never stalls the calling worker
/// thread's other queued tasks the way a bare synchronous call would.
/// Fails open on every error class: no plugin manager, no plugin currently
/// declaring the capability, a disabled plugin, a trap/timeout/fuel
/// exhaustion, a malformed or oversized output body, a base64 decode
/// failure, or a `block_in_place` panic all return `body` unchanged (after
/// counting a failure metric where applicable).
fn apply_transform_response_plugin(
    plugin_manager: Option<&Arc<PluginManager>>,
    status: u16,
    body: Vec<u8>,
) -> Vec<u8> {
    let Some(manager) = plugin_manager else {
        return body;
    };
    let Some(transformer) = manager.transform_response_plugin() else {
        return body;
    };
    let metrics = manager.metrics();
    metrics.record_transform_response_invocation();
    let request = bearust_plugin_sdk::TransformResponseRequest {
        status,
        body: base64::engine::general_purpose::STANDARD.encode(&body),
    };
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        tokio::task::block_in_place(|| transformer.transform_response(&request))
    }));
    match outcome {
        Ok(Ok(response)) => {
            match base64::engine::general_purpose::STANDARD.decode(&response.body) {
                Ok(decoded) if decoded.len() <= RESPONSE_BODY_TRANSFORM_CAP_BYTES => {
                    metrics.record_transform_response_applied();
                    decoded
                }
                Ok(_) => {
                    tracing::warn!(
                        event = "transform_response_failed",
                        reason = "output_bounds_exceeded"
                    );
                    metrics.record_transform_response_failure();
                    body
                }
                Err(_) => {
                    tracing::warn!(
                        event = "transform_response_failed",
                        reason = "invalid_base64"
                    );
                    metrics.record_transform_response_failure();
                    body
                }
            }
        }
        Ok(Err(error)) => {
            tracing::warn!(event = "transform_response_failed", reason = error.code());
            metrics.record_transform_response_failure();
            body
        }
        Err(_panic) => {
            tracing::warn!(event = "transform_response_failed", reason = "panic");
            metrics.record_transform_response_failure();
            body
        }
    }
}
```

- [ ] **Step 5: Add the `response_filter` and `response_body_filter` overrides**

In `src/proxy.rs`, inside `impl ProxyHttp for BearustProxy`, add the following two methods directly after `request_body_filter` (i.e. after its closing `}`, before `logging`):

```rust
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if should_buffer_response_for_transform(self.plugin_manager.as_ref(), upstream_response) {
            upstream_response.remove_header("content-length");
            ctx.transform_response_buffering = true;
            ctx.transform_response_status = upstream_response.status.as_u16();
        }
        Ok(())
    }

    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<Option<Duration>> {
        if !ctx.transform_response_buffering {
            return Ok(None);
        }
        if let Some(chunk) = body.take() {
            if let Some(overflow) = accumulate_response_chunk(ctx, &chunk) {
                *body = Some(Bytes::from(overflow));
                return Ok(None);
            }
        }
        if end_of_stream {
            let buffer = std::mem::take(&mut ctx.transform_response_buffer);
            ctx.transform_response_buffering = false;
            *body = Some(Bytes::from(apply_transform_response_plugin(
                self.plugin_manager.as_ref(),
                ctx.transform_response_status,
                buffer,
            )));
        }
        Ok(None)
    }
```

- [ ] **Step 6: Run the proxy tests to verify they pass**

Run: `cargo test --lib proxy::tests`
Expected: PASS — all tests in the module, including the new ones.

- [ ] **Step 7: Run the full workspace fmt/clippy/test gate**

Run: `cargo fmt --all -- --check`
Expected: PASS

Run: `cargo clippy --workspace --all-targets -- -D warnings`
Expected: PASS, no warnings

Run: `cargo test --workspace --locked` (allow up to 5 minutes)
Expected: PASS, 0 failed

- [ ] **Step 8: Commit**

```bash
git add src/proxy.rs
git commit -m "feat: buffer and apply the transform.response plugin verdict in response_body_filter"
```

---

## Task 5: Documentation and final acceptance gate

**Files:**
- Modify: `docs/PRD.md`

**Interfaces:**
- Consumes: nothing new — this task only documents what Tasks 1–4 built.

- [ ] **Step 1: Add the Phase 13F status section to the PRD**

Append to the end of `docs/PRD.md` (directly after the existing Phase 13E status section's closing paragraph):

```markdown

### Phase 13F status: response body transform hook

Phase 13F is complete and adds the plugin system's first response-mutating
hook: a plugin can rewrite the full response body before it is sent to the
downstream client. It overrides two previously-unused `ProxyHttp` methods,
`response_filter` and `response_body_filter`, on `BearustProxy`.

Discovered during implementation planning: `pingora-proxy 0.8.1` sends the
response header task to the downstream client as soon as `response_filter`
returns, before body chunks have necessarily even arrived from upstream.
By the time `response_body_filter`'s `end_of_stream` call knows the
plugin's output, headers are already on the wire, so header mutation based
on the plugin's output is not buildable against this pingora version.
Phase 13F is therefore scoped to the response body only; a `transform.response`
plugin never receives or returns headers, closing off any header
injection/spoofing surface for this capability by scope rather than by
filtering.

`response_filter` decides eligibility -- a plugin must be enabled and
currently declaring `transform.response`, and the response must not be
compressed (a non-identity `Content-Encoding` skips the plugin entirely,
since it would otherwise receive opaque bytes it cannot meaningfully
transform). When eligible, `Content-Length` is stripped; pingora's own H1
pipeline then automatically upgrades framing to `Transfer-Encoding:
chunked`, so the host never needs to (and structurally cannot)
reconstruct `Content-Length` after the transform's outcome is known.

`response_body_filter` buffers the response body up to a 1 MiB cap
(`RESPONSE_BODY_TRANSFORM_CAP_BYTES`). A body exceeding the cap aborts
buffering and streams through unmodified -- fail open, no plugin
invocation. Within the cap, at `end_of_stream`, the plugin is invoked with
the full buffered body (and the response status, informational only) via
`tokio::task::block_in_place`, since `response_body_filter` is a
synchronous `ProxyHttp` method (unlike the request-side hooks, which are
`async fn` and could use `spawn_blocking`). `block_in_place` lets the
blocking wasmtime call run without stalling the calling worker thread's
other queued tasks, requiring Bearust's Tokio runtime to be multi-threaded
(already the case: `rt-multi-thread` is enabled).

Fail-open covers every error class: no plugin manager, no active plugin, a
disabled plugin, a trap, fuel exhaustion, a timeout, malformed or
oversized output, a base64 decode failure, or a `block_in_place` panic all
leave the original buffered body unchanged. The body travels through the
same JSON-over-linear-memory channel every other `abi_version: 2`
capability uses, with the raw bytes base64-encoded into a `body: String`
field (`bearust_plugin_sdk::TransformResponseRequest`/
`TransformResponseResult`) to avoid the ~4x expansion a JSON byte array
would incur.

The new manifest-validation floor, `MIN_TRANSFORM_RESPONSE_INPUT_BYTES`
(1.5 MiB), sits far above every other capability's floor -- sized for the
1 MiB body cap's ~4/3 base64 inflation. This exceeded the pre-existing
hard config-validation ceiling on `plugins.max_output_bytes` (1 MiB), so
this phase also raises that ceiling to 2 MiB. Enabling any
`transform.response` plugin therefore requires an operator to
deliberately raise `plugins.max_output_bytes` in config -- a conscious
per-deployment opt-in to a materially larger per-request memory
footprint, not a silent default change. Every other capability's default
ceiling (64 KiB) is unaffected, since each plugin's own `max_output_bytes`
is independently validated against its declared capabilities.

Three new Prometheus counters
(`bearust_plugins_transform_response_invocations_total`,
`bearust_plugins_transform_response_applied_total`,
`bearust_plugins_transform_response_failures_total`) surface plugin
activity on the existing plugin metrics endpoint, kept distinct from
Phase 13E's request-side trio. No new host import, capability, or
resource-limit bypass was added; every guest-controlled pointer/length is
bounds-checked identically to the Phase 13B health-check path.

Response header transform, chunked/streaming body transform, and
compressed-body transform all remain deliberately out of scope; see
`docs/superpowers/specs/2026-08-09-phase-13f-response-transform-design.md`
for the full rationale and follow-up increments.
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
git commit -m "docs: mark phase 13f response body transform hook complete"
```
