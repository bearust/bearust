# Phase 13E: Request Header Transform Hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a single, fail-open WASM plugin rewrite the outbound request's headers (and only headers) right before they are sent upstream, reusing the exact ABI/memory/selection conventions Phase 13B–13D already established.

**Architecture:** A new `abi_version: 2` capability, `transform.request`, exported as `bearust_transform_request(ptr: i32, len: i32) -> i64`. `src/proxy.rs::upstream_request_filter` invokes the lowest-ID enabled plugin declaring the capability via `spawn_blocking`, passing a bounded `TransformRequest`; on success it wholesale-replaces the outbound header list with the plugin's `TransformResponse.headers`, then the existing Host/X-Forwarded-For/X-Request-Id reassertion (already the next code in that function) runs unconditionally, so the plugin can never spoof or drop those three. Every failure class (no plugin, trap, timeout, fuel exhaustion, malformed/oversized output, join failure) leaves the header list untouched.

**Tech Stack:** Rust, wasmtime `=27.0.0`, pingora (`pingora-http::RequestHeader`), tokio (`spawn_blocking`), the existing `bearust-plugin-sdk` JSON-over-linear-memory convention.

## Global Constraints

- Reuses `SUPPORTED_ABI_VERSIONS: RangeInclusive<u32> = 1..=2` — no new ABI version.
- `ALLOWED_CAPABILITIES` in `src/plugin_runtime.rs` grows from 3 to 4 entries: adds `"transform.request"`.
- `transform.request` requires `abi_version: 2`, exactly like `notify.waf_block` and `waf.detect`.
- New manifest-validation floor `MIN_TRANSFORM_INPUT_BYTES = 32_768` (32 KiB) — a plugin declaring `transform.request` with a smaller `max_output_bytes` is rejected at manifest validation, not silently broken at invocation time.
- Selection rule: exactly one active transform plugin — lowest plugin ID among enabled plugins declaring `transform.request` — mirroring `waf_block_sink_plugin`/`waf_detector_plugin` exactly.
- Fail-open on every error class; every failure increments `record_transform_failure()` and logs `tracing::warn!(event = "transform_request_failed", reason = ...)`.
- `Host`, `X-Forwarded-For`, `X-Request-Id` are reasserted after the transform runs (or fails), unconditionally, using the existing insertion code already present in `upstream_request_filter` — no new code needed for this, only correct ordering.
- No body transform, no blocking/verdict semantics, no plugin chaining — spec: `docs/superpowers/specs/2026-08-08-phase-13e-transform-request-design.md`.

---

### Task 1: `bearust-plugin-sdk` wire types

**Files:**
- Modify: `crates/bearust-plugin-sdk/src/lib.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `bearust_plugin_sdk::TransformRequest { method: String, path: String, query: String, headers: Vec<(String, String)> }`, `bearust_plugin_sdk::TransformResponse { headers: Vec<(String, String)> }`. Used by Tasks 2–4. Guest export contract: `bearust_transform_request(ptr: i32, len: i32) -> i64`.

- [ ] **Step 1: Add the failing round-trip tests**

Add to the existing `#[cfg(test)] mod tests` block in `crates/bearust-plugin-sdk/src/lib.rs`, directly after `waf_detect_verdict_round_trips` (around line 107):

```rust
    #[test]
    fn transform_request_round_trips() {
        let value = TransformRequest {
            method: "GET".into(),
            path: "/api/orders".into(),
            query: "page=2".into(),
            headers: vec![("host".into(), "example.com".into())],
        };
        let bytes = encode(&value);
        let decoded: TransformRequest = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn transform_response_round_trips() {
        let value = TransformResponse {
            headers: vec![
                ("x-region".into(), "us-east-1".into()),
                ("host".into(), "internal.example.com".into()),
            ],
        };
        let bytes = encode(&value);
        let decoded: TransformResponse = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `cargo test -p bearust-plugin-sdk`
Expected: FAIL to compile — `TransformRequest`/`TransformResponse` not found.

- [ ] **Step 3: Add the types**

Add to `crates/bearust-plugin-sdk/src/lib.rs`, at the end of the file, directly after the `WafDetectVerdict` struct:

```rust
/// Input to `bearust_transform_request`. The host
/// (`src/proxy.rs::transform_request`) bounds `method`/`path`/`query`/
/// `headers` to the same combined `MAX_NORMALIZED_METADATA_BYTES` /
/// `MAX_NORMALIZED_HEADERS` / `MAX_NORMALIZED_FIELD_BYTES` budgets
/// `waf_detect_request` uses for the same raw fields. There is no `body`
/// field: this hook only ever sees and returns headers.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
}

/// Output of `bearust_transform_request`. The host wholesale-replaces the
/// outbound request's header list with `headers` (subject to the same
/// bounds checked on the input side), then unconditionally reasserts
/// `Host`, `X-Forwarded-For`, and `X-Request-Id` afterward — this hook can
/// never remove, blank, or spoof those three.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformResponse {
    pub headers: Vec<(String, String)>,
}
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `cargo test -p bearust-plugin-sdk`
Expected: PASS, including the two new round-trip tests.

- [ ] **Step 5: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add crates/bearust-plugin-sdk/src/lib.rs
git commit -m "feat: add TransformRequest/TransformResponse wire types to the plugin SDK"
```

---

### Task 2: Observability counters

**Files:**
- Modify: `src/observability.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `PluginMetrics::record_transform_invocation()`, `PluginMetrics::record_transform_applied()`, `PluginMetrics::record_transform_failure()`. Used by Task 4.

- [ ] **Step 1: Add the failing test**

Add to the existing `#[cfg(test)] mod tests` block in `src/observability.rs`, directly after `waf_detect_metrics_render_as_counters` (around line 377):

```rust
    #[test]
    fn transform_metrics_render_as_counters() {
        let metrics = PluginMetrics::default();
        metrics.record_transform_invocation();
        metrics.record_transform_invocation();
        metrics.record_transform_applied();
        metrics.record_transform_failure();
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_transform_invocations_total 2"));
        assert!(output.contains("bearust_plugins_transform_applied_total 1"));
        assert!(output.contains("bearust_plugins_transform_failures_total 1"));
    }
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `cargo test --lib observability`
Expected: FAIL to compile — `record_transform_invocation`/`record_transform_applied`/`record_transform_failure` not found.

- [ ] **Step 3: Add the fields, methods, and Prometheus output**

In `src/observability.rs`, add three fields to `PluginMetrics` (directly after `waf_detect_failures: AtomicU64,`):

```rust
    transform_invocations: AtomicU64,
    transform_applied: AtomicU64,
    transform_failures: AtomicU64,
```

Add three methods to `impl PluginMetrics`, directly after `record_waf_detect_failure`:

```rust
    /// A `transform.request` plugin call was attempted (regardless of
    /// outcome).
    pub fn record_transform_invocation(&self) {
        self.transform_invocations.fetch_add(1, Ordering::Relaxed);
    }

    /// A `transform.request` plugin call succeeded and its returned headers
    /// were applied to the outbound request.
    pub fn record_transform_applied(&self) {
        self.transform_applied.fetch_add(1, Ordering::Relaxed);
    }

    /// A `transform.request` plugin call failed: trap, timeout, fuel
    /// exhaustion, malformed export/output, output exceeding the header
    /// count/size bounds, or a `spawn_blocking` join failure.
    pub fn record_transform_failure(&self) {
        self.transform_failures.fetch_add(1, Ordering::Relaxed);
    }
```

Add three blocks to `render_prometheus`, directly after the `bearust_plugins_waf_detect_failures_total` block and before the final `output`:

```rust
        output.push_str("# TYPE bearust_plugins_transform_invocations_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_transform_invocations_total {}\n",
            self.transform_invocations.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_transform_applied_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_transform_applied_total {}\n",
            self.transform_applied.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_transform_failures_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_transform_failures_total {}\n",
            self.transform_failures.load(Ordering::Relaxed)
        ));
```

- [ ] **Step 4: Run the test to verify it passes**

Run: `cargo test --lib observability`
Expected: PASS, including the new `transform_metrics_render_as_counters` test.

- [ ] **Step 5: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add src/observability.rs
git commit -m "feat: add transform.request plugin observability counters"
```

---

### Task 3: `plugin_runtime.rs` capability, export validation, invocation, selection

**Files:**
- Modify: `src/plugin_runtime.rs`
- Modify: `tests/plugin_runtime.rs`
- Create: `tests/fixtures/plugins/transform_request_v2/plugin.toml`
- Create: `tests/fixtures/plugins/transform_request_v2/transform_request_v2.wat`
- Create: `tests/fixtures/plugins/transform_request_v2/README.md`

**Interfaces:**
- Consumes: `bearust_plugin_sdk::{TransformRequest, TransformResponse}` (Task 1).
- Produces: `CompiledPlugin::transform(&self, request: &bearust_plugin_sdk::TransformRequest) -> Result<bearust_plugin_sdk::TransformResponse, PluginError>`, `PluginManager::transform_plugin(&self) -> Option<Arc<CompiledPlugin>>`. Both used by Task 4.

- [ ] **Step 1: Create the fixture module and manifest**

Create `tests/fixtures/plugins/transform_request_v2/plugin.toml`:

```toml
id = "transform-request-v2"
display_name = "Deterministic request header transformer"
abi_version = 2
module = "transform_request_v2.wasm"
capabilities = ["transform.request"]

[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 32768
```

Create `tests/fixtures/plugins/transform_request_v2/transform_request_v2.wat`:

```wat
;; Deterministic Phase 13E fixture. Build with:
;;   wat2wasm transform_request_v2.wat -o transform_request_v2.wasm
;;
;; The test suite parses this WAT with the pinned `wat` dev dependency, so the
;; generated binary and any compiler cache are intentionally not checked in.
;;
;; Ignores the JSON the host writes as input and always returns the fixed
;; JSON literal `{"headers":[["x-transformed","yes"]]}` (37 bytes) stored at
;; memory offset 0, proving the host's alloc/write/call/read/dealloc round
;; trip end to end. Every abi_version: 2 module must also export
;; bearust_health_check_v2 regardless of its declared capabilities (an
;; existing Phase 13B requirement); this fixture is never health-checked in
;; tests, so that export is a trivial stub.
(module
  (memory (export "memory") 1)
  (global $heap_ptr (mut i32) (i32.const 1024))
  (data (i32.const 0) "{\22headers\22:[[\22x-transformed\22,\22yes\22]]}")

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

  (func (export "bearust_transform_request") (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
      (i64.extend_i32_u (i32.const 37)))))
```

Create `tests/fixtures/plugins/transform_request_v2/README.md`:

```markdown
# Deterministic request header transformer fixture

Local-only, no-import WASM fixture for the Phase 13E `transform.request`
acceptance tests. Exports `bearust_alloc`/`bearust_dealloc`/
`bearust_transform_request` per the memory convention in
`docs/superpowers/specs/2026-08-08-phase-13e-transform-request-design.md`,
plus a trivial `bearust_health_check_v2` stub (required unconditionally of
every `abi_version: 2` module, independent of declared capabilities). It
ignores the host-supplied input and always returns the fixed header list
`[["x-transformed","yes"]]`, so the test suite can assert an exact outcome
while still exercising the full alloc/write/call/read/dealloc round trip.

The checked-in WAT source is preferred over a generated binary for the same
reproducibility reasons as `tests/fixtures/plugins/health_ok/`.
```

- [ ] **Step 2: Add the failing tests**

Add to `tests/plugin_runtime.rs`, directly after the existing `waf_detect_capability_rejects_output_limit_below_the_waf_detect_input_floor` test (around line 371):

```rust
#[test]
fn transform_capability_requires_abi_version_two() {
    let text = manifest("").replace("[\"health_check\"]", "[\"transform.request\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(
        m.validate(&PluginPolicy::default()).unwrap_err(),
        PluginError::InvalidManifest
    );
}

#[test]
fn transform_capability_is_accepted_with_abi_version_two() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"transform.request\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 32768");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let validated = m.validate(&p).unwrap();
    assert_eq!(validated.capabilities, vec!["transform.request".to_string()]);
}

#[test]
fn transform_capability_rejects_output_limit_below_the_transform_input_floor() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"transform.request\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 4096");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap_err(), PluginError::InvalidManifest);

    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"transform.request\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 32768");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap().abi_version, 2);
}
```

Add directly after the existing `v2_missing_waf_detect_export_is_abi_mismatch` test (around line 592):

```rust
#[test]
fn v2_missing_transform_export_is_abi_mismatch() {
    // Exports the mandatory v2 baseline (memory, alloc, dealloc,
    // bearust_health_check_v2) but not bearust_transform_request, even
    // though the manifest declares the transform.request capability.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(
        compile_error_v2_with_capabilities(wat, vec!["transform.request".into()]),
        PluginError::AbiMismatch
    );
}
```

Add directly after the existing `v2_out_of_bounds_alloc_pointer_is_trap_on_the_detect_input_write` test (around line 665):

```rust
#[test]
fn v2_out_of_bounds_alloc_pointer_is_trap_on_the_transform_input_write() {
    // Hostile guest: bearust_alloc hands back a pointer far past the end of
    // the guest's single 65536-byte page. The host must reject it while
    // bounds-checking the *input* write, before bearust_transform_request is
    // even called. Mirrors the equivalent detect-path test.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1000000)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_transform_request") (param i32 i32) (result i64)
            unreachable))"#;
    let plugin = compile_v2_with_capabilities(wat, vec!["transform.request".into()]).unwrap();
    let request = bearust_plugin_sdk::TransformRequest {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
    };
    assert_eq!(plugin.transform(&request).unwrap_err(), PluginError::Trap);
}

#[test]
fn v2_malformed_transform_output_is_trap() {
    // A guest that returns a packed pointer/length pointing at bytes that
    // are not valid TransformResponse JSON.
    let wat = r#"(module
        (memory (export "memory") 1)
        (data (i32.const 0) "not json")
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1024)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_transform_request") (param i32 i32) (result i64)
            i64.const 8))"#; // pack(0, 8): (0i64 << 32) | 8
    let plugin = compile_v2_with_capabilities(wat, vec!["transform.request".into()]).unwrap();
    let request = bearust_plugin_sdk::TransformRequest {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
    };
    assert_eq!(plugin.transform(&request).unwrap_err(), PluginError::Trap);
}
```

Add at the end of the file (mirroring `waf_detect_fixture_round_trips_json_and_returns_verdict` and the two `waf_detector_plugin_is_none_*` tests):

```rust
#[test]
fn transform_fixture_round_trips_json_and_returns_headers() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("transform-request-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/transform_request_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/transform_request_v2/transform_request_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("transform_request_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);

    let transformer = manager
        .transform_plugin()
        .expect("transform-request-v2 declares transform.request and is enabled");
    let request = bearust_plugin_sdk::TransformRequest {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
    };
    let response = transformer.transform(&request).unwrap();
    assert_eq!(
        response.headers,
        vec![("x-transformed".to_string(), "yes".to_string())]
    );
}

#[test]
fn transform_plugin_is_none_when_no_plugin_declares_the_capability() {
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
    assert!(manager.transform_plugin().is_none());
}

#[test]
fn transform_plugin_is_none_when_disabled() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("transform-request-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/transform_request_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/transform_request_v2/transform_request_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("transform_request_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager.set_enabled("transform-request-v2", false).unwrap();
    assert!(manager.transform_plugin().is_none());
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --test plugin_runtime`
Expected: FAIL to compile — `transform.request` capability not allow-listed, `CompiledPlugin::transform` and `PluginManager::transform_plugin` not found.

- [ ] **Step 4: Implement the capability, export validation, invocation, and selection**

In `src/plugin_runtime.rs`:

1. Extend `ALLOWED_CAPABILITIES`:

```rust
const ALLOWED_CAPABILITIES: [&str; 4] = [
    "health_check",
    "notify.waf_block",
    "waf.detect",
    "transform.request",
];
```

2. Add the new floor constant, directly after `MIN_WAF_DETECT_INPUT_BYTES`:

```rust
/// `transform.request` carries only method/path/query/headers in both
/// directions -- no body. `src/proxy.rs::transform_request` bounds the
/// input to the same combined `MAX_NORMALIZED_METADATA_BYTES` (16 KiB)
/// budget `waf_detect_request` uses, and
/// `src/proxy.rs::is_valid_transform_headers` enforces the same budget on
/// the plugin's returned headers. With JSON string-escaping overhead
/// (~1.5x) that is roughly 24 KiB of worst-case JSON in either direction.
/// This floor gives comfortable headroom above that worst case while
/// staying under the default 64 KiB policy ceiling. Deliberately its own
/// constant -- not shared with `MIN_NOTIFY_INPUT_BYTES` or
/// `MIN_WAF_DETECT_INPUT_BYTES`, whose worst cases are shaped differently
/// (a compact event, and a metadata-plus-body request, respectively).
const MIN_TRANSFORM_INPUT_BYTES: usize = 32_768;
```

3. Add `has_transform_request: bool` to the `CompiledPlugin` struct (after `has_waf_detect: bool,`):

```rust
    has_transform_request: bool,
```

4. In `PluginEngine::compile`, change the `abi_version` match to return four-tuples instead of three. Replace:

```rust
        let (has_health_check, has_notify_waf_block, has_waf_detect) = match manifest.abi_version {
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
                (has_health_check, false, false)
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
                (false, has_notify_waf_block, has_waf_detect)
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
        })
```

with:

```rust
        let (has_health_check, has_notify_waf_block, has_waf_detect, has_transform_request) =
            match manifest.abi_version {
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
                    (has_health_check, false, false, false)
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
                    let has_waf_detect =
                        if manifest.capabilities.iter().any(|c| c == "waf.detect") {
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
                    (false, has_notify_waf_block, has_waf_detect, has_transform_request)
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
        })
```

5. In `PluginManifest::validate`, replace the abi-version-gate check. Replace:

```rust
        if self.abi_version != 2
            && self
                .capabilities
                .iter()
                .any(|c| c == "notify.waf_block" || c == "waf.detect")
        {
            return Err(PluginError::InvalidManifest);
        }
```

with:

```rust
        if self.abi_version != 2
            && self.capabilities.iter().any(|c| {
                c == "notify.waf_block" || c == "waf.detect" || c == "transform.request"
            })
        {
            return Err(PluginError::InvalidManifest);
        }
```

Add a new floor check, directly after the existing `waf.detect` floor check:

```rust
        if self.capabilities.iter().any(|c| c == "transform.request")
            && self.limits.max_output_bytes < MIN_TRANSFORM_INPUT_BYTES
        {
            return Err(PluginError::InvalidManifest);
        }
```

6. Add `CompiledPlugin::transform`, directly after the existing `detect` method (inside `impl CompiledPlugin`, before its closing `}`):

```rust
    /// Invokes the `transform.request` capability's entry point on an
    /// `abi_version: 2` plugin that declared it. Returns the plugin's
    /// replacement header list or a `PluginError` for any host-detected
    /// failure (trap, timeout, fuel exhaustion, malformed export/output, or
    /// an out-of-bounds pointer). Never panics: every guest-controlled
    /// pointer/length is bounds-checked exactly as in `health_check`'s v2
    /// path.
    pub fn transform(
        &self,
        request: &bearust_plugin_sdk::TransformRequest,
    ) -> Result<bearust_plugin_sdk::TransformResponse, PluginError> {
        if !self.has_transform_request {
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
            .get_typed_func::<(i32, i32), i64>(&mut store, "bearust_transform_request")
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

7. Add `PluginManager::transform_plugin`, directly after the existing `waf_detector_plugin` method:

```rust
    /// Returns the compiled plugin currently acting as the active request
    /// transformer, if any: the first (lowest plugin ID) enabled plugin
    /// whose manifest declared `transform.request`. Mirrors
    /// `waf_detector_plugin`'s selection rule exactly -- at most one plugin
    /// is ever treated as the active transformer; any other plugin also
    /// declaring the capability is simply never selected.
    pub fn transform_plugin(&self) -> Option<Arc<CompiledPlugin>> {
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
                    .has_transform_request
                    .then(|| Arc::clone(compiled))
            })
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --test plugin_runtime`
Expected: PASS, all tests including the new `transform_*`/`v2_missing_transform_export_is_abi_mismatch`/`v2_out_of_bounds_alloc_pointer_is_trap_on_the_transform_input_write`/`v2_malformed_transform_output_is_trap` tests.

- [ ] **Step 6: Run the full workspace test suite**

Run: `cargo test --workspace --locked`
Expected: PASS — confirms the `CompiledPlugin` field addition and tuple-arity change did not break any existing plugin_runtime consumer.

- [ ] **Step 7: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add src/plugin_runtime.rs tests/plugin_runtime.rs tests/fixtures/plugins/transform_request_v2/
git commit -m "feat: add transform.request plugin capability, export validation, and invocation"
```

---

### Task 4: Wire the transformer into `proxy.rs`

**Files:**
- Modify: `src/proxy.rs`

**Interfaces:**
- Consumes: `crate::plugin_runtime::PluginManager::transform_plugin`/`CompiledPlugin::transform` (Task 3), `bearust_plugin_sdk::{TransformRequest, TransformResponse}` (Task 1), `PluginMetrics::record_transform_*` (Task 2). Reuses the existing `BeaRustProxy::plugin_manager: Option<Arc<PluginManager>>` field and `crate::waf::{MAX_NORMALIZED_METADATA_BYTES, MAX_NORMALIZED_HEADERS, MAX_NORMALIZED_FIELD_BYTES}` (Phase 13D) — no new field or builder method needed; `src/cli.rs` already wires `plugin_manager` into every `BeaRustProxy`.
- Produces: `apply_transform_plugin(...)`, wired into `upstream_request_filter`, before the existing Host/X-Forwarded-For/X-Request-Id insertion code.

- [ ] **Step 1: Add the failing tests**

Add to `src/proxy.rs`'s existing `#[cfg(test)] mod tests` block. First extend the `use super::{...}` line at the top of the block (currently `use super::{apply_waf_detector, error_status, invoke_analytics_changed, waf_block_event};`) to:

```rust
    use super::{
        apply_transform_plugin, apply_waf_detector, error_status, invoke_analytics_changed,
        waf_block_event,
    };
```

Then add these tests at the end of the `mod tests` block, before its closing `}` (the block already has `use crate::config::PluginConfig;`, `use crate::plugin_runtime::PluginManager;`, `use std::fs;`, and `use tempfile::tempdir;` from Phase 13D — reuse them, do not duplicate):

```rust
    fn transform_manager(enabled: bool) -> Arc<PluginManager> {
        let root = tempdir().unwrap();
        let plugin = root.path().join("transform-request-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/transform_request_v2/plugin.toml"),
        )
        .unwrap();
        let module = wat::parse_str(include_str!(
            "../tests/fixtures/plugins/transform_request_v2/transform_request_v2.wat"
        ))
        .unwrap();
        fs::write(plugin.join("transform_request_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();
        if !enabled {
            manager.set_enabled("transform-request-v2", false).unwrap();
        }
        manager
    }

    fn sample_request_header() -> RequestHeader {
        let mut header = RequestHeader::build("GET", b"/", None).unwrap();
        header.insert_header("Host", "example.com").unwrap();
        header
    }

    #[tokio::test]
    async fn a_successful_transform_replaces_the_header_list() {
        let manager = transform_manager(true);
        let mut header = sample_request_header();
        apply_transform_plugin(Some(&manager), &mut header).await;
        assert_eq!(
            header.headers.get("x-transformed").unwrap(),
            "yes"
        );
        // The plugin's fixed response does not include Host -- it is only
        // reasserted by upstream_request_filter's own code, which this unit
        // test does not call, so it is correctly absent here.
        assert!(header.headers.get("host").is_none());
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_invocations_total 1"));
        assert!(output.contains("bearust_plugins_transform_applied_total 1"));
    }

    #[tokio::test]
    async fn no_transformer_configured_leaves_headers_unchanged() {
        let manager = PluginManager::new(PluginConfig::default());
        let mut header = sample_request_header();
        apply_transform_plugin(Some(&manager), &mut header).await;
        assert_eq!(header.headers.get("host").unwrap(), "example.com");
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_invocations_total 0"));
    }

    #[tokio::test]
    async fn a_disabled_transformer_leaves_headers_unchanged() {
        let manager = transform_manager(false);
        let mut header = sample_request_header();
        apply_transform_plugin(Some(&manager), &mut header).await;
        assert_eq!(header.headers.get("host").unwrap(), "example.com");
    }

    #[tokio::test]
    async fn no_plugin_manager_leaves_headers_unchanged() {
        let mut header = sample_request_header();
        apply_transform_plugin(None, &mut header).await;
        assert_eq!(header.headers.get("host").unwrap(), "example.com");
    }

    #[tokio::test]
    async fn a_trapping_transformer_fails_open_and_counts_a_failure() {
        let root = tempdir().unwrap();
        let plugin = root.path().join("transform-request-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/transform_request_v2/plugin.toml"),
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
            (func (export "bearust_transform_request") (param i32 i32) (result i64) unreachable))"#;
        let module = wat::parse_str(wat).unwrap();
        fs::write(plugin.join("transform_request_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();

        let mut header = sample_request_header();
        apply_transform_plugin(Some(&manager), &mut header).await;
        assert_eq!(header.headers.get("host").unwrap(), "example.com");
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_transform_failures_total 1"));
        assert!(output.contains("bearust_plugins_transform_applied_total 0"));
    }

    #[test]
    fn oversized_header_count_is_rejected_as_invalid() {
        let headers: Vec<(String, String)> = (0..(crate::waf::MAX_NORMALIZED_HEADERS + 1))
            .map(|i| (format!("x-h{i}"), "v".to_string()))
            .collect();
        assert!(!is_valid_transform_headers(&headers));
    }

    #[test]
    fn header_field_exceeding_the_per_field_bound_is_rejected_as_invalid() {
        let headers = vec![(
            "x-big".to_string(),
            "a".repeat(crate::waf::MAX_NORMALIZED_FIELD_BYTES + 1),
        )];
        assert!(!is_valid_transform_headers(&headers));
    }

    #[test]
    fn ordinary_headers_are_valid() {
        let headers = vec![("host".to_string(), "example.com".to_string())];
        assert!(is_valid_transform_headers(&headers));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib proxy::tests`
Expected: FAIL to compile — `apply_transform_plugin`/`is_valid_transform_headers` not found.

- [ ] **Step 3: Implement the wiring**

Add three free functions to `src/proxy.rs`, directly after the existing `apply_waf_detector` function (before `emit_waf_telemetry`):

```rust
/// Converts the outbound `RequestHeader` into the wire shape a
/// `transform.request` plugin receives. `method`/`path`/`query`/`headers`
/// share a `crate::waf::MAX_NORMALIZED_METADATA_BYTES` budget and each
/// header is additionally capped at `crate::waf::MAX_NORMALIZED_FIELD_BYTES`
/// -- the same bounds `waf_detect_request` enforces on the same kind of raw
/// fields -- so a transform plugin never receives more request metadata
/// than a detector plugin already does. There is no body: this hook only
/// ever sees headers. Pure and side-effect free.
fn transform_request(header: &RequestHeader) -> bearust_plugin_sdk::TransformRequest {
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
    bearust_plugin_sdk::TransformRequest {
        method,
        path,
        query,
        headers,
    }
}

/// A plugin's returned header list is applied only if it stays within the
/// same bounds `transform_request` enforces on the input side: no more than
/// `MAX_NORMALIZED_HEADERS` entries, and no single name or value longer
/// than `MAX_NORMALIZED_FIELD_BYTES`. A plugin that returns more than this
/// has produced malformed output as far as the host is concerned -- the
/// whole transform is rejected (see `apply_transform_plugin`), not
/// partially truncated, so a plugin can't silently have some of its
/// intended headers dropped without warning.
fn is_valid_transform_headers(headers: &[(String, String)]) -> bool {
    headers.len() <= crate::waf::MAX_NORMALIZED_HEADERS
        && headers.iter().all(|(name, value)| {
            name.len() <= crate::waf::MAX_NORMALIZED_FIELD_BYTES
                && value.len() <= crate::waf::MAX_NORMALIZED_FIELD_BYTES
        })
}

/// Replaces every existing header on `request` with `response`'s headers.
/// A header whose name or value the plugin returned is not valid HTTP
/// header syntax is silently skipped (best-effort application) rather than
/// failing the whole request -- the caller has already validated the
/// response's size/count bounds via `is_valid_transform_headers` before
/// calling this.
fn apply_transform_response(
    request: &mut RequestHeader,
    response: bearust_plugin_sdk::TransformResponse,
) {
    let existing_names: Vec<_> = request.headers.keys().cloned().collect();
    for name in existing_names {
        request.remove_header(&name);
    }
    for (name, value) in response.headers {
        let _ = request.append_header(name, value);
    }
}

/// Runs the registered `transform.request` plugin (if any) against
/// `request`'s current headers and, on success, wholesale-replaces them
/// with the plugin's response. Synchronous from the caller's point of view
/// but offloads the blocking wasmtime call via `spawn_blocking` so it never
/// blocks the shared async runtime. Fails open on every error class: no
/// transformer configured, no plugin currently declaring the capability, a
/// disabled plugin, a trap/timeout/fuel exhaustion, output exceeding the
/// header count/size bounds, a malformed response, or a `spawn_blocking`
/// join failure all leave `request`'s headers untouched (after counting a
/// failure metric where applicable). The caller (`upstream_request_filter`)
/// unconditionally reasserts `Host`/`X-Forwarded-For`/`X-Request-Id` right
/// after this call returns, whether or not a transform was applied, so this
/// function never needs to protect those three headers itself.
async fn apply_transform_plugin(
    plugin_manager: Option<&Arc<PluginManager>>,
    request: &mut RequestHeader,
) {
    let Some(manager) = plugin_manager else {
        return;
    };
    let Some(transformer) = manager.transform_plugin() else {
        return;
    };
    let metrics = manager.metrics();
    metrics.record_transform_invocation();
    let input = transform_request(request);
    let outcome = tokio::task::spawn_blocking(move || transformer.transform(&input)).await;
    match outcome {
        Ok(Ok(response)) if is_valid_transform_headers(&response.headers) => {
            apply_transform_response(request, response);
            metrics.record_transform_applied();
        }
        Ok(Ok(_)) => {
            tracing::warn!(
                event = "transform_request_failed",
                reason = "output_bounds_exceeded"
            );
            metrics.record_transform_failure();
        }
        Ok(Err(error)) => {
            tracing::warn!(event = "transform_request_failed", reason = error.code());
            metrics.record_transform_failure();
        }
        Err(_join_error) => {
            tracing::warn!(event = "transform_request_failed", reason = "join_error");
            metrics.record_transform_failure();
        }
    }
}
```

Wire it into `upstream_request_filter`. Replace:

```rust
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if ctx.waf_blocked {
            return Err(pingora_core::Error::explain(
                ErrorType::HTTPStatus(403),
                "request blocked by waf",
            ));
        }
        if let Some(host) = session
```

with:

```rust
    async fn upstream_request_filter(
        &self,
        session: &mut Session,
        request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
        if ctx.waf_blocked {
            return Err(pingora_core::Error::explain(
                ErrorType::HTTPStatus(403),
                "request blocked by waf",
            ));
        }
        apply_transform_plugin(self.plugin_manager.as_ref(), request).await;
        if let Some(host) = session
```

This places the transform call before the existing `Host`/`X-Forwarded-For`/`X-Request-Id` insertion code, which already runs unconditionally right after — no changes are needed to that insertion code itself.

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib proxy::tests`
Expected: PASS, all new `apply_transform_plugin`/`is_valid_transform_headers` tests plus every existing test in the module.

- [ ] **Step 5: Run the full workspace test suite**

Run: `cargo test --workspace --locked`
Expected: PASS.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add src/proxy.rs
git commit -m "feat: apply the transform.request plugin verdict in upstream_request_filter"
```

---

### Task 5: Documentation and final acceptance gate

**Files:**
- Modify: `docs/PRD.md`

**Interfaces:**
- Consumes: nothing new (documentation only).
- Produces: nothing consumed by later tasks — this is the final task.

- [ ] **Step 1: Update the PRD**

In `docs/PRD.md`, replace the final paragraph of the Phase 13D section:

```markdown
Phase 13E is next: request/response transform hooks, followed by custom
load-balancing hooks, each reviewed individually and built on this same
memory convention.
```

with:

```markdown
Phase 13E is next: a request header transform hook.
```

Then add a new section directly after the Phase 13D section (before any following top-level heading), mirroring the Phase 13D section's structure:

```markdown
### Phase 13E status: request header transform hook

Phase 13E is complete and adds the plugin system's first request-mutating
hook: a plugin can rewrite the outbound request's headers before they reach
the upstream, running once per request in `upstream_request_filter` (after
WAF evaluation and routing have both already been finalized, so the
transform cannot influence either).

A plugin opts in by declaring `abi_version: 2`, `capabilities =
["transform.request"]`, and exporting `bearust_transform_request(ptr: i32,
len: i32) -> i64`. The hook receives a `TransformRequest` (method, path,
query, and headers, bounded to the same combined budget the rule engine's
own `InspectionContext` normalization enforces -- no body) and returns a
`TransformResponse` (a full replacement header list) via the same
alloc/write/call/read/dealloc memory convention Phase 13B introduced for
the health check.

A `transform.request` manifest must declare `max_output_bytes >= 32768`
(`MIN_TRANSFORM_INPUT_BYTES` in `src/plugin_runtime.rs`) -- enforced at
manifest validation -- sized the same way `MIN_WAF_DETECT_INPUT_BYTES` was:
generous headroom above the worst-case bounded JSON payload in either
direction.

Application is all-or-nothing: on success, the plugin's returned header
list wholesale-replaces the outbound request's header list. `Host`,
`X-Forwarded-For`, and `X-Request-Id` are then unconditionally reasserted
by the existing insertion logic that already runs immediately afterward, so
a transform plugin -- buggy or malicious -- can never drop, blank, or spoof
those three. Fail-open on every error class (trap, fuel exhaustion, timeout,
ABI/output error, output exceeding the header count/size bounds, or a
`spawn_blocking` join failure): drop the plugin's output, log a warning,
count a failure metric, and leave the outbound headers exactly as they
were.

At most one plugin is ever treated as the active transformer (the lowest
plugin ID among enabled plugins declaring the capability); every other
plugin is unaffected -- the same selection rule as `notify.waf_block` and
`waf.detect`.

Three new Prometheus counters (`bearust_plugins_transform_invocations_total`,
`bearust_plugins_transform_applied_total`,
`bearust_plugins_transform_failures_total`) surface plugin activity on the
existing plugin metrics endpoint. No new host import, capability, or
resource-limit bypass was added; every guest-controlled pointer/length is
bounds-checked identically to the Phase 13B health-check path.

This phase deliberately covers request headers only: no body transform (the
proxy already streams/buffers the request body incrementally for WAF
inspection, and rewriting it introduces re-splicing complexity out of scope
here), and no response transform (the proxy currently has no
`response_filter`/`response_body_filter` hook points in `ProxyHttp` at
all -- introducing them is a materially larger change, deferred to a later
phase).
```

- [ ] **Step 2: Format, lint, and run the full acceptance gate**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

Expected: all three PASS with zero warnings and zero test failures.

- [ ] **Step 3: Commit**

```bash
git add docs/PRD.md
git commit -m "docs: mark phase 13e request transform hook complete"
```

---
