# Phase 13D: Custom WAF Detector Plugin Hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let a WASM plugin declaring the `waf.detect` capability contribute an additional, escalate-only verdict to BeaRust's built-in WAF rule engine, synchronously, with fail-open behavior on any plugin error.

**Architecture:** At both existing WAF evaluation call sites (`request_filter` header-stage, `request_body_filter` body-stage), after `waf::evaluate()` runs, the lowest-ID enabled plugin declaring `waf.detect` (if any) is invoked via `tokio::task::spawn_blocking` with the same bounded `InspectionContext` fields the rule engine itself inspected. Its verdict (`decision`, `category`, `score`) is merged into the `Evaluation` via a pure, most-severe-wins `merge_plugin_verdict` function that can only escalate, never downgrade. Any plugin failure counts a metric and leaves the rule engine's own decision untouched.

**Tech Stack:** Rust, `wasmtime` (pinned `=27.0.0`), `tokio`, `serde`/`serde_json`, `wat` (dev-dependency for hand-written WASM text fixtures), the existing `bearust-plugin-sdk` crate.

## Global Constraints

- New manifest capability string: `"waf.detect"`, added to `plugin_runtime.rs`'s `ALLOWED_CAPABILITIES`. Valid only when `abi_version: 2` (same rule already enforced for `"notify.waf_block"`).
- Required guest export when `"waf.detect"` is declared: `bearust_waf_detect(ptr: i32, len: i32) -> i64` — a packed pointer/length pair (via `bearust_plugin_sdk::pack`/`unpack`) pointing at the verdict's JSON in guest memory. Every `abi_version: 2` module must still unconditionally export `bearust_health_check_v2` regardless of declared capabilities (existing, unchanged Phase 13B rule).
- Manifests declaring `"waf.detect"` reuse the existing `MIN_NOTIFY_INPUT_BYTES` (1024-byte) `max_output_bytes` floor already enforced for `"notify.waf_block"` — do not introduce a second constant.
- Exactly one active detector plugin per request: the lowest-ID enabled plugin declaring `"waf.detect"`, selected via `PluginManager::waf_detector_plugin()` (mirrors `waf_block_sink_plugin`'s `BTreeMap` ascending-order selection exactly).
- The detector runs at both WAF evaluation call sites (header-stage and body-stage), synchronously, via `tokio::task::spawn_blocking` so the blocking wasmtime call never blocks the shared async runtime.
- Merge semantics are escalate-only: `Block` beats `Log` beats `Allow`, applied between the rule engine's existing decision and the plugin's verdict. A plugin verdict can never turn an existing `Block` into anything else.
- Fail-open on every failure class (trap, fuel exhaustion, timeout, ABI/output error, `spawn_blocking` join failure): drop the plugin's contribution, log a `tracing::warn!`, increment a failure counter, and let the rule engine's own `Evaluation` proceed unchanged.
- Wire types (`bearust-plugin-sdk`):
  ```rust
  pub enum WafPluginDecision { Allow, Log, Block }   // serde snake_case
  pub struct WafDetectRequest { pub method: String, pub path: String, pub query: String, pub headers: Vec<(String, String)>, pub body: Vec<u8> }
  pub struct WafDetectVerdict { pub decision: WafPluginDecision, pub category: String, pub score: u16 }
  ```
- New Prometheus counters (`src/observability.rs`, `PluginMetrics`): `bearust_plugins_waf_detect_invocations_total`, `bearust_plugins_waf_detect_block_total`, `bearust_plugins_waf_detect_failures_total`.
- Acceptance gate for every task: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace --locked`.

---

### Task 1: `bearust-plugin-sdk` wire types

**Files:**
- Modify: `crates/bearust-plugin-sdk/src/lib.rs`

**Interfaces:**
- Produces: `bearust_plugin_sdk::WafPluginDecision` (`Allow | Log | Block`), `bearust_plugin_sdk::WafDetectRequest { method, path, query, headers, body }`, `bearust_plugin_sdk::WafDetectVerdict { decision, category, score }` — all `Debug, Clone, Serialize, Deserialize, PartialEq, Eq`.

- [ ] **Step 1: Add the failing round-trip test**

Add to the existing `#[cfg(test)] mod tests` block in `crates/bearust-plugin-sdk/src/lib.rs` (after `waf_block_event_round_trips`):

```rust
    #[test]
    fn waf_detect_request_round_trips() {
        let value = WafDetectRequest {
            method: "POST".into(),
            path: "/login".into(),
            query: "next=/".into(),
            headers: vec![("host".into(), "example.com".into())],
            body: b"user=admin".to_vec(),
        };
        let bytes = encode(&value);
        let decoded: WafDetectRequest = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn waf_detect_verdict_round_trips() {
        let value = WafDetectVerdict {
            decision: WafPluginDecision::Block,
            category: "custom_detector".into(),
            score: 10,
        };
        let bytes = encode(&value);
        let decoded: WafDetectVerdict = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn waf_plugin_decision_serializes_as_lowercase() {
        assert_eq!(
            serde_json::to_string(&WafPluginDecision::Allow).unwrap(),
            "\"allow\""
        );
        assert_eq!(
            serde_json::to_string(&WafPluginDecision::Log).unwrap(),
            "\"log\""
        );
        assert_eq!(
            serde_json::to_string(&WafPluginDecision::Block).unwrap(),
            "\"block\""
        );
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test -p bearust-plugin-sdk`
Expected: FAIL to compile — `WafDetectRequest`, `WafDetectVerdict`, `WafPluginDecision` not found.

- [ ] **Step 3: Add the types**

Append to `crates/bearust-plugin-sdk/src/lib.rs`, after the existing `WafBlockEvent` struct at the end of the file:

```rust
/// A plugin's decision on `waf.detect`, mirroring `src/waf.rs::WafDecision`
/// on the host side. Serialized in `snake_case` (`"allow" | "log" |
/// "block"`).
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WafPluginDecision {
    Allow,
    Log,
    Block,
}

/// Input to `bearust_waf_detect`. Mirrors `src/waf.rs::InspectionContext`
/// on the host side — the exact same bounded fields the built-in rule
/// engine itself evaluates, so a detector plugin never receives more
/// attacker-controlled data than the engine already inspects.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WafDetectRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

/// Output of `bearust_waf_detect`. Merged into the host's `Evaluation` via
/// an escalate-only rule: `decision` can raise severity but never lower a
/// decision the rule engine already reached.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WafDetectVerdict {
    pub decision: WafPluginDecision,
    pub category: String,
    pub score: u16,
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test -p bearust-plugin-sdk`
Expected: PASS, all tests including the three new ones.

- [ ] **Step 5: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy -p bearust-plugin-sdk --all-targets -- -D warnings
git add crates/bearust-plugin-sdk/src/lib.rs
git commit -m "feat: add waf.detect wire types to the plugin SDK"
```

---

### Task 2: Observability counters

**Files:**
- Modify: `src/observability.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `PluginMetrics::record_waf_detect_invocation(&self)`, `PluginMetrics::record_waf_detect_block(&self)`, `PluginMetrics::record_waf_detect_failure(&self)`. `render_prometheus()` gains three new counter blocks: `bearust_plugins_waf_detect_invocations_total`, `bearust_plugins_waf_detect_block_total`, `bearust_plugins_waf_detect_failures_total`.

- [ ] **Step 1: Add the failing test**

Add to `src/observability.rs`'s existing `#[cfg(test)] mod tests` block (find it near the bottom of the file, alongside the existing `notify_metrics_render_as_counters` test — add this test directly after it):

```rust
    #[test]
    fn waf_detect_metrics_render_as_counters() {
        let metrics = PluginMetrics::default();
        metrics.record_waf_detect_invocation();
        metrics.record_waf_detect_invocation();
        metrics.record_waf_detect_block();
        metrics.record_waf_detect_failure();
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_waf_detect_invocations_total 2"));
        assert!(output.contains("bearust_plugins_waf_detect_block_total 1"));
        assert!(output.contains("bearust_plugins_waf_detect_failures_total 1"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib observability::tests::waf_detect_metrics_render_as_counters`
Expected: FAIL to compile — `record_waf_detect_invocation` etc. not found.

- [ ] **Step 3: Extend `PluginMetrics`**

In `src/observability.rs`, add three fields to the `PluginMetrics` struct (after `notify_dropped: AtomicU64,`):

```rust
    waf_detect_invocations: AtomicU64,
    waf_detect_block: AtomicU64,
    waf_detect_failures: AtomicU64,
```

Add three methods to `impl PluginMetrics` (after `record_notify_dropped`):

```rust
    /// A `waf.detect` plugin call completed successfully (any decision,
    /// including `Allow`).
    pub fn record_waf_detect_invocation(&self) {
        self.waf_detect_invocations.fetch_add(1, Ordering::Relaxed);
    }

    /// A `waf.detect` plugin verdict actually changed the merged
    /// `Evaluation`'s decision (an escalation occurred).
    pub fn record_waf_detect_block(&self) {
        self.waf_detect_block.fetch_add(1, Ordering::Relaxed);
    }

    /// A `waf.detect` plugin call failed: trap, timeout, fuel exhaustion,
    /// malformed export/output, or a `spawn_blocking` join failure.
    pub fn record_waf_detect_failure(&self) {
        self.waf_detect_failures.fetch_add(1, Ordering::Relaxed);
    }
```

Extend `render_prometheus()`, appending after the existing `bearust_plugins_notify_dropped_total` block and before the final `output`:

```rust
        output.push_str("# TYPE bearust_plugins_waf_detect_invocations_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_waf_detect_invocations_total {}\n",
            self.waf_detect_invocations.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_waf_detect_block_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_waf_detect_block_total {}\n",
            self.waf_detect_block.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_waf_detect_failures_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_waf_detect_failures_total {}\n",
            self.waf_detect_failures.load(Ordering::Relaxed)
        ));
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib observability::`
Expected: PASS, all `observability` unit tests including the new one.

- [ ] **Step 5: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --all-targets -- -D warnings
git add src/observability.rs
git commit -m "feat: add waf.detect Prometheus counters to PluginMetrics"
```

---

### Task 3: `plugin_runtime.rs` capability, export validation, invocation, selection

**Files:**
- Modify: `src/plugin_runtime.rs`
- Modify: `tests/plugin_runtime.rs`
- Create: `tests/fixtures/plugins/waf_detect_v2/plugin.toml`
- Create: `tests/fixtures/plugins/waf_detect_v2/waf_detect_v2.wat`
- Create: `tests/fixtures/plugins/waf_detect_v2/README.md`

**Interfaces:**
- Consumes: `bearust_plugin_sdk::{WafDetectRequest, WafDetectVerdict}` (Task 1).
- Produces: `CompiledPlugin::detect(&self, request: &bearust_plugin_sdk::WafDetectRequest) -> Result<bearust_plugin_sdk::WafDetectVerdict, PluginError>`, `PluginManager::waf_detector_plugin(&self) -> Option<Arc<CompiledPlugin>>`. Both used by Task 5.

- [ ] **Step 1: Create the fixture module and manifest**

Create `tests/fixtures/plugins/waf_detect_v2/plugin.toml`:

```toml
id = "waf-detect-v2"
display_name = "Deterministic custom WAF detector"
abi_version = 2
module = "waf_detect_v2.wasm"
capabilities = ["waf.detect"]

[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1024
```

Create `tests/fixtures/plugins/waf_detect_v2/waf_detect_v2.wat`:

```wat
;; Deterministic Phase 13D fixture. Build with:
;;   wat2wasm waf_detect_v2.wat -o waf_detect_v2.wasm
;;
;; The test suite parses this WAT with the pinned `wat` dev dependency, so the
;; generated binary and any compiler cache are intentionally not checked in.
;;
;; Ignores the JSON the host writes as input and always returns the fixed
;; JSON literal `{"decision":"block","category":"custom_detector","score":10}`
;; (60 bytes) stored at memory offset 0, proving the host's
;; alloc/write/call/read/dealloc round trip end to end. Every abi_version: 2
;; module must also export bearust_health_check_v2 regardless of its
;; declared capabilities (an existing Phase 13B requirement); this fixture
;; is never health-checked in tests, so that export is a trivial stub.
(module
  (memory (export "memory") 1)
  (global $heap_ptr (mut i32) (i32.const 1024))
  (data (i32.const 0) "{\22decision\22:\22block\22,\22category\22:\22custom_detector\22,\22score\22:10}")

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

  (func (export "bearust_waf_detect") (param $ptr i32) (param $len i32) (result i64)
    (i64.or
      (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
      (i64.extend_i32_u (i32.const 60)))))
```

Create `tests/fixtures/plugins/waf_detect_v2/README.md`:

```markdown
# Deterministic custom WAF detector fixture

Local-only, no-import WASM fixture for the Phase 13D `waf.detect`
acceptance tests. Exports `bearust_alloc`/`bearust_dealloc`/
`bearust_waf_detect` per the memory convention in
`docs/superpowers/specs/2026-08-06-phase-13d-waf-detector-design.md`, plus a
trivial `bearust_health_check_v2` stub (required unconditionally of every
`abi_version: 2` module, independent of declared capabilities). It ignores
the host-supplied input and always returns the fixed verdict
`{"decision":"block","category":"custom_detector","score":10}`, so the test
suite can assert an exact outcome while still exercising the full
alloc/write/call/read/dealloc round trip.

The checked-in WAT source is preferred over a generated binary for the same
reproducibility reasons as `tests/fixtures/plugins/health_ok/`.
```

- [ ] **Step 2: Add the failing tests**

Add to `tests/plugin_runtime.rs`, directly after the existing `notify_capability_rejects_output_limit_below_the_notify_input_floor` test (around line 323):

```rust
#[test]
fn waf_detect_capability_requires_abi_version_two() {
    let text = manifest("").replace("[\"health_check\"]", "[\"waf.detect\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(
        m.validate(&PluginPolicy::default()).unwrap_err(),
        PluginError::InvalidManifest
    );
}

#[test]
fn waf_detect_capability_is_accepted_with_abi_version_two() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"waf.detect\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let validated = m.validate(&p).unwrap();
    assert_eq!(validated.capabilities, vec!["waf.detect".to_string()]);
}

#[test]
fn waf_detect_capability_rejects_output_limit_below_the_notify_input_floor() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"waf.detect\"]")
        .replace("max_output_bytes = 1024", "max_output_bytes = 100");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap_err(), PluginError::InvalidManifest);

    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"waf.detect\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(m.validate(&p).unwrap().abi_version, 2);
}
```

Add directly after the existing `v2_missing_notify_export_is_abi_mismatch` test (around line 519):

```rust
#[test]
fn v2_missing_waf_detect_export_is_abi_mismatch() {
    // Exports the mandatory v2 baseline (memory, alloc, dealloc,
    // bearust_health_check_v2) but not bearust_waf_detect, even though the
    // manifest declares the waf.detect capability.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(
        compile_error_v2_with_capabilities(wat, vec!["waf.detect".into()]),
        PluginError::AbiMismatch
    );
}
```

Add directly after the existing `v2_out_of_bounds_alloc_pointer_is_trap_on_the_notify_input_write` test (around line 550):

```rust
#[test]
fn v2_out_of_bounds_alloc_pointer_is_trap_on_the_detect_input_write() {
    // Hostile guest: bearust_alloc hands back a pointer far past the end of
    // the guest's single 65536-byte page. The host must reject it while
    // bounds-checking the *input* write, before bearust_waf_detect is even
    // called. Mirrors the equivalent notify-path test.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1000000)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_waf_detect") (param i32 i32) (result i64)
            unreachable))"#;
    let plugin = compile_v2_with_capabilities(wat, vec!["waf.detect".into()]).unwrap();
    let request = bearust_plugin_sdk::WafDetectRequest {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    assert_eq!(plugin.detect(&request).unwrap_err(), PluginError::Trap);
}
```

Add at the end of the file (mirroring `notify_sink_fixture_round_trips_json_and_reports_success` and the two `waf_block_sink_plugin_is_none_*` tests, near lines 93-179):

```rust
#[test]
fn waf_detect_fixture_round_trips_json_and_returns_verdict() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("waf-detect-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/waf_detect_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/waf_detect_v2/waf_detect_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("waf_detect_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);

    let detector = manager
        .waf_detector_plugin()
        .expect("waf-detect-v2 declares waf.detect and is enabled");
    let request = bearust_plugin_sdk::WafDetectRequest {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers: Vec::new(),
        body: Vec::new(),
    };
    let verdict = detector.detect(&request).unwrap();
    assert_eq!(verdict.decision, bearust_plugin_sdk::WafPluginDecision::Block);
    assert_eq!(verdict.category, "custom_detector");
    assert_eq!(verdict.score, 10);
}

#[test]
fn waf_detector_plugin_is_none_when_no_plugin_declares_the_capability() {
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
    assert!(manager.waf_detector_plugin().is_none());
}

#[test]
fn waf_detector_plugin_is_none_when_disabled() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("waf-detect-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/waf_detect_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/waf_detect_v2/waf_detect_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("waf_detect_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager.set_enabled("waf-detect-v2", false).unwrap();
    assert!(manager.waf_detector_plugin().is_none());
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test --test plugin_runtime`
Expected: FAIL to compile — `waf.detect` capability not allow-listed, `CompiledPlugin::detect` and `PluginManager::waf_detector_plugin` not found.

- [ ] **Step 4: Implement the capability, export validation, invocation, and selection**

In `src/plugin_runtime.rs`:

1. Extend `ALLOWED_CAPABILITIES` (currently `["health_check", "notify.waf_block"]`):

```rust
const ALLOWED_CAPABILITIES: [&str; 3] = ["health_check", "notify.waf_block", "waf.detect"];
```

2. Update the comment above `MIN_NOTIFY_INPUT_BYTES` to note it is now shared:

```rust
/// `WafBlockEvent`'s JSON encoding can be far larger than
/// `HealthCheckInput`'s: the worst realistic case is a 128-byte
/// client-supplied `request_id` plus up to eight 32-byte WAF category
/// identifiers in both `category` and `reason_ids`. 1024 bytes gives
/// generous headroom above that worst case (matches the checked-in
/// `notify_sink_v2` fixture's declared limit), so a `notify.waf_block`
/// plugin declaring less is rejected at manifest validation instead of
/// silently failing every notification with an opaque `MemoryLimit` —
/// mirroring `MIN_V2_OUTPUT_BYTES`'s rationale above. `waf.detect`'s
/// worst-case verdict JSON is smaller than `WafBlockEvent`'s; it reuses
/// this same floor rather than introducing a second constant.
const MIN_NOTIFY_INPUT_BYTES: usize = 1024;
```

3. Add `has_waf_detect: bool` to the `CompiledPlugin` struct (after `has_notify_waf_block: bool,`):

```rust
    has_waf_detect: bool,
```

4. In `PluginEngine::compile`, change the `abi_version` match to return three-tuples instead of two. Replace:

```rust
        let (has_health_check, has_notify_waf_block) = match manifest.abi_version {
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
                (has_health_check, false)
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
                (false, has_notify_waf_block)
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
        })
```

with:

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

5. In `PluginManifest::validate`, replace the two `notify.waf_block`-specific checks with checks that also cover `waf.detect`. Replace:

```rust
        if self.abi_version != 2 && self.capabilities.iter().any(|c| c == "notify.waf_block") {
            return Err(PluginError::InvalidManifest);
        }
```

with:

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

and replace:

```rust
        if self.capabilities.iter().any(|c| c == "notify.waf_block")
            && self.limits.max_output_bytes < MIN_NOTIFY_INPUT_BYTES
        {
            return Err(PluginError::InvalidManifest);
        }
```

with:

```rust
        if self
            .capabilities
            .iter()
            .any(|c| c == "notify.waf_block" || c == "waf.detect")
            && self.limits.max_output_bytes < MIN_NOTIFY_INPUT_BYTES
        {
            return Err(PluginError::InvalidManifest);
        }
```

6. Add `CompiledPlugin::detect`, directly after the existing `notify_waf_block` method (inside `impl CompiledPlugin`, before its closing `}`):

```rust
    /// Invokes the `waf.detect` capability's entry point on an
    /// `abi_version: 2` plugin that declared it. Returns the plugin's
    /// verdict or a `PluginError` for any host-detected failure (trap,
    /// timeout, fuel exhaustion, malformed export/output, or an
    /// out-of-bounds pointer). Never panics: every guest-controlled
    /// pointer/length is bounds-checked exactly as in `health_check`'s v2
    /// path.
    pub fn detect(
        &self,
        request: &bearust_plugin_sdk::WafDetectRequest,
    ) -> Result<bearust_plugin_sdk::WafDetectVerdict, PluginError> {
        if !self.has_waf_detect {
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
        let detect = instance
            .get_typed_func::<(i32, i32), i64>(&mut store, "bearust_waf_detect")
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

        let packed = detect
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

7. Add `PluginManager::waf_detector_plugin`, directly after the existing `waf_block_sink_plugin` method:

```rust
    /// Returns the compiled plugin currently acting as the custom WAF
    /// detector, if any: the first (lowest plugin ID) enabled plugin whose
    /// manifest declared `waf.detect`. Mirrors `waf_block_sink_plugin`'s
    /// selection rule exactly — at most one plugin is ever treated as the
    /// active detector; any other plugin also declaring the capability is
    /// simply never selected.
    pub fn waf_detector_plugin(&self) -> Option<Arc<CompiledPlugin>> {
        self.current
            .load_full()
            .plugins
            .values()
            .find_map(|record| {
                if !record.status.enabled {
                    return None;
                }
                let compiled = record.compiled.as_ref()?;
                compiled.has_waf_detect.then(|| Arc::clone(compiled))
            })
    }
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --test plugin_runtime`
Expected: PASS, all tests including the new `waf_detect_*`/`v2_missing_waf_detect_export_is_abi_mismatch`/`v2_out_of_bounds_alloc_pointer_is_trap_on_the_detect_input_write`/`waf_detector_plugin_is_none_*` tests.

- [ ] **Step 6: Run the full workspace test suite**

Run: `cargo test --workspace --locked`
Expected: PASS — confirms the `CompiledPlugin` field addition and tuple-arity change did not break any existing plugin_runtime consumer.

- [ ] **Step 7: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add src/plugin_runtime.rs tests/plugin_runtime.rs tests/fixtures/plugins/waf_detect_v2/
git commit -m "feat: add waf.detect plugin capability, export validation, and invocation"
```

---

### Task 4: `merge_plugin_verdict` in `src/waf.rs`

**Files:**
- Modify: `src/waf.rs`

**Interfaces:**
- Consumes: `bearust_plugin_sdk::{WafDetectVerdict, WafPluginDecision}` (Task 1), the existing `Evaluation`/`WafDecision` types in this same file.
- Produces: `pub fn merge_plugin_verdict(evaluation: Evaluation, verdict: bearust_plugin_sdk::WafDetectVerdict) -> Evaluation`, used by Task 5.

- [ ] **Step 1: Add the failing tests**

Add to `src/waf.rs`. There is currently no `#[cfg(test)] mod tests` block in this file, so add one at the end of the file:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use bearust_plugin_sdk::{WafDetectVerdict, WafPluginDecision};

    fn evaluation(decision: WafDecision) -> Evaluation {
        Evaluation {
            decision,
            matched_rule_ids: Vec::new(),
            categories: Vec::new(),
            diagnostic: None,
            semantic_score: 0,
            severity: None,
        }
    }

    fn verdict(decision: WafPluginDecision) -> WafDetectVerdict {
        WafDetectVerdict {
            decision,
            category: "custom_detector".into(),
            score: 5,
        }
    }

    #[test]
    fn merge_is_most_severe_wins_across_all_nine_combinations() {
        let cases = [
            (WafDecision::Allow, WafPluginDecision::Allow, WafDecision::Allow),
            (WafDecision::Allow, WafPluginDecision::Log, WafDecision::Log),
            (WafDecision::Allow, WafPluginDecision::Block, WafDecision::Block),
            (WafDecision::Log, WafPluginDecision::Allow, WafDecision::Log),
            (WafDecision::Log, WafPluginDecision::Log, WafDecision::Log),
            (WafDecision::Log, WafPluginDecision::Block, WafDecision::Block),
            (WafDecision::Block, WafPluginDecision::Allow, WafDecision::Block),
            (WafDecision::Block, WafPluginDecision::Log, WafDecision::Block),
            (WafDecision::Block, WafPluginDecision::Block, WafDecision::Block),
        ];
        for (existing, plugin, expected) in cases {
            let merged = merge_plugin_verdict(evaluation(existing.clone()), verdict(plugin.clone()));
            assert_eq!(
                merged.decision, expected,
                "existing={existing:?} plugin={plugin:?} expected={expected:?}"
            );
        }
    }

    #[test]
    fn merge_can_never_downgrade_an_existing_block() {
        let merged = merge_plugin_verdict(
            evaluation(WafDecision::Block),
            verdict(WafPluginDecision::Allow),
        );
        assert_eq!(merged.decision, WafDecision::Block);
    }

    #[test]
    fn merge_appends_the_plugin_category_and_adds_its_score() {
        let mut base = evaluation(WafDecision::Allow);
        base.categories.push("sqli".into());
        base.semantic_score = 3;
        let merged = merge_plugin_verdict(base, verdict(WafPluginDecision::Log));
        assert_eq!(merged.categories, vec!["sqli".to_string(), "custom_detector".to_string()]);
        assert_eq!(merged.semantic_score, 8);
    }

    #[test]
    fn merge_does_not_duplicate_a_category_the_rule_engine_already_matched() {
        let mut base = evaluation(WafDecision::Allow);
        base.categories.push("custom_detector".into());
        let merged = merge_plugin_verdict(base, verdict(WafPluginDecision::Allow));
        assert_eq!(merged.categories, vec!["custom_detector".to_string()]);
    }

    #[test]
    fn merge_recomputes_severity_from_the_combined_score() {
        let merged = merge_plugin_verdict(
            evaluation(WafDecision::Allow),
            WafDetectVerdict {
                decision: WafPluginDecision::Log,
                category: "custom_detector".into(),
                score: 8,
            },
        );
        assert_eq!(merged.severity.as_deref(), Some("high"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib waf::tests`
Expected: FAIL to compile — `merge_plugin_verdict` not found.

- [ ] **Step 3: Implement `merge_plugin_verdict`**

Add to `src/waf.rs`, directly after the `pub fn evaluate(...)` function's closing `}`:

```rust
/// Merges a `waf.detect` plugin's verdict into an existing `Evaluation`.
/// Escalate-only: the combined decision is the more severe of the two
/// (`Block` beats `Log` beats `Allow`), so a plugin verdict can raise
/// severity but can never turn an `Evaluation` that already reached
/// `Block` into anything else. The plugin's category is appended (deduped)
/// and its score is added into `semantic_score`, with `severity`
/// recomputed from the combined score so the two fields stay consistent.
pub fn merge_plugin_verdict(
    mut evaluation: Evaluation,
    verdict: bearust_plugin_sdk::WafDetectVerdict,
) -> Evaluation {
    let verdict_decision = match verdict.decision {
        bearust_plugin_sdk::WafPluginDecision::Allow => WafDecision::Allow,
        bearust_plugin_sdk::WafPluginDecision::Log => WafDecision::Log,
        bearust_plugin_sdk::WafPluginDecision::Block => WafDecision::Block,
    };
    evaluation.decision = match (evaluation.decision, verdict_decision) {
        (WafDecision::Block, _) | (_, WafDecision::Block) => WafDecision::Block,
        (WafDecision::Log, _) | (_, WafDecision::Log) => WafDecision::Log,
        _ => WafDecision::Allow,
    };
    if !verdict.category.is_empty() && !evaluation.categories.contains(&verdict.category) {
        evaluation.categories.push(verdict.category);
    }
    evaluation.semantic_score = evaluation.semantic_score.saturating_add(verdict.score);
    evaluation.severity = severity_for_score(evaluation.semantic_score);
    evaluation
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib waf::tests`
Expected: PASS, all 5 new tests.

- [ ] **Step 5: Run the full workspace test suite**

Run: `cargo test --workspace --locked`
Expected: PASS.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add src/waf.rs
git commit -m "feat: add escalate-only merge_plugin_verdict to the WAF evaluator"
```

---

### Task 5: Wire the detector into `proxy.rs` and `cli.rs`

**Files:**
- Modify: `src/proxy.rs`
- Modify: `src/cli.rs`

**Interfaces:**
- Consumes: `crate::plugin_runtime::PluginManager::waf_detector_plugin`/`CompiledPlugin::detect` (Task 3), `crate::waf::merge_plugin_verdict` (Task 4), `bearust_plugin_sdk::WafDetectRequest` (Task 1), `PluginMetrics::record_waf_detect_*` (Task 2).
- Produces: `BeaRustProxy::plugin_manager: Option<Arc<crate::plugin_runtime::PluginManager>>`, `BeaRustProxy::with_plugin_manager(...)` builder method, wired at both `request_filter` and `request_body_filter` call sites.

- [ ] **Step 1: Add the failing tests**

Add to `src/proxy.rs`'s existing `#[cfg(test)] mod tests` block. First extend the `use super::{...}` line at the top of the block (currently `use super::{error_status, invoke_analytics_changed, waf_block_event};`) to:

```rust
    use super::{apply_waf_detector, error_status, invoke_analytics_changed, waf_block_event};
```

Then add these imports and tests at the end of the `mod tests` block, before its closing `}`:

```rust
    use crate::config::PluginConfig;
    use crate::plugin_runtime::PluginManager;
    use std::fs;
    use tempfile::tempdir;

    fn waf_detector_manager(enabled: bool) -> Arc<PluginManager> {
        let root = tempdir().unwrap();
        let plugin = root.path().join("waf-detect-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/waf_detect_v2/plugin.toml"),
        )
        .unwrap();
        let module = wat::parse_str(include_str!(
            "../tests/fixtures/plugins/waf_detect_v2/waf_detect_v2.wat"
        ))
        .unwrap();
        fs::write(plugin.join("waf_detect_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();
        if !enabled {
            manager.set_enabled("waf-detect-v2", false).unwrap();
        }
        manager
    }

    fn sample_context() -> crate::waf::InspectionContext {
        crate::waf::InspectionContext {
            method: "GET".into(),
            path: "/".into(),
            query: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    fn allow_evaluation() -> crate::waf::Evaluation {
        crate::waf::Evaluation {
            decision: crate::waf::WafDecision::Allow,
            matched_rule_ids: Vec::new(),
            categories: Vec::new(),
            diagnostic: None,
            semantic_score: 0,
            severity: None,
        }
    }

    fn block_evaluation() -> crate::waf::Evaluation {
        crate::waf::Evaluation {
            decision: crate::waf::WafDecision::Block,
            ..allow_evaluation()
        }
    }

    #[tokio::test]
    async fn a_block_verdict_escalates_an_allow_decision() {
        let manager = waf_detector_manager(true);
        let merged =
            apply_waf_detector(Some(&manager), &sample_context(), allow_evaluation()).await;
        assert_eq!(merged.decision, crate::waf::WafDecision::Block);
        assert!(merged.categories.contains(&"custom_detector".to_string()));
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_waf_detect_invocations_total 1"));
        assert!(output.contains("bearust_plugins_waf_detect_block_total 1"));
    }

    #[tokio::test]
    async fn a_plugin_verdict_can_never_downgrade_an_existing_block() {
        // The fixture always returns Block, so this exercises the
        // Block-stays-Block path rather than a downgrade -- the important
        // assertion is that a rule-engine Block is never lost.
        let manager = waf_detector_manager(true);
        let merged =
            apply_waf_detector(Some(&manager), &sample_context(), block_evaluation()).await;
        assert_eq!(merged.decision, crate::waf::WafDecision::Block);
    }

    #[tokio::test]
    async fn no_detector_configured_leaves_the_evaluation_unchanged() {
        let manager = PluginManager::new(PluginConfig::default());
        let evaluation = allow_evaluation();
        let merged =
            apply_waf_detector(Some(&manager), &sample_context(), evaluation.clone()).await;
        assert_eq!(merged.decision, evaluation.decision);
        assert_eq!(merged.categories, evaluation.categories);
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_waf_detect_invocations_total 0"));
    }

    #[tokio::test]
    async fn a_disabled_detector_leaves_the_evaluation_unchanged() {
        let manager = waf_detector_manager(false);
        let evaluation = allow_evaluation();
        let merged =
            apply_waf_detector(Some(&manager), &sample_context(), evaluation.clone()).await;
        assert_eq!(merged.decision, evaluation.decision);
    }

    #[tokio::test]
    async fn no_plugin_manager_leaves_the_evaluation_unchanged() {
        let evaluation = allow_evaluation();
        let merged = apply_waf_detector(None, &sample_context(), evaluation.clone()).await;
        assert_eq!(merged.decision, evaluation.decision);
    }

    #[tokio::test]
    async fn a_trapping_detector_fails_open_and_counts_a_failure() {
        let root = tempdir().unwrap();
        let plugin = root.path().join("waf-detect-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/waf_detect_v2/plugin.toml"),
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
            (func (export "bearust_waf_detect") (param i32 i32) (result i64) unreachable))"#;
        let module = wat::parse_str(wat).unwrap();
        fs::write(plugin.join("waf_detect_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();

        let evaluation = allow_evaluation();
        let merged =
            apply_waf_detector(Some(&manager), &sample_context(), evaluation.clone()).await;
        assert_eq!(merged.decision, evaluation.decision);
        let output = manager.metrics().render_prometheus();
        assert!(output.contains("bearust_plugins_waf_detect_failures_total 1"));
        assert!(output.contains("bearust_plugins_waf_detect_invocations_total 0"));
    }
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib proxy::tests`
Expected: FAIL to compile — `apply_waf_detector` not found.

- [ ] **Step 3: Implement the wiring**

In `src/proxy.rs`, add `PluginManager` to the existing `use crate::{...}` block at the top of the file (after the `waf_store::WafStore,` line):

```rust
    plugin_runtime::PluginManager,
```

Add a new field to `BeaRustProxy` (after `pub plugin_notify: Option<Arc<crate::plugin_notify::NotificationSink>>,`):

```rust
    pub plugin_manager: Option<Arc<PluginManager>>,
```

Initialize it in `BeaRustProxy::new` (after `plugin_notify: None,`):

```rust
            plugin_manager: None,
```

Add a builder method, directly after `with_plugin_notify_sink`:

```rust
    pub fn with_plugin_manager(mut self, manager: Arc<PluginManager>) -> Self {
        self.plugin_manager = Some(manager);
        self
    }
```

Add two free functions, directly after the existing `waf_block_event` function (before `emit_waf_telemetry`):

```rust
/// Converts a WAF `InspectionContext` into the wire shape a `waf.detect`
/// plugin receives. Pure and side-effect free.
fn waf_detect_request(context: &InspectionContext) -> bearust_plugin_sdk::WafDetectRequest {
    bearust_plugin_sdk::WafDetectRequest {
        method: context.method.clone(),
        path: context.path.clone(),
        query: context.query.clone(),
        headers: context.headers.clone(),
        body: context.body.clone(),
    }
}

/// Runs the registered `waf.detect` plugin (if any) against `context` and
/// merges its verdict into `evaluation`. Synchronous from the caller's
/// point of view but offloads the blocking wasmtime call via
/// `spawn_blocking` so it never blocks the shared async runtime. Fails
/// open on every error class: no detector configured, no plugin currently
/// declaring the capability, a disabled plugin, a trap/timeout/fuel
/// exhaustion, a malformed verdict, or a `spawn_blocking` join failure all
/// return `evaluation` unchanged (after counting a failure metric where
/// applicable).
async fn apply_waf_detector(
    plugin_manager: Option<&Arc<PluginManager>>,
    context: &InspectionContext,
    evaluation: Evaluation,
) -> Evaluation {
    let Some(manager) = plugin_manager else {
        return evaluation;
    };
    let Some(detector) = manager.waf_detector_plugin() else {
        return evaluation;
    };
    let metrics = manager.metrics();
    let request = waf_detect_request(context);
    let outcome = tokio::task::spawn_blocking(move || detector.detect(&request)).await;
    match outcome {
        Ok(Ok(verdict)) => {
            metrics.record_waf_detect_invocation();
            let previous_decision = evaluation.decision.clone();
            let merged = crate::waf::merge_plugin_verdict(evaluation, verdict);
            if merged.decision != previous_decision {
                metrics.record_waf_detect_block();
            }
            merged
        }
        Ok(Err(error)) => {
            tracing::warn!(event = "waf_detect_failed", reason = error.code());
            metrics.record_waf_detect_failure();
            evaluation
        }
        Err(_join_error) => {
            tracing::warn!(event = "waf_detect_failed", reason = "join_error");
            metrics.record_waf_detect_failure();
            evaluation
        }
    }
}
```

Wire the header-stage call site. In `request_filter`, replace:

```rust
            let evaluation = evaluate(&waf_snapshot, &context);
            ctx.waf_blocked = evaluation.decision == WafDecision::Block;
```

with:

```rust
            let evaluation = evaluate(&waf_snapshot, &context);
            let evaluation =
                apply_waf_detector(self.plugin_manager.as_ref(), &context, evaluation).await;
            ctx.waf_blocked = evaluation.decision == WafDecision::Block;
```

Wire the body-stage call site. In `request_body_filter`, replace:

```rust
            let evaluation = ctx
                .waf_snapshot
                .as_ref()
                .map(|snapshot| evaluate(snapshot, &context))
                .unwrap_or_else(|| evaluate(&waf.snapshot(), &context));
            ctx.waf_blocked = evaluation.decision == WafDecision::Block;
```

with:

```rust
            let evaluation = ctx
                .waf_snapshot
                .as_ref()
                .map(|snapshot| evaluate(snapshot, &context))
                .unwrap_or_else(|| evaluate(&waf.snapshot(), &context));
            let evaluation =
                apply_waf_detector(self.plugin_manager.as_ref(), &context, evaluation).await;
            ctx.waf_blocked = evaluation.decision == WafDecision::Block;
```

In `src/cli.rs`, wire the manager into the proxy builder chain. After the existing line:

```rust
                .with_plugin_notify_sink(plugin_notify_sink)
```

add:

```rust
                .with_plugin_manager(control_state.plugin_manager.clone())
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cargo test --lib proxy::tests`
Expected: PASS, all new `apply_waf_detector` tests plus the existing `waf_block_event*` tests.

- [ ] **Step 5: Run the full workspace test suite**

Run: `cargo test --workspace --locked`
Expected: PASS.

- [ ] **Step 6: Format, lint, commit**

```bash
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
git add src/proxy.rs src/cli.rs
git commit -m "feat: apply the waf.detect plugin verdict at both WAF evaluation stages"
```

---

### Task 6: Documentation and final acceptance gate

**Files:**
- Modify: `docs/PRD.md`

**Interfaces:** None (documentation only).

- [ ] **Step 1: Update the PRD**

Find the "Phase 13D is next" forward-pointer paragraph in `docs/PRD.md` (added at the end of Phase 13C's work) and replace it with a completed-status section, following the exact structure of the existing "Phase 13C status" section immediately above it. Read that section first (`grep -n "Phase 13C status" -A 30 docs/PRD.md`) to match its tone and level of detail, then write a "Phase 13D status: custom WAF detector hook" section covering:
- The capability name (`waf.detect`) and required export signature (`bearust_waf_detect(ptr: i32, len: i32) -> i64`).
- That the hook runs synchronously at both WAF evaluation stages (header and body), off the async runtime via `spawn_blocking`.
- The escalate-only merge rule: a plugin verdict can raise severity but never downgrade an existing `Block`.
- Fail-open behavior on every plugin error class.
- Lowest-enabled-ID selection (at most one active detector).
- The three new Prometheus counters.
- A forward-pointer: "Phase 13E is next: request/response transform hooks, followed by custom load-balancing hooks, each reviewed individually and built on this same memory convention."

- [ ] **Step 2: Run the full acceptance gate**

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

Expected: all three commands pass with zero warnings/failures. If `cargo test --workspace --locked` hits a subprocess-spawning integration test failure unrelated to any file this plan touches (there is prior, documented flakiness in tests that spawn a real `bearust serve` against a shared relative `./data/` SQLite path — see `log_contract.rs`, `shutdown.rs`, `cluster_command_gateway.rs`), re-run that specific test in isolation after `rm -rf ./data && pkill -9 -f "bearust serve" || true` before concluding it is a regression.

- [ ] **Step 3: Commit**

```bash
git add docs/PRD.md
git commit -m "docs: mark phase 13d custom waf detector hook complete"
```
