# Phase 13C — Notification Sink Hook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add the first plugin traffic hook — a WAF-block notification sink — so an `abi_version: 2` plugin declaring the `notify.waf_block` capability can observe WAF-block events without ever being able to affect the request/response that triggered them or add latency to the proxy hot path.

**Architecture:** `emit_waf_telemetry` in `src/proxy.rs` builds a `WafBlockEvent` (a new type in `bearust-plugin-sdk`, mirroring the existing `waf::RedactedTelemetry` fields) whenever a request is blocked, and hands it to a `NotificationSink` (new `src/plugin_notify.rs`) via a non-blocking `try_send` into a bounded `tokio::sync::mpsc` channel. A background worker task pulls events off the channel and, if exactly one enabled plugin currently declares the `notify.waf_block` capability, invokes its `bearust_notify_waf_block(ptr, len) -> i32` export using Phase 13B's existing alloc/write/call/dealloc memory convention. Every outcome (success, plugin-reported failure, host-detected failure, dropped-because-full) is counted in new `PluginMetrics` counters; none of it is ever awaited by, or able to block, the request path.

**Tech Stack:** Rust, `wasmtime` (`=27.0.0`, already pinned), `tokio::sync::mpsc`, the existing `bearust-plugin-sdk` crate and `PluginManager`/`CompiledPlugin` runtime from Phase 13A/13B.

## Global Constraints

- Queue capacity is a fixed `256`; a full queue drops the newest event (never blocks the sender) and increments `notify_queue_dropped_total`.
- No retry on any notify failure (queue-full, trap, timeout, fuel exhaustion, malformed export, or a plugin-reported nonzero status) — one attempt per event, then the outcome is counted and discarded.
- Exactly one plugin is ever treated as the active sink: the first, by ascending plugin ID, currently **enabled** plugin whose manifest declares the `notify.waf_block` capability. Any other plugin also declaring the capability is simply never selected — this is intentional, not an error.
- New capability string `"notify.waf_block"` is only valid on a manifest with `abi_version: 2`; declaring it with `abi_version: 1` (or any other value) is `PluginError::InvalidManifest` at manifest validation time.
- New guest export required only when `notify.waf_block` is declared: `bearust_notify_waf_block(ptr: i32, len: i32) -> i32`, returning `0` for success and any nonzero value for a plugin-self-reported failure. Missing or mistyped is `PluginError::AbiMismatch`, exactly like every other Phase 13A/13B export check.
- Existing, unrelated `abi_version: 2` behavior does not change: every `abi_version: 2` module — notify-capable or not — must still unconditionally export `bearust_health_check_v2` (this was already true before this phase and is out of scope to change).
- Event JSON shape (new `bearust_plugin_sdk::WafBlockEvent`, shared by host and guest):
  ```rust
  pub struct WafBlockEvent {
      pub request_id: String,
      pub occurred_at_ms: u64,
      pub category: String,
      pub score: u16,
      pub severity: String,
      pub reason_ids: String,
  }
  ```
  `category`/`score`/`severity`/`reason_ids` are always populated from `src/waf.rs::redacted_telemetry`'s existing output — no new redaction logic, no raw headers/body/query/IP ever included.
- The proxy request path must never await plugin execution for this hook: enqueueing is a synchronous, non-blocking `try_send`.
- New Prometheus counters on the existing `bearust_plugins_operations_total`-style surface (`PluginMetrics` in `src/observability.rs`): `bearust_plugins_notify_invocations_total` (plugin returned `0`), `bearust_plugins_notify_failures_total` (any other outcome), `bearust_plugins_notify_dropped_total` (queue was full).
- The acceptance gate is: `cargo fmt --all -- --check`, `cargo clippy --workspace --all-targets -- -D warnings`, and `cargo test --workspace --locked` all pass on the project's pinned toolchain (currently `1.97.1`, see `rust-toolchain.toml`).

---

### Task 1: `WafBlockEvent` shared type in `bearust-plugin-sdk`

**Files:**
- Modify: `crates/bearust-plugin-sdk/src/lib.rs`

**Interfaces:**
- Produces: `pub struct WafBlockEvent { pub request_id: String, pub occurred_at_ms: u64, pub category: String, pub score: u16, pub severity: String, pub reason_ids: String }`, deriving `Debug, Clone, Serialize, Deserialize, PartialEq, Eq`. Used by `src/plugin_runtime.rs` (Task 3), `src/plugin_notify.rs` (Task 4), and `src/proxy.rs` (Task 5) on the host side, and by any `notify.waf_block` plugin's guest code via `bearust_plugin_sdk::read_input`.

- [ ] **Step 1: Write the failing test**

Add to the existing `#[cfg(test)] mod tests` block in `crates/bearust-plugin-sdk/src/lib.rs` (it already has `use super::*;` at the top, so no new import is needed once the type exists below):

```rust
    #[test]
    fn waf_block_event_round_trips() {
        let value = WafBlockEvent {
            request_id: "req-1".into(),
            occurred_at_ms: 1_700_000_000_000,
            category: "sqli".into(),
            score: 42,
            severity: "high".into(),
            reason_ids: "sqli".into(),
        };
        let bytes = encode(&value);
        let decoded: WafBlockEvent = decode(&bytes).unwrap();
        assert_eq!(decoded, value);
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test -p bearust-plugin-sdk waf_block_event_round_trips`
Expected: FAIL to compile — `WafBlockEvent` is not defined yet.

- [ ] **Step 3: Add the type**

Add this at the bottom of `crates/bearust-plugin-sdk/src/lib.rs`, after the existing `HealthCheckOutput` definition:

```rust
/// Event delivered to a `notify.waf_block` capability plugin when the WAF
/// blocks a request. Mirrors `src/waf.rs::RedactedTelemetry` on the host
/// side, plus a request identifier and timestamp. Never carries raw
/// headers, body, query string, or client IP — only what
/// `redacted_telemetry` already produces for tracing/audit today.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct WafBlockEvent {
    pub request_id: String,
    pub occurred_at_ms: u64,
    pub category: String,
    pub score: u16,
    pub severity: String,
    pub reason_ids: String,
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test -p bearust-plugin-sdk`
Expected: PASS, all `bearust-plugin-sdk` tests green (including the new one).

- [ ] **Step 5: Commit**

```bash
git add crates/bearust-plugin-sdk/src/lib.rs
git commit -m "feat(plugin-sdk): add WafBlockEvent shared type for the notify.waf_block hook"
```

---

### Task 2: `PluginMetrics` notify counters

**Files:**
- Modify: `src/observability.rs`

**Interfaces:**
- Consumes: nothing new.
- Produces: `PluginMetrics::record_notify_invocation(&self)`, `PluginMetrics::record_notify_failure(&self)`, `PluginMetrics::record_notify_dropped(&self)` — used by `src/plugin_notify.rs` (Task 4). `render_prometheus()` gains three new counter lines: `bearust_plugins_notify_invocations_total`, `bearust_plugins_notify_failures_total`, `bearust_plugins_notify_dropped_total`.

- [ ] **Step 1: Write the failing test**

Add to the `#[cfg(test)] mod tests` block at the bottom of `src/observability.rs` (it already has `use super::*;`):

```rust
    #[test]
    fn notify_metrics_render_as_counters() {
        let metrics = PluginMetrics::default();
        metrics.record_notify_invocation();
        metrics.record_notify_invocation();
        metrics.record_notify_failure();
        metrics.record_notify_dropped();
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_invocations_total 2"));
        assert!(output.contains("bearust_plugins_notify_failures_total 1"));
        assert!(output.contains("bearust_plugins_notify_dropped_total 1"));
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib observability::tests::notify_metrics_render_as_counters`
Expected: FAIL to compile — `record_notify_invocation` and friends are not defined yet.

- [ ] **Step 3: Add the fields, methods, and Prometheus lines**

In `src/observability.rs`, extend the `PluginMetrics` struct definition:

```rust
#[derive(Debug, Default)]
pub struct PluginMetrics {
    reload_success: AtomicU64,
    reload_failure: AtomicU64,
    enable_success: AtomicU64,
    enable_failure: AtomicU64,
    disable_success: AtomicU64,
    disable_failure: AtomicU64,
    unload_success: AtomicU64,
    unload_failure: AtomicU64,
    health_check_success: AtomicU64,
    health_check_failure: AtomicU64,
    loaded: AtomicU64,
    notify_invocations: AtomicU64,
    notify_failures: AtomicU64,
    notify_dropped: AtomicU64,
}
```

Add these methods to `impl PluginMetrics`, right after `set_loaded`:

```rust
    /// The registered `notify.waf_block` sink returned status `0`.
    pub fn record_notify_invocation(&self) {
        self.notify_invocations.fetch_add(1, Ordering::Relaxed);
    }

    /// The registered sink returned a nonzero status, trapped, timed out,
    /// exhausted its fuel, or had a malformed export — any outcome other
    /// than a clean `0` return.
    pub fn record_notify_failure(&self) {
        self.notify_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// A WAF-block event was dropped because the notification queue was
    /// full.
    pub fn record_notify_dropped(&self) {
        self.notify_dropped.fetch_add(1, Ordering::Relaxed);
    }
```

Extend `render_prometheus`, adding this immediately before the final `output` (the function's last line, `output`):

```rust
        output.push_str("# TYPE bearust_plugins_notify_invocations_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_notify_invocations_total {}\n",
            self.notify_invocations.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_notify_failures_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_notify_failures_total {}\n",
            self.notify_failures.load(Ordering::Relaxed)
        ));
        output.push_str("# TYPE bearust_plugins_notify_dropped_total counter\n");
        output.push_str(&format!(
            "bearust_plugins_notify_dropped_total {}\n",
            self.notify_dropped.load(Ordering::Relaxed)
        ));
```

- [ ] **Step 4: Run test to verify it passes**

Run: `cargo test --lib observability::`
Expected: PASS, all `observability` module tests green.

- [ ] **Step 5: Commit**

```bash
git add src/observability.rs
git commit -m "feat: add notification-sink counters to PluginMetrics"
```

---

### Task 3: Plugin runtime — `notify.waf_block` capability, export validation, and invocation

**Files:**
- Modify: `src/plugin_runtime.rs`
- Create: `tests/fixtures/plugins/notify_sink_v2/plugin.toml`
- Create: `tests/fixtures/plugins/notify_sink_v2/notify_sink_v2.wat`
- Create: `tests/fixtures/plugins/notify_sink_v2/README.md`
- Modify: `tests/plugin_runtime.rs`

**Interfaces:**
- Consumes: `bearust_plugin_sdk::WafBlockEvent`, `bearust_plugin_sdk::encode` (Task 1).
- Produces: `CompiledPlugin::notify_waf_block(&self, event: &bearust_plugin_sdk::WafBlockEvent) -> Result<i32, PluginError>` and `PluginManager::waf_block_sink_plugin(&self) -> Option<Arc<CompiledPlugin>>` — both used by `src/plugin_notify.rs` (Task 4).

**Important existing behavior to preserve:** `PluginEngine::compile` already requires every `abi_version: 2` module to export `bearust_health_check_v2` unconditionally, regardless of its declared capabilities. This does not change. The new `notify_sink_v2` fixture below must still export a (trivial, unused-in-these-tests) `bearust_health_check_v2` to compile at all.

- [ ] **Step 1: Write the failing tests**

Add these to `tests/plugin_runtime.rs`. First, two manifest-validation tests — add them after the existing `abi_version_one_output_floor_is_unaffected_by_the_v2_floor` test:

```rust
#[test]
fn notify_capability_requires_abi_version_two() {
    let text = manifest("").replace("[\"health_check\"]", "[\"notify.waf_block\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    assert_eq!(
        m.validate(&PluginPolicy::default()).unwrap_err(),
        PluginError::InvalidManifest
    );
}

#[test]
fn notify_capability_is_accepted_with_abi_version_two() {
    let dir = tempdir().unwrap();
    fs::write(dir.path().join("demo.wasm"), b"wasm").unwrap();
    let text = manifest("")
        .replace("abi_version = 1", "abi_version = 2")
        .replace("[\"health_check\"]", "[\"notify.waf_block\"]");
    let m = PluginManifest::from_toml(text.as_bytes()).unwrap();
    let p = PluginPolicy {
        module_root: dir.path().into(),
        ..Default::default()
    };
    let validated = m.validate(&p).unwrap();
    assert_eq!(validated.capabilities, vec!["notify.waf_block".to_string()]);
}
```

Next, add a capability-aware compile helper and an `AbiMismatch` test for a missing `bearust_notify_waf_block` export. Add the helper right after the existing `compile_error_v2` function:

```rust
fn validated_v2_with_capabilities(limits: PluginLimits, capabilities: Vec<String>) -> ValidatedManifest {
    ValidatedManifest {
        capabilities,
        ..validated_v2(limits)
    }
}

fn compile_error_v2_with_capabilities(wat: &str, capabilities: Vec<String>) -> PluginError {
    let engine = PluginEngine::new(PluginPolicy::default()).unwrap();
    let bytes = wat::parse_str(wat).unwrap();
    match engine.compile(validated_v2_with_capabilities(limits(), capabilities), &bytes) {
        Ok(_) => panic!("module unexpectedly compiled"),
        Err(error) => error,
    }
}

fn compile_v2_with_capabilities(
    wat: &str,
    capabilities: Vec<String>,
) -> Result<CompiledPlugin, PluginError> {
    let engine = PluginEngine::new(PluginPolicy::default())?;
    let bytes = wat::parse_str(wat).unwrap();
    engine.compile(validated_v2_with_capabilities(limits(), capabilities), &bytes)
}
```

Then add the tests, after `v2_wrong_signature_export_is_abi_mismatch`:

```rust
#[test]
fn v2_missing_notify_export_is_abi_mismatch() {
    // Exports the mandatory v2 baseline (memory, alloc, dealloc,
    // bearust_health_check_v2) but not bearust_notify_waf_block, even
    // though the manifest declares the notify.waf_block capability.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 0)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0))"#;
    assert_eq!(
        compile_error_v2_with_capabilities(wat, vec!["notify.waf_block".into()]),
        PluginError::AbiMismatch
    );
}

#[test]
fn v2_out_of_bounds_alloc_pointer_is_trap_on_the_notify_input_write() {
    // Hostile guest: bearust_alloc hands back a pointer far past the end of
    // the guest's single 65536-byte page. The host must reject it while
    // bounds-checking the *input* write, before bearust_notify_waf_block is
    // even called. Mirrors
    // v2_out_of_bounds_alloc_pointer_is_trap_on_the_input_write for the
    // health-check path.
    let wat = r#"(module
        (memory (export "memory") 1)
        (func (export "bearust_abi_version") (result i32) i32.const 2)
        (func (export "bearust_alloc") (param i32) (result i32) i32.const 1000000)
        (func (export "bearust_dealloc") (param i32 i32))
        (func (export "bearust_health_check_v2") (param i32 i32) (result i64) i64.const 0)
        (func (export "bearust_notify_waf_block") (param i32 i32) (result i32)
            unreachable))"#;
    let plugin = compile_v2_with_capabilities(wat, vec!["notify.waf_block".into()]).unwrap();
    let event = bearust_plugin_sdk::WafBlockEvent {
        request_id: "req-1".into(),
        occurred_at_ms: 1_700_000_000_000,
        category: "sqli".into(),
        score: 42,
        severity: "high".into(),
        reason_ids: "sqli".into(),
    };
    assert_eq!(plugin.notify_waf_block(&event).unwrap_err(), PluginError::Trap);
}
```

Finally, add the fixture-based round-trip and sink-selection tests. Add these after `v2_health_fixture_round_trips_json_over_guest_memory`:

```rust
#[test]
fn notify_sink_fixture_round_trips_json_and_reports_success() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("notify-sink-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/notify_sink_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/notify_sink_v2/notify_sink_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("notify_sink_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    let summary = manager.reload_from_disk().unwrap();
    assert_eq!(summary.loaded, 1);

    let sink = manager
        .waf_block_sink_plugin()
        .expect("notify-sink-v2 declares notify.waf_block and is enabled");
    let event = bearust_plugin_sdk::WafBlockEvent {
        request_id: "req-1".into(),
        occurred_at_ms: 1_700_000_000_000,
        category: "sqli".into(),
        score: 42,
        severity: "high".into(),
        reason_ids: "sqli".into(),
    };
    assert_eq!(sink.notify_waf_block(&event).unwrap(), 0);
}

#[test]
fn waf_block_sink_plugin_is_none_when_no_plugin_declares_the_capability() {
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
    assert!(manager.waf_block_sink_plugin().is_none());
}

#[test]
fn waf_block_sink_plugin_is_none_when_disabled() {
    let root = tempdir().unwrap();
    let plugin = root.path().join("notify-sink-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        include_str!("fixtures/plugins/notify_sink_v2/plugin.toml"),
    )
    .unwrap();
    let module = wat::parse_str(include_str!(
        "fixtures/plugins/notify_sink_v2/notify_sink_v2.wat"
    ))
    .unwrap();
    fs::write(plugin.join("notify_sink_v2.wasm"), &module).unwrap();

    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: root.path().to_path_buf(),
        ..PluginConfig::default()
    });
    manager.reload_from_disk().unwrap();
    manager.set_enabled("notify-sink-v2", false).unwrap();
    assert!(manager.waf_block_sink_plugin().is_none());
}
```

No new `use` import is needed in `tests/plugin_runtime.rs`: every test above references `bearust_plugin_sdk::WafBlockEvent { .. }` by its full path, since `bearust_plugin_sdk` is already a dependency of the `bearust` crate and thus visible to its integration tests without an explicit `use`.

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --test plugin_runtime`
Expected: FAIL to compile — `notify.waf_block` is rejected by the current allow-list, `PluginManager::waf_block_sink_plugin` and `CompiledPlugin::notify_waf_block` don't exist yet, and the fixture files don't exist yet.

- [ ] **Step 3: Create the fixture files**

Create `tests/fixtures/plugins/notify_sink_v2/plugin.toml`:

```toml
id = "notify-sink-v2"
display_name = "Deterministic WAF-block notification sink"
abi_version = 2
module = "notify_sink_v2.wasm"
capabilities = ["notify.waf_block"]

[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1024
```

Create `tests/fixtures/plugins/notify_sink_v2/notify_sink_v2.wat`:

```wat
;; Deterministic Phase 13C fixture. Build with:
;;   wat2wasm notify_sink_v2.wat -o notify_sink_v2.wasm
;;
;; The test suite parses this WAT with the pinned `wat` dev dependency, so the
;; generated binary and any compiler cache are intentionally not checked in.
;;
;; Ignores the JSON the host writes as input and always returns status 0
;; (success) from bearust_notify_waf_block, proving the host's
;; alloc/write/call/dealloc round trip end to end. Every abi_version: 2
;; module must also export bearust_health_check_v2 regardless of its
;; declared capabilities (an existing Phase 13B requirement); this fixture
;; is never health-checked in tests, so that export is a trivial stub.
(module
  (memory (export "memory") 1)
  (global $heap_ptr (mut i32) (i32.const 1024))

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

  (func (export "bearust_notify_waf_block") (param $ptr i32) (param $len i32) (result i32)
    i32.const 0))
```

Create `tests/fixtures/plugins/notify_sink_v2/README.md`:

```markdown
# Deterministic notification-sink fixture

Local-only, no-import WASM fixture for the Phase 13C `notify.waf_block`
acceptance tests. Exports `bearust_alloc`/`bearust_dealloc`/
`bearust_notify_waf_block` per the memory convention in
`docs/superpowers/specs/2026-08-05-phase-13b-plugin-sdk-design.md`, plus a
trivial `bearust_health_check_v2` stub (required unconditionally of every
`abi_version: 2` module, independent of declared capabilities). It ignores
the host-supplied input and always returns status `0`, so the test suite can
assert an exact outcome while still exercising the full
alloc/write/call/dealloc round trip.

The checked-in WAT source is preferred over a generated binary for the same
reproducibility reasons as `tests/fixtures/plugins/health_ok/`.
```

- [ ] **Step 4: Add `ALLOWED_CAPABILITIES` and the abi_version-2 requirement**

In `src/plugin_runtime.rs`, add this constant right after `const MAX_DETAIL_BYTES: usize = 4096;`:

```rust
const ALLOWED_CAPABILITIES: [&str; 2] = ["health_check", "notify.waf_block"];
```

Replace the capabilities check inside `PluginManifest::validate`:

```rust
        if self
            .capabilities
            .iter()
            .any(|c| c != "health_check" || c.len() > MAX_CAPABILITY_LEN)
        {
            return Err(PluginError::InvalidManifest);
        }
```

with:

```rust
        if self.capabilities.iter().any(|c| {
            c.len() > MAX_CAPABILITY_LEN || !ALLOWED_CAPABILITIES.contains(&c.as_str())
        }) {
            return Err(PluginError::InvalidManifest);
        }
        if self.abi_version != 2 && self.capabilities.iter().any(|c| c == "notify.waf_block") {
            return Err(PluginError::InvalidManifest);
        }
```

- [ ] **Step 5: Run the manifest-validation tests**

Run: `cargo test --test plugin_runtime notify_capability`
Expected: PASS for both `notify_capability_requires_abi_version_two` and `notify_capability_is_accepted_with_abi_version_two`.

- [ ] **Step 6: Add `has_notify_waf_block` to `CompiledPlugin` and gate the new export at compile time**

In `src/plugin_runtime.rs`, add a field to the `CompiledPlugin` struct:

```rust
pub struct CompiledPlugin {
    engine: Engine,
    scheduler: Arc<EpochScheduler>,
    module: Module,
    limits: PluginLimits,
    abi_version: u32,
    has_health_check: bool,
    has_notify_waf_block: bool,
}
```

Inside `PluginEngine::compile`, replace this block:

```rust
        // Exhaustive on purpose: widening SUPPORTED_ABI_VERSIONS without
        // adding an arm here fails closed with AbiMismatch rather than
        // silently validating a new version against the wrong export set.
        let has_health_check = match manifest.abi_version {
            1 => match instance.get_typed_func::<(), i32>(&mut store, "bearust_health_check") {
                Ok(_) => true,
                Err(_)
                    if instance
                        .get_export(&mut store, "bearust_health_check")
                        .is_none() =>
                {
                    false
                }
                Err(_) => return Err(PluginError::AbiMismatch),
            },
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
                false
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
        })
```

with:

```rust
        // Exhaustive on purpose: widening SUPPORTED_ABI_VERSIONS without
        // adding an arm here fails closed with AbiMismatch rather than
        // silently validating a new version against the wrong export set.
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

- [ ] **Step 7: Run the missing-export test**

Run: `cargo test --test plugin_runtime v2_missing_notify_export_is_abi_mismatch`
Expected: PASS.

- [ ] **Step 8: Add `CompiledPlugin::notify_waf_block`**

In `src/plugin_runtime.rs`, add this method to `impl CompiledPlugin`, right after `health_check`:

```rust
    /// Invokes the `notify.waf_block` capability's entry point on an
    /// `abi_version: 2` plugin that declared it. Returns the plugin's raw
    /// `i32` status (`0` = success, nonzero = plugin-reported failure) or a
    /// `PluginError` for any host-detected failure (trap, timeout, fuel
    /// exhaustion, malformed export, or an out-of-bounds pointer). Never
    /// panics: every guest-controlled pointer/length is bounds-checked
    /// exactly as in `health_check`'s v2 path.
    pub fn notify_waf_block(
        &self,
        event: &bearust_plugin_sdk::WafBlockEvent,
    ) -> Result<i32, PluginError> {
        if !self.has_notify_waf_block {
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
        let notify = instance
            .get_typed_func::<(i32, i32), i32>(&mut store, "bearust_notify_waf_block")
            .map_err(|_| PluginError::AbiMismatch)?;

        let input = bearust_plugin_sdk::encode(event);
        let input_len: i32 = input
            .len()
            .try_into()
            .map_err(|_| PluginError::MemoryLimit)?;
        let input_ptr = alloc
            .call(&mut store, input_len)
            .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
        write_guest_bytes(&memory, &mut store, input_ptr, &input, &self.limits)?;

        let status = notify
            .call(&mut store, (input_ptr, input_len))
            .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
        dealloc
            .call(&mut store, (input_ptr, input_len))
            .map_err(|error| map_runtime_error(&error, started, &self.limits))?;

        Ok(status)
    }
```

- [ ] **Step 9: Add `PluginManager::waf_block_sink_plugin`**

In `src/plugin_runtime.rs`, add this method to `impl PluginManager`, right after `list`:

```rust
    /// Returns the compiled plugin currently acting as the WAF-block
    /// notification sink, if any: the first (lowest plugin ID) enabled
    /// plugin whose manifest declared `notify.waf_block`. At most one
    /// plugin is ever treated as the active sink in this phase; any other
    /// plugin also declaring the capability is simply never selected.
    pub fn waf_block_sink_plugin(&self) -> Option<Arc<CompiledPlugin>> {
        self.current.load_full().plugins.values().find_map(|record| {
            if !record.status.enabled {
                return None;
            }
            let compiled = record.compiled.as_ref()?;
            compiled.has_notify_waf_block.then(|| Arc::clone(compiled))
        })
    }
```

- [ ] **Step 10: Run all Task 3 tests**

Run: `cargo test --test plugin_runtime`
Expected: PASS, every test in `tests/plugin_runtime.rs` green, including all new ones.

- [ ] **Step 11: Commit**

```bash
git add src/plugin_runtime.rs tests/plugin_runtime.rs tests/fixtures/plugins/notify_sink_v2
git commit -m "feat: add notify.waf_block plugin capability, export validation, and invocation"
```

---

### Task 4: `NotificationSink` — bounded queue and background worker

**Files:**
- Create: `src/plugin_notify.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `bearust_plugin_sdk::WafBlockEvent` (Task 1), `PluginMetrics::record_notify_invocation/record_notify_failure/record_notify_dropped` (Task 2), `PluginManager::waf_block_sink_plugin`, `CompiledPlugin::notify_waf_block`, `PluginManager::metrics` (Task 3).
- Produces: `pub struct NotificationSink`, `NotificationSink::spawn(manager: Arc<PluginManager>) -> Arc<NotificationSink>`, `NotificationSink::notify_waf_block(&self, event: bearust_plugin_sdk::WafBlockEvent)` — both used by `src/proxy.rs` and `src/cli.rs` (Task 5).

- [ ] **Step 1: Write the failing tests**

Create `src/plugin_notify.rs` with just the module doc comment, the struct skeleton, and its test module (no working implementation yet), so the tests below fail to compile first:

```rust
//! Off-hot-path delivery of WAF-block events to an optional plugin sink.
use crate::observability::PluginMetrics;
use crate::plugin_runtime::PluginManager;
use std::sync::Arc;
use tokio::sync::mpsc;

/// Bounded queue capacity between the proxy request path and the
/// notification worker. A full queue drops the newest event rather than
/// blocking the sender; see `NotificationSink::notify_waf_block`.
const QUEUE_CAPACITY: usize = 256;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PluginConfig;
    use std::fs;
    use tempfile::tempdir;

    fn manager_with_notify_sink_fixture(enabled: bool) -> Arc<PluginManager> {
        let root = tempdir().unwrap();
        let plugin = root.path().join("notify-sink-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/notify_sink_v2/plugin.toml"),
        )
        .unwrap();
        let module = wat::parse_str(include_str!(
            "../tests/fixtures/plugins/notify_sink_v2/notify_sink_v2.wat"
        ))
        .unwrap();
        fs::write(plugin.join("notify_sink_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();
        if !enabled {
            manager.set_enabled("notify-sink-v2", false).unwrap();
        }
        manager
    }

    fn sample_event() -> bearust_plugin_sdk::WafBlockEvent {
        bearust_plugin_sdk::WafBlockEvent {
            request_id: "req-1".into(),
            occurred_at_ms: 1_700_000_000_000,
            category: "sqli".into(),
            score: 42,
            severity: "high".into(),
            reason_ids: "sqli".into(),
        }
    }

    #[test]
    fn deliver_invokes_the_registered_sink_and_records_success() {
        let manager = manager_with_notify_sink_fixture(true);
        let metrics = manager.metrics();
        NotificationSink::deliver(&manager, &metrics, &sample_event());
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_invocations_total 1"));
        assert!(output.contains("bearust_plugins_notify_failures_total 0"));
    }

    #[test]
    fn deliver_is_a_no_op_when_no_sink_is_registered() {
        let manager = PluginManager::new(PluginConfig::default());
        let metrics = manager.metrics();
        NotificationSink::deliver(&manager, &metrics, &sample_event());
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_invocations_total 0"));
        assert!(output.contains("bearust_plugins_notify_failures_total 0"));
    }

    #[test]
    fn deliver_counts_a_disabled_sink_as_no_sink_registered() {
        let manager = manager_with_notify_sink_fixture(false);
        let metrics = manager.metrics();
        NotificationSink::deliver(&manager, &metrics, &sample_event());
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_invocations_total 0"));
    }

    #[test]
    fn deliver_counts_a_nonzero_plugin_status_as_a_failure_not_a_host_error() {
        let root = tempdir().unwrap();
        let plugin = root.path().join("notify-sink-v2");
        fs::create_dir_all(&plugin).unwrap();
        fs::write(
            plugin.join("plugin.toml"),
            include_str!("../tests/fixtures/plugins/notify_sink_v2/plugin.toml"),
        )
        .unwrap();
        // Same shape as the checked-in fixture, but always reports failure.
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
            (func (export "bearust_notify_waf_block") (param i32 i32) (result i32) i32.const 1))"#;
        let module = wat::parse_str(wat).unwrap();
        fs::write(plugin.join("notify_sink_v2.wasm"), &module).unwrap();

        let manager = PluginManager::new(PluginConfig {
            enabled: true,
            directory: root.path().to_path_buf(),
            ..PluginConfig::default()
        });
        manager.reload_from_disk().unwrap();
        let metrics = manager.metrics();
        NotificationSink::deliver(&manager, &metrics, &sample_event());
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_invocations_total 0"));
        assert!(output.contains("bearust_plugins_notify_failures_total 1"));
    }

    #[test]
    fn notify_waf_block_drops_the_event_and_counts_it_when_the_queue_is_full() {
        let (sender, _receiver) = mpsc::channel(1);
        let metrics = Arc::new(PluginMetrics::default());
        let sink = NotificationSink {
            sender,
            metrics: Arc::clone(&metrics),
        };
        sink.notify_waf_block(sample_event());
        sink.notify_waf_block(sample_event());
        let output = metrics.render_prometheus();
        assert!(output.contains("bearust_plugins_notify_dropped_total 1"));
    }
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cargo test --lib plugin_notify::`
Expected: FAIL to compile — `NotificationSink` has no fields or methods yet.

- [ ] **Step 3: Implement `NotificationSink`**

Above the `#[cfg(test)]` line in `src/plugin_notify.rs`, add:

```rust
/// Delivers WAF-block events to at most one registered `notify.waf_block`
/// plugin, off the proxy's request path. `notify_waf_block` never blocks
/// and never fails visibly to the caller: a full queue drops the event and
/// increments a metric instead.
pub struct NotificationSink {
    sender: mpsc::Sender<bearust_plugin_sdk::WafBlockEvent>,
    metrics: Arc<PluginMetrics>,
}

impl NotificationSink {
    /// Spawns the background worker and returns the handle the proxy holds
    /// for the process lifetime. The worker task owns the receiving half of
    /// the channel and outlives every individual request.
    pub fn spawn(manager: Arc<PluginManager>) -> Arc<Self> {
        let (sender, receiver) = mpsc::channel(QUEUE_CAPACITY);
        let metrics = manager.metrics();
        tokio::spawn(Self::run(manager, receiver, Arc::clone(&metrics)));
        Arc::new(Self { sender, metrics })
    }

    /// Enqueues `event` for delivery. Never blocks: if the queue is full,
    /// the event is dropped and `notify_queue_dropped_total` is
    /// incremented.
    pub fn notify_waf_block(&self, event: bearust_plugin_sdk::WafBlockEvent) {
        if self.sender.try_send(event).is_err() {
            self.metrics.record_notify_dropped();
        }
    }

    async fn run(
        manager: Arc<PluginManager>,
        mut receiver: mpsc::Receiver<bearust_plugin_sdk::WafBlockEvent>,
        metrics: Arc<PluginMetrics>,
    ) {
        while let Some(event) = receiver.recv().await {
            Self::deliver(&manager, &metrics, &event);
        }
    }

    /// Delivers one event to the currently registered sink plugin, if any.
    /// No sink registered is not an error: the event is simply discarded.
    /// A plugin-side failure (trap, timeout, fuel exhaustion, malformed
    /// export, or a nonzero self-reported status) is counted and never
    /// retried or propagated.
    fn deliver(
        manager: &PluginManager,
        metrics: &PluginMetrics,
        event: &bearust_plugin_sdk::WafBlockEvent,
    ) {
        let Some(plugin) = manager.waf_block_sink_plugin() else {
            return;
        };
        match plugin.notify_waf_block(event) {
            Ok(0) => metrics.record_notify_invocation(),
            Ok(_) => metrics.record_notify_failure(),
            Err(_) => metrics.record_notify_failure(),
        }
    }
}
```

- [ ] **Step 4: Register the module**

In `src/lib.rs`, insert `pub mod plugin_notify;` before `pub mod plugin_runtime;` (alphabetical order: `plugin_notify` < `plugin_runtime`):

```rust
pub mod plugin_notify;
pub mod plugin_runtime;
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test --lib plugin_notify::`
Expected: PASS, all five tests green.

- [ ] **Step 6: Run the full lib+workspace test suite to check for regressions**

Run: `cargo test --workspace --locked`
Expected: PASS, no regressions in any other module.

- [ ] **Step 7: Commit**

```bash
git add src/plugin_notify.rs src/lib.rs
git commit -m "feat: add NotificationSink background worker for the notify.waf_block hook"
```

---

### Task 5: Wire the sink into the proxy request path and process startup

**Files:**
- Modify: `src/proxy.rs`
- Modify: `src/cli.rs`

**Interfaces:**
- Consumes: `crate::plugin_notify::NotificationSink` (Task 4).
- Produces: `BeaRustProxy::plugin_notify: Option<Arc<NotificationSink>>`, `BeaRustProxy::with_plugin_notify_sink(self, sink: Arc<NotificationSink>) -> Self` — used by `src/cli.rs`.

- [ ] **Step 1: Write the failing test**

Add this test to the `#[cfg(test)] mod tests` block at the bottom of `src/proxy.rs` (it already imports `use super::{error_status, invoke_analytics_changed};` — extend that import line):

```rust
    use super::{error_status, invoke_analytics_changed, waf_block_event};
```

Add the test itself, after `analytics_change_notifier_is_invoked`:

```rust
    #[test]
    fn waf_block_event_is_built_only_for_block_decisions() {
        let details = crate::waf::RedactedTelemetry {
            category: "sqli".into(),
            score: 42,
            severity: "high".into(),
            reason_ids: "sqli".into(),
        };
        assert!(waf_block_event("req-1", crate::waf::WafDecision::Allow, &details).is_none());
        assert!(waf_block_event("req-1", crate::waf::WafDecision::Log, &details).is_none());
        let event = waf_block_event("req-1", crate::waf::WafDecision::Block, &details).unwrap();
        assert_eq!(event.request_id, "req-1");
        assert_eq!(event.category, "sqli");
        assert_eq!(event.score, 42);
        assert_eq!(event.severity, "high");
        assert_eq!(event.reason_ids, "sqli");
    }
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cargo test --lib proxy::tests::waf_block_event_is_built_only_for_block_decisions`
Expected: FAIL to compile — `waf_block_event` is not defined yet.

- [ ] **Step 3: Add the `plugin_notify` field and builder to `BeaRustProxy`**

In `src/proxy.rs`, add a field to the `BeaRustProxy` struct, right after `anomaly`:

```rust
    pub anomaly: Option<Arc<crate::anomaly::AnomalyDetector>>,
    pub plugin_notify: Option<Arc<crate::plugin_notify::NotificationSink>>,
```

In `BeaRustProxy::new`, add the matching initializer, right after `anomaly: None,`:

```rust
            anomaly: None,
            plugin_notify: None,
```

Add a builder method, right after `with_anomaly`:

```rust
    pub fn with_plugin_notify_sink(
        mut self,
        sink: Arc<crate::plugin_notify::NotificationSink>,
    ) -> Self {
        self.plugin_notify = Some(sink);
        self
    }
```

- [ ] **Step 4: Extract `waf_block_event` and rewire `emit_waf_telemetry`**

Replace the existing `emit_waf_telemetry` function:

```rust
fn emit_waf_telemetry(request_id: &str, waf: &WafStore, evaluation: &Evaluation) {
    if evaluation.semantic_score == 0 && evaluation.matched_rule_ids.is_empty() {
        return;
    }
    let details = crate::waf::redacted_telemetry(evaluation);
    tracing::info!(
        event = "waf_detection",
        request_id,
        category = %details.category,
        score = details.score,
        severity = %details.severity,
        reason_ids = %details.reason_ids,
        decision = ?evaluation.decision,
    );
    waf.record_detection(evaluation);
}
```

with:

```rust
/// Builds the notification-sink event for a WAF decision, or `None` if the
/// decision was not a block. Pure and side-effect free so it can be tested
/// without a running plugin or channel.
fn waf_block_event(
    request_id: &str,
    decision: WafDecision,
    details: &crate::waf::RedactedTelemetry,
) -> Option<bearust_plugin_sdk::WafBlockEvent> {
    if decision != WafDecision::Block {
        return None;
    }
    Some(bearust_plugin_sdk::WafBlockEvent {
        request_id: request_id.to_owned(),
        occurred_at_ms: chrono::Utc::now().timestamp_millis().max(0) as u64,
        category: details.category.clone(),
        score: details.score,
        severity: details.severity.clone(),
        reason_ids: details.reason_ids.clone(),
    })
}

fn emit_waf_telemetry(
    request_id: &str,
    waf: &WafStore,
    evaluation: &Evaluation,
    notify: Option<&crate::plugin_notify::NotificationSink>,
) {
    if evaluation.semantic_score == 0 && evaluation.matched_rule_ids.is_empty() {
        return;
    }
    let details = crate::waf::redacted_telemetry(evaluation);
    tracing::info!(
        event = "waf_detection",
        request_id,
        category = %details.category,
        score = details.score,
        severity = %details.severity,
        reason_ids = %details.reason_ids,
        decision = ?evaluation.decision,
    );
    waf.record_detection(evaluation);
    if let Some(event) = waf_block_event(request_id, evaluation.decision, &details) {
        if let Some(notify) = notify {
            notify.notify_waf_block(event);
        }
    }
}
```

- [ ] **Step 5: Update the three call sites**

In `request_filter`, replace:

```rust
            if !ctx.waf_body_expected && !ctx.waf_telemetry_emitted {
                emit_waf_telemetry(&ctx.request_id, waf, &evaluation);
                ctx.waf_telemetry_emitted =
                    evaluation.semantic_score > 0 || !evaluation.matched_rule_ids.is_empty();
            }
```

with:

```rust
            if !ctx.waf_body_expected && !ctx.waf_telemetry_emitted {
                emit_waf_telemetry(
                    &ctx.request_id,
                    waf,
                    &evaluation,
                    self.plugin_notify.as_deref(),
                );
                ctx.waf_telemetry_emitted =
                    evaluation.semantic_score > 0 || !evaluation.matched_rule_ids.is_empty();
            }
```

In `request_body_filter`, replace the first occurrence:

```rust
            if ctx.waf_blocked {
                emit_waf_telemetry(&ctx.request_id, waf, &evaluation);
                *body = None;
```

with:

```rust
            if ctx.waf_blocked {
                emit_waf_telemetry(
                    &ctx.request_id,
                    waf,
                    &evaluation,
                    self.plugin_notify.as_deref(),
                );
                *body = None;
```

And the second occurrence in the same function:

```rust
            if end_of_stream
                && (evaluation.semantic_score > 0 || !evaluation.matched_rule_ids.is_empty())
            {
                emit_waf_telemetry(&ctx.request_id, waf, &evaluation);
            }
```

with:

```rust
            if end_of_stream
                && (evaluation.semantic_score > 0 || !evaluation.matched_rule_ids.is_empty())
            {
                emit_waf_telemetry(
                    &ctx.request_id,
                    waf,
                    &evaluation,
                    self.plugin_notify.as_deref(),
                );
            }
```

- [ ] **Step 6: Run test to verify it passes**

Run: `cargo test --lib proxy::`
Expected: PASS, all `proxy` module tests green.

- [ ] **Step 7: Wire the sink into `src/cli.rs`**

In `src/cli.rs`, add this line right after the plugin reload block (right after the closing `}` of `if config.plugins.enabled { ... }`, before `control_state.ai_advisor = ...`):

```rust
        let plugin_notify_sink =
            crate::plugin_notify::NotificationSink::spawn(control_state.plugin_manager.clone());
```

Then add `.with_plugin_notify_sink(plugin_notify_sink)` to the `BeaRustProxy` builder chain, right after `.with_anomaly(control_state.anomaly.clone())`:

```rust
            crate::proxy::BeaRustProxy::new(store.clone()).with_waf_store(waf_store).with_bot_store(bot_store, challenge_service)
                .with_analytics(analytics)
                .with_analytics_changed_notifier(Arc::new(move || { realtime.publish("analytics.changed"); }))
                .with_analytics_host_ids(analytics_host_ids)
                .with_baseline(control_state.baseline.clone())
                .with_anomaly(control_state.anomaly.clone())
                .with_plugin_notify_sink(plugin_notify_sink)
                .with_rate_limiter(rate_limiter)
                .with_rate_limit_policy(rate_policy)
                .with_trusted_proxies(trusted_proxies),
```

- [ ] **Step 8: Run the full workspace build and test suite**

Run: `cargo build --workspace && cargo test --workspace --locked`
Expected: PASS — the binary builds with the sink wired in, and no test anywhere regresses.

- [ ] **Step 9: Commit**

```bash
git add src/proxy.rs src/cli.rs
git commit -m "feat: deliver WAF-block events to the plugin notification sink from the proxy"
```

---

### Task 6: Documentation and acceptance gate

**Files:**
- Modify: `docs/PRD.md`

**Interfaces:**
- Consumes: none.
- Produces: none (documentation only).

- [ ] **Step 1: Update the Phase 13 roadmap status**

In `docs/PRD.md`, find the `### Phase 13B status: plugin SDK and memory conventions` section (added by the previous phase) and the two closing paragraphs starting with "Phase 13C is next: ...". Replace those two paragraphs:

```markdown
Phase 13C is next: explicitly reviewed traffic hooks, one at a time, using
this same memory convention, with per-hook redaction, backpressure, and
fail-open/fail-closed semantics. Phase 14 remains deferred for registry
distribution and signature verification.
```

with a new `### Phase 13C status` section:

```markdown
Phase 14 remains deferred for registry distribution and signature
verification.

### Phase 13C status: WAF-block notification sink

Phase 13C is complete. It adds the plugin system's first traffic hook: a
notification sink that receives a structured JSON event
(`{"request_id", "occurred_at_ms", "category", "score", "severity",
"reason_ids"}`, mirroring `src/waf.rs::redacted_telemetry`'s existing
tracing/audit fields) every time the WAF blocks a request. A plugin opts in
by declaring `abi_version: 2` and `capabilities = ["notify.waf_block"]` and
exporting `bearust_notify_waf_block(ptr, len) -> i32` using the same
alloc/write/call/dealloc memory convention Phase 13B introduced for the
health check. At most one enabled plugin is ever treated as the active sink
(the lowest plugin ID declaring the capability); every other plugin is
unaffected.

The hook is purely observational and cannot influence the request/response
that triggered it. The proxy enqueues each event with a non-blocking
`try_send` into a bounded (256-entry) channel and returns immediately; a
background worker task invokes the sink plugin off the request's call
stack. A full queue drops the newest event; a trapping, timed-out,
fuel-exhausted, or otherwise failing invocation is counted and never
retried. Three new Prometheus counters
(`bearust_plugins_notify_invocations_total`,
`bearust_plugins_notify_failures_total`,
`bearust_plugins_notify_dropped_total`) surface this on the existing plugin
metrics endpoint. No new host import, capability, or resource-limit bypass
was added; every guest-controlled pointer/length is bounds-checked
identically to the Phase 13B health-check path.

Phase 13D is next: a custom WAF detector hook, where a plugin's verdict can
influence traffic (a higher blast radius than a sink, since its output can
block requests), followed by request/response transform and custom
load-balancing hooks — each reviewed individually and built on this same
memory convention.
```

- [ ] **Step 2: Run the full acceptance gate**

Run, in order:

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
```

Expected: all three PASS with no findings. If `cargo fmt` reports drift, run `cargo fmt --all` and re-check. If `cargo clippy` reports a warning, fix it in the relevant file from Tasks 1-5 before proceeding — do not suppress it with an `#[allow]` unless the plan's other steps already justify one.

- [ ] **Step 3: Commit**

```bash
git add docs/PRD.md
git commit -m "docs: mark phase 13c notification sink complete"
```
