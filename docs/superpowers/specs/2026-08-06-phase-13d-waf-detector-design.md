# Phase 13D: Custom WAF Detector Plugin Hook — Design

## Goals

- Allow a WASM plugin to contribute an additional detection signal to the
  built-in WAF's rule-engine/semantic evaluation, with the power to escalate
  a request toward `Log` or `Block`.
- Reuse the plugin runtime, ABI, and manifest-capability conventions
  established in Phase 13A–13C (fuel/memory/timeout limits, JSON-over-linear-
  memory, `abi_version: 2`, allow-listed capability strings, lowest-ID-wins
  selection).
- Keep the blast radius of a buggy or malicious detector plugin bounded to
  false positives (over-blocking), never to a WAF bypass or a proxy outage.

## Non-goals

- No fan-out to multiple detector plugins per request (exactly one active
  detector, same selection rule as the Phase 13C notification sink).
- No ability for a plugin to *downgrade* a decision the built-in rule engine
  already made — a plugin cannot turn a rule-engine `Block` into `Allow`.
- No new ABI version. This hook is gated by a new capability string on the
  existing `abi_version: 2`.
- No changes to the notification-sink hook itself; a plugin-escalated block
  flows through the existing `emit_waf_telemetry`/notification-sink path
  unchanged.
- No async/fire-and-forget delivery — this hook is synchronous and must
  complete (or fail open) before the request's WAF decision is finalized.

## Proposed architecture

At both existing WAF evaluation call sites — header-stage (`request_filter`,
before the body is available) and body-stage (`request_body_filter`, once
the body is buffered) — after `waf::evaluate()` produces its `Evaluation`,
BeaRust checks whether an enabled plugin declares the `"waf.detect"`
capability. If so, it builds a `WafDetectRequest` from the same bounded
fields the rule engine itself inspected (method, path, query, headers,
body) and invokes the plugin's `bearust_waf_detect` export via
`tokio::task::spawn_blocking` (the same "keep blocking wasmtime work off
the shared async runtime" pattern used for the notification sink's delivery
worker and for `reload_from_disk_without_audit`).

On success, the plugin's `WafDetectVerdict` (`decision`, `category`,
`score`) is merged into the existing `Evaluation` via
`merge_plugin_verdict`, using the same most-severe-wins rule already applied
between rule matches and semantic scoring: `Block` beats `Log` beats
`Allow`, and only escalation is possible — a plugin verdict can never
override an `Evaluation` that is already `Block`. On any failure (WASM
trap, fuel exhaustion, ABI/output error, `spawn_blocking` join failure), the
request fails open: the plugin's contribution is dropped, a failure counter
increments, and the rule engine's own decision proceeds untouched.

Because the merged `Evaluation` is what feeds the existing block-response,
telemetry, and notification-sink logic, a plugin-triggered block is
indistinguishable in *handling* from a rule-engine block — same `403`
response, same `RedactedTelemetry`, same `WafBlockEvent` — but the plugin's
`category`/`score` are visible in that telemetry so it can be attributed in
logs and to the notification sink.

## Components

### `bearust-plugin-sdk`

Two new shared types, alongside the existing `WafBlockEvent`:

```rust
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum WafPluginDecision {
    Allow,
    Log,
    Block,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WafDetectRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WafDetectVerdict {
    pub decision: WafPluginDecision,
    pub category: String,
    pub score: u16,
}
```

Serde uses `snake_case` decision values (`"allow" | "log" | "block"`),
matching the lowercase convention already used elsewhere in the wire
contracts.

### `src/plugin_runtime.rs`

- `ALLOWED_CAPABILITIES` gains `"waf.detect"`.
- `PluginManifest::validate` extends the existing `abi_version != 2` capability
  check to also reject `"waf.detect"` on any non-`abi_version: 2` manifest,
  and extends the existing `max_output_bytes` floor check (added in Phase
  13C's fix wave) to also apply when `"waf.detect"` is declared — a detector
  verdict's worst-case JSON is smaller than `WafBlockEvent`'s, but reuses the
  *same* `MIN_NOTIFY_INPUT_BYTES` floor for simplicity rather than
  introducing a second constant.
- `CompiledPlugin` gains `has_waf_detect: bool`.
- `PluginEngine::compile`'s `abi_version: 2` arm, after its existing
  unconditional checks, validates guest export
  `bearust_waf_detect(ptr: i32, len: i32) -> i64` when `"waf.detect"` is
  declared (else `AbiMismatch`). The `i64` return is a packed
  pointer/length pair (via `bearust_plugin_sdk::pack`/`unpack`, the same
  convention `bearust_health_check_v2` uses) pointing at the verdict's JSON
  in guest memory, since — unlike the notify hook's plain status code — the
  detector must return structured data.
- New method `CompiledPlugin::detect(&self, request: &WafDetectRequest) ->
  Result<WafDetectVerdict, PluginError>`: fresh Store/Instance, fuel/epoch
  setup (mirrors `health_check`/`notify_waf_block`), writes the serialized
  request into guest memory, calls the export, unpacks the returned
  pointer/length, reads and deserializes the verdict, deallocates.
- New method `PluginManager::waf_detector_plugin(&self) ->
  Option<Arc<CompiledPlugin>>`: iterates `current.plugins` (a `BTreeMap`, so
  ascending plugin-ID order) and returns the first enabled plugin whose
  `CompiledPlugin::has_waf_detect` is true — identical shape to
  `waf_block_sink_plugin`.

### `src/waf.rs`

New pure function:

```rust
pub fn merge_plugin_verdict(mut evaluation: Evaluation, verdict: WafDetectVerdict) -> Evaluation {
    // most-severe-wins: Block > Log > Allow; only escalates, never downgrades
    // appends verdict.category into evaluation.categories (deduped)
    // adds verdict.score into evaluation.semantic_score (saturating)
}
```

Pure and side-effect free, so it is unit-testable without any plugin runtime
involvement — mirrors the existing `waf_block_event` extraction pattern from
Phase 13C.

### `src/proxy.rs`

Both `request_filter` and `request_body_filter`, immediately after their
existing `evaluate(&waf_snapshot, &context)` call, gain:

```rust
if let Some(detector) = self.waf.as_ref().and_then(|w| w.manager.waf_detector_plugin()) {
    let request = waf_detect_request(&context);
    let evaluation = match tokio::task::spawn_blocking(move || detector.detect(&request)).await {
        Ok(Ok(verdict)) => {
            metrics.record_waf_detect_invocation();
            if verdict.decision != WafPluginDecision::Allow {
                metrics.record_waf_detect_block(); // when it actually escalates
            }
            merge_plugin_verdict(evaluation, verdict)
        }
        _ => {
            metrics.record_waf_detect_failure();
            evaluation // fail open: unchanged
        }
    };
}
```

(Exact plumbing of `self.waf`'s manager handle and metrics registry to be
finalized in the implementation plan, following the existing `self.plugin_notify`
wiring pattern from Phase 13C.)

### `src/observability.rs`

Three new `PluginMetrics` counters, following the exact pattern of the
Phase 13C notify counters:

- `bearust_plugins_waf_detect_invocations_total`
- `bearust_plugins_waf_detect_block_total`
- `bearust_plugins_waf_detect_failures_total`

## Data flow

```
request_filter / request_body_filter
  -> waf::evaluate(snapshot, context)          [existing rule engine]
  -> PluginManager::waf_detector_plugin()       [lowest enabled ID, if any]
  -> waf_detect_request(&context)               [build bounded WafDetectRequest]
  -> spawn_blocking(|| CompiledPlugin::detect)  [off the async runtime]
  -> merge_plugin_verdict(evaluation, verdict)  [most-severe-wins, escalate only]
  -> existing block-response / telemetry / notification-sink logic [unchanged]
```

## Error handling

| Failure | Behavior |
|---|---|
| No detector plugin configured | Skip entirely, zero overhead (existing behavior). |
| Plugin trap / fuel exhaustion / timeout | Fail open — drop contribution, log, count. |
| ABI mismatch / malformed verdict JSON | Fail open — drop contribution, log, count. |
| `spawn_blocking` join error (panic) | Fail open — drop contribution, log, count. |
| Plugin returns `Block` | Merge; existing block-response path fires exactly as for a rule-engine block. |

All failure branches share the same fail-open behavior and the same
`bearust_plugins_waf_detect_failures_total` counter — there is deliberately
no partial-failure taxonomy, keeping this consistent with the Phase 13C
notify path's failure handling.

## Security

- **Bounded input**: `WafDetectRequest` reuses the exact fields and size
  caps already enforced on `InspectionContext` before normalization
  (`MAX_INSPECTION_BODY_BYTES`, header count/size limits) — a detector
  plugin never receives more attacker-controlled data than the built-in
  engine itself inspects.
- **Escalate-only**: a plugin verdict can raise severity but never lower an
  `Evaluation` that already reached `Block`. This bounds a malicious/buggy
  detector's blast radius to over-blocking (availability impact on
  legitimate traffic through this specific detector), never to a WAF
  bypass.
- **Fail-open by design**: a compromised, crashed, or resource-exhausted
  detector plugin degrades WAF coverage back to "rule engine only" rather
  than causing a proxy-wide outage — consistent with this being an
  *additive* signal, not a replacement for the rule engine.
- **Output-size floor**: `plugin.toml`'s `max_output_bytes` must meet the
  existing `MIN_NOTIFY_INPUT_BYTES` floor when `"waf.detect"` is declared,
  closing the same attacker-influenceable-truncation class of issue fixed
  for the notify path in Phase 13C's final review.

## Testing / acceptance gate

- `bearust-plugin-sdk`: round-trip test for `WafDetectRequest`/`WafDetectVerdict`
  (serialize → deserialize → equal), matching the existing `WafBlockEvent` test.
- `src/waf.rs`: unit tests for `merge_plugin_verdict` covering all nine
  `(existing decision) x (verdict decision)` combinations, confirming
  escalate-only behavior and category/score merging.
- `src/plugin_runtime.rs` / `tests/plugin_runtime.rs`: capability/ABI
  validation (rejects `"waf.detect"` on non-`abi_version: 2`), missing-export
  is `AbiMismatch`, out-of-bounds alloc pointer traps safely, a new WAT
  fixture (`waf_detect_v2`) round-trips a fixed verdict, `waf_detector_plugin`
  selection (lowest ID, excludes disabled plugins, `None` when no plugin
  declares the capability), output-size floor rejection.
- `src/proxy.rs` integration tests:
  1. A plugin `Block` verdict returns `403` on a request the rule engine
     alone would `Allow`.
  2. A plugin `Log`/`Allow` verdict cannot downgrade an existing
     rule-engine `Block` (request still returns `403`).
  3. A plugin trap/error leaves the rule-engine's own decision untouched
     (fail-open), and the request proceeds/blocks exactly as the rule
     engine alone would decide.
- Acceptance gate: `cargo fmt --all -- --check`, `cargo clippy --workspace
  --all-targets -- -D warnings`, `cargo test --workspace --locked`.

## Follow-up increments

Request/response transform hooks and custom load-balancing hooks remain the
next increments after this one, each to be brainstormed and reviewed
individually, per the existing plugin-hook roadmap in `docs/PRD.md`.
