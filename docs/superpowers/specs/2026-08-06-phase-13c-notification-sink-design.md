# Phase 13C — Notification Sink Hook Design

**Status:** Design approved; implementation plan pending

**Scope:** Phase 13C of the BeaRust roadmap. This increment adds the first
plugin traffic hook: a WAF-block notification sink. It builds directly on
Phase 13A's WASM plugin runtime and Phase 13B's `bearust-plugin-sdk` memory
convention. It does not add request/response mutation, WAF detection, or
load-balancing hooks — those remain later, higher-risk increments.

## Goals

FR-9.2 lists four target extension points for the plugin system: custom WAF
detector, request/response transform, custom load balancing algorithm, and
notification sink. Phase 13B's design doc named the notification sink as the
lowest-risk starting point because it cannot affect request/response
handling — it only observes, after the fact, that something happened.
Concretely, Phase 13C must:

- let a plugin receive a WAF-block event without being able to affect the
  request or response that triggered it;
- guarantee the proxy hot path never waits on, or is slowed by, plugin
  execution;
- guarantee a slow, stuck, or malicious sink plugin can only lose its own
  notifications (via a bounded queue), never degrade or block traffic;
- reuse Phase 13B's JSON-over-linear-memory convention and ABI-2 plumbing
  rather than introducing a new wire format; and
- expose only data already proven safe to leave the host: the same fields
  `src/waf.rs::redacted_telemetry` already produces for tracing/audit today.

## Non-goals

The following remain outside Phase 13C:

- request/response transform hooks (a later, higher-risk increment);
- a custom WAF detector hook (the plugin scoring/blocking traffic itself);
- a custom load-balancing hook;
- notifications for events other than WAF blocks (bot-detection blocks,
  rate-limit decisions, plugin health-check failures) — a narrower first
  slice keeps the event-schema and redaction surface reviewable in one pass;
- retry-on-failure for notification delivery — this phase is fire-and-forget
  by design;
- a new ABI version — the notification export is capability-gated within
  the existing `abi_version: 2` convention; and
- fan-out to multiple simultaneous sink plugins — exactly one sink plugin
  may be active at a time in this phase.

## Proposed architecture

### Event flow

1. `emit_waf_telemetry` (`src/proxy.rs`) already builds a
   `waf::RedactedTelemetry { category, score, severity, reason_ids }` for
   every WAF block and logs it via `tracing`. Phase 13C adds one step after
   the existing tracing call: build a `WafBlockEvent` (see below) from the
   same `RedactedTelemetry` plus `request_id` and the current timestamp, and
   `try_send` it into a bounded `tokio::sync::mpsc::channel` (capacity 256).
2. `try_send` never blocks. If the channel is full, the event is dropped and
   a counter is incremented; the request path is entirely unaffected either
   way.
3. A single background task, spawned once at proxy startup and running for
   the process lifetime, loops on `recv().await`. For each event, it checks
   whether a sink plugin is currently registered (see Registration below);
   if none is registered, the event is discarded silently (no sink
   configured is the default, not an error). If one is registered, the
   worker invokes it and records success/failure in metrics. There is no
   retry: exactly one invocation attempt per event.

### Wire convention

`WafBlockEvent` is a new shared type in `bearust-plugin-sdk`, defined once
and used by both host and guest exactly as `HealthCheckInput`/
`HealthCheckOutput` are today:

```rust
#[derive(Serialize, Deserialize)]
pub struct WafBlockEvent {
    pub request_id: String,
    pub occurred_at_ms: u64,
    pub category: String,
    pub score: u16,
    pub severity: String,
    pub reason_ids: String,
}
```

A plugin that wants to receive these events must declare, in its manifest:

```toml
abi_version = 2
capabilities = ["notify.waf_block"]
```

and export:

```rust
#[no_mangle]
pub extern "C" fn bearust_notify_waf_block(ptr: i32, len: i32) -> i32 {
    let _event: bearust_plugin_sdk::WafBlockEvent =
        bearust_plugin_sdk::read_input(ptr, len);
    // ... plugin does its own work (e.g. queue a webhook) ...
    0 // 0 = ok, nonzero = plugin-reported failure
}
```

This reuses Phase 13B's `bearust_alloc`/`bearust_dealloc`/packed-pointer
convention unchanged: `abi_version` stays a pure wire-format version, and
`capabilities` stays the sole feature-gating mechanism. A plugin can declare
both `abi_version: 2` and `notify.waf_block` without any coupling between
the two — a future hook adds a new capability + export pair, not a new ABI
version.

### Host-side plugin runtime changes (`src/plugin_runtime.rs`)

- `PluginEngine::compile`: when a manifest's `capabilities` contains
  `"notify.waf_block"`, additionally validate the
  `bearust_notify_waf_block(i32, i32) -> i32` export is present with the
  correct signature. Missing or mistyped is `PluginError::AbiMismatch`,
  fail-closed exactly like the existing v2 health-check export checks.
- `CompiledPlugin` gains `pub fn notify_waf_block(&self, event: &WafBlockEvent) -> Result<(), PluginError>`,
  implemented as the same alloc → write-input → call → dealloc sequence as
  `health_check`'s v2 path, minus reading a JSON output buffer (the `i32`
  return value is read directly, no guest memory read needed for it). Every
  guest-controlled pointer/length the host touches during this call is
  bounds-checked exactly as it is in the health-check path; all limits
  (fuel, memory, timeout, `max_output_bytes` for the input write) apply
  unchanged.
- A new `NotificationSink` type owns: the channel's `Sender`/`Receiver`
  pair, an `ArcSwap<Option<Arc<CompiledPlugin>>>` holding the currently
  registered sink plugin (updated by the same reload path that already
  hot-swaps other plugin state, satisfying FR-9.5 — no proxy restart to
  add, change, or remove a sink), and atomic counters for `sent`,
  `dropped`, `invoked_ok`, `invoked_failed`.
- The background worker task is spawned once when the sink is constructed
  and holds the `Receiver` for the process lifetime.

### Observability

`PluginMetrics` gains three counters, exposed the same way existing plugin
metrics are surfaced today (Prometheus endpoint / control-plane surface):

- `notify_queue_dropped_total` — events dropped because the channel was full;
- `notify_invocations_total` — successful plugin invocations (`i32` return `0`);
- `notify_failures_total` — invocations that trapped, timed out, exhausted
  fuel, returned malformed data, or returned a nonzero status.

No new audit-log or realtime-event surface is added in this phase — the
existing WAF-block tracing line is untouched; the sink is a second,
independent consumer of the same redacted data.

## Failure and security behavior

- The proxy request path never awaits plugin execution for this hook —
  `try_send` is synchronous and non-blocking; the worker task runs entirely
  off the request's call stack.
- A full queue drops the newest event and counts it; it never blocks the
  sender or the request.
- A trapping, timing-out, fuel-exhausted, or malformed-output plugin
  invocation is recorded as a failure and discarded — no retry, no crash,
  no effect on the request that generated the event (which has already
  completed by the time the worker processes it).
- The event payload is exactly the fields `redacted_telemetry` already
  produces for tracing/audit today, plus `request_id` and a timestamp — no
  raw headers, body, query string, or client IP ever reaches a plugin.
- No new host import, WASI capability, or resource-limit bypass is
  introduced. Fuel, memory, timeout, and `max_output_bytes` (bounding the
  input write) all apply to the notify invocation exactly as they do to the
  health check.
- `abi_version: 1` and `abi_version: 2` plugins without the
  `notify.waf_block` capability are entirely unaffected — they are never
  considered for the sink role and never receive events.

## Testing and acceptance gate

Tests must cover:

- a hand-written WAT fixture (`tests/fixtures/plugins/notify_sink_v2/`)
  exporting `bearust_notify_waf_block`, exercising the full
  alloc/write/call/dealloc round trip with real JSON;
- a manifest declaring `notify.waf_block` missing the required export →
  `AbiMismatch`;
- malformed or out-of-bounds return handling from the notify call, mirrored
  from the existing v2 health-check trap/memory-limit tests;
- a nonzero `i32` return counted as `notify_failures_total`, not surfaced as
  a host-side error;
- an integration test exercising `emit_waf_telemetry` → channel → worker →
  plugin end-to-end;
- a full-channel scenario proving events are dropped (not blocked) and
  `notify_queue_dropped_total` increments;
- a regression test proving WAF block/allow decisions are byte-for-byte
  unchanged by the presence or absence of a sink plugin — the hook is
  purely observational;
- `bearust-plugin-sdk` unit tests for the new `WafBlockEvent` type's
  encode/decode, run on the host target.

The Phase 13C gate is satisfied when:

1. a registered `notify.waf_block` plugin receives a structured JSON event
   for every WAF block, using the Phase 13B memory convention;
2. no plugin behavior (slow, stuck, trapping, or absent) can add latency to,
   or change the outcome of, the request that triggered the event;
3. a full notification queue drops events rather than blocking the proxy;
4. no guest-controlled pointer/length can cause an out-of-bounds host read,
   regardless of how malformed or adversarial the value is;
5. no new host import, capability, or resource-limit bypass is introduced;
6. `abi_version: 1` plugins and `abi_version: 2` plugins without the new
   capability are unaffected; and
7. Rust formatting, Clippy (`-D warnings`), the full test suite (via
   `cargo test --workspace --locked`), frontend build/tests/locale
   validation, and `git diff --check` all pass on the project's pinned
   stable toolchain.

## Follow-up increments

A later phase will add the custom WAF detector hook (plugin input feeds a
verdict alongside the built-in WAF — higher blast radius than a sink since
its output can block traffic), followed by request/response transform and
custom load-balancing hooks, each built on this same memory convention and
each getting its own capability string and reviewed export. Broadening the
notification sink to other event types (bot-detection blocks, rate-limit
decisions, plugin health-check failures) and to multiple simultaneous sink
plugins (fan-out) are both explicitly deferred past this phase.
