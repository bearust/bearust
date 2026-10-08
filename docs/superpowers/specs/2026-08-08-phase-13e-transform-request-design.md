# Phase 13E: Request Header Transform Hook — Design Spec

Status: Approved for implementation planning.

## Goals

- Add the plugin system's first request-mutating hook: a plugin can rewrite
  the outbound request's headers before they are sent upstream.
- Reuse the exact ABI, memory, selection, and fail-open conventions
  established in Phase 13B (SDK/memory), 13C (notification sink), and 13D
  (WAF detector), so this phase is additive infrastructure, not a new
  pattern.
- Keep the hook single-purpose: it can only change header key/value pairs
  sent upstream. It cannot block the request, change the route, or touch
  the request body.

## Non-goals

- **No response transform.** The proxy currently has no `response_filter`/
  `response_body_filter` hooks in `ProxyHttp` at all (confirmed by survey:
  zero matches for those hook names in `src/proxy.rs`). Adding response-side
  transform requires introducing new pingora hook points and is deliberately
  deferred to a later phase (tentatively 13F).
- **No body transform.** Only headers are in scope for this phase.
- **No blocking/verdict semantics.** Unlike `waf.detect`, this hook cannot
  reject a request. Blocking stays the WAF detector's job. A transform
  plugin that wants to reject traffic should be built as (or paired with) a
  `waf.detect` plugin instead.
- **No plugin chaining.** Exactly one active transform plugin, same
  lowest-ID-wins rule as `notify.waf_block` and `waf.detect`.
- **No new ABI version.** This is another `abi_version: 2` capability,
  reusing the same alloc/write/call/read/dealloc memory convention.
- **No override of Bearust's own required headers.** `Host`,
  `X-Forwarded-For`, and `X-Request-Id` are reasserted after the plugin
  runs, regardless of what the plugin returned for those keys.

## Architecture

The hook runs synchronously inside `upstream_request_filter`, the existing
stage where Bearust already builds the final outbound `RequestHeader` and
inserts `Host`/`X-Forwarded-For`/`X-Request-Id`. This stage runs after
`request_filter` (WAF header-stage evaluation, routing, rate limiting) and
after `upstream_peer` (backend selection), so the transform cannot affect
WAF decisions or routing choice — it only affects the literal bytes sent to
the chosen upstream.

Flow:

1. `upstream_request_filter` builds/has the current outbound header list.
2. If an enabled plugin declares `transform.request` (lowest plugin ID among
   enabled plugins declaring the capability is the sole active transformer),
   invoke it via `tokio::task::spawn_blocking`, passing a bounded
   `TransformRequest { method, path, query, headers }`.
3. On success (`Ok(Ok(TransformResponse { headers }))`), replace the
   `RequestHeader`'s header list wholesale with the plugin's returned list.
4. On any failure — no active plugin, trap, fuel exhaustion, timeout,
   malformed/oversized output, or `spawn_blocking` join failure — skip
   straight to step 5 with the original header list untouched. Every
   failure class increments `record_transform_failure()` and logs a
   `tracing::warn!`.
5. Reassert `Host`, `X-Forwarded-For`, `X-Request-Id` unconditionally (this
   is today's existing insertion logic, just now running last instead of
   first) so the transform — successful or not — can never break routing or
   spoof trace/forwarding headers.

This mirrors Phase 13D's `apply_waf_detector` shape almost exactly, with the
"merge into WAF decision" step replaced by "swap header list, then
reassert required headers."

## Components

### `crates/bearust-plugin-sdk/src/lib.rs`

```rust
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformResponse {
    pub headers: Vec<(String, String)>,
}
```

Guest export contract: `bearust_transform_request(ptr: i32, len: i32) -> i64`
— input is a packed pointer/length to a serialized `TransformRequest` in
guest linear memory (written by the host via the existing
`bearust_alloc`/write convention); output is a packed pointer/length to a
serialized `TransformResponse`, read and validated by the host, followed by
a `bearust_dealloc` call — identical shape to `bearust_waf_detect`.

Round-trip serialization tests for both types, following the existing
`WafDetectRequest`/`WafDetectVerdict` test pattern.

### `src/plugin_runtime.rs`

- `ALLOWED_CAPABILITIES` gains `"transform.request"` (4th entry).
- `CompiledPlugin` gains `has_transform_request: bool`, populated in
  `PluginEngine::compile`'s `abi_version: 2` arm alongside the existing
  `has_notify_waf_block`/`has_waf_detect` checks; validates the
  `bearust_transform_request(i32, i32) -> i64` export exists when
  `"transform.request"` is declared.
- `PluginManifest::validate`'s `abi_version != 2` rejection extends to cover
  `"transform.request"` alongside the other two data-carrying capabilities.
- New manifest-validation floor, `MIN_TRANSFORM_INPUT_BYTES`, computed the
  same way `MIN_WAF_DETECT_INPUT_BYTES` was: take the real bounded
  worst-case JSON size for both `TransformRequest` (bounded by
  `MAX_NORMALIZED_METADATA_BYTES`/`MAX_NORMALIZED_HEADERS`/
  `MAX_NORMALIZED_FIELD_BYTES`, no body) and `TransformResponse` (headers
  only, same bound), and pick the larger of the two plus headroom. This is
  a distinct constant from `MIN_WAF_DETECT_INPUT_BYTES` and
  `MIN_NOTIFY_INPUT_BYTES` — each hook keeps its own floor sized to its own
  worst case, not a shared minimum. Exact byte value computed and justified
  in the implementation plan once the bounding helper's real limits are
  finalized.
- New `CompiledPlugin::transform(&self, request: &TransformRequest) ->
  Result<TransformResponse, PluginError>` — mirrors `detect()`'s
  alloc/write/call/read/dealloc shape exactly, calling
  `bearust_transform_request` instead of `bearust_waf_detect`.
- New `PluginManager::transform_plugin(&self) -> Option<Arc<CompiledPlugin>>`
  — mirrors `waf_detector_plugin()`'s lowest-enabled-ID selection exactly.

### `src/proxy.rs`

- New bounding helper `transform_request(header: &RequestHeader, ...) ->
  bearust_plugin_sdk::TransformRequest`, reusing the same
  `bounded_metadata`/`MAX_NORMALIZED_HEADERS`/`MAX_NORMALIZED_METADATA_BYTES`
  machinery `waf_detect_request` already uses in this file — same budget,
  same char-boundary-safe truncation, headers capped at
  `MAX_NORMALIZED_HEADERS` count.
- New `async fn apply_transform_plugin(plugin_manager: Option<&Arc<PluginManager>>,
  header: &mut RequestHeader) -> ()` (or returns a bool "applied" flag for
  metrics/logging) — fails open identically to `apply_waf_detector`: `None`
  manager, `None` transform plugin, `Ok(Err(_))`, and `Err(_)` (join
  failure) all leave `header` untouched.
- Wired into `upstream_request_filter`, called before the existing
  Host/X-Forwarded-For/X-Request-Id insertion block; that insertion block
  now always runs last and unconditionally, regardless of whether a
  transform ran or what it returned.

### `src/observability.rs`

`PluginMetrics` gains `transform_invocations`, `transform_applied`,
`transform_failures: AtomicU64` fields, matching accessor methods
(`record_transform_invocation()`, `record_transform_applied()`,
`record_transform_failure()`), and three new `render_prometheus()` counter
blocks: `bearust_plugins_transform_invocations_total`,
`bearust_plugins_transform_applied_total`,
`bearust_plugins_transform_failures_total`. `transform_applied` increments
only on the success path (step 3 above), giving operators a signal
distinct from "invoked" (which also counts failed attempts).

## Data flow

`upstream_request_filter` already owns the final outbound `RequestHeader`
at the point it currently inserts Host/XFF/X-Request-Id — no new context
struct is needed; the transform reads directly off that struct via the new
bounding helper, exactly the way `waf_detect_request` reads off
`InspectionContext`.

## Error handling

All failure classes are fail-open: the plugin's contribution is dropped,
`record_transform_failure()` is incremented, a `tracing::warn!` is logged,
and the original header list proceeds untouched to the required-header
reassertion step.

| Failure | Handling |
|---|---|
| No plugin declares `transform.request`, or plugin disabled | Skip transform entirely; today's behavior unchanged |
| Trap / fuel exhaustion / timeout | Drop plugin output, count failure, warn |
| Malformed or undersized output buffer | Same as above |
| `spawn_blocking` join failure | Same as above |
| Plugin's returned headers exceed `MAX_NORMALIZED_HEADERS` count or `MAX_NORMALIZED_FIELD_BYTES` per-field bound | Treated as malformed output — the whole transform is rejected (not partially truncated), so a plugin can't silently have some of its intended headers dropped without warning |

`Host`, `X-Forwarded-For`, `X-Request-Id` are reasserted unconditionally
after this step, whether or not a transform ran or succeeded — a
misbehaving or malicious plugin cannot remove, blank, or spoof these three
keys.

## Security

- No new host import, capability escalation, or resource-limit bypass:
  reuses the same fuel/memory/timeout limits and the same
  `spawn_blocking`-off-async-runtime pattern as `waf.detect`.
- Every guest-controlled pointer/length is bounds-checked identically to
  the Phase 13B health-check path.
- The transform cannot influence WAF decisions or routing — it runs after
  both are finalized, and only replaces the header list on the
  already-selected upstream request.
- Reasserting Host/X-Forwarded-For/X-Request-Id after the plugin runs
  closes off the most likely misuse: a plugin (buggy or malicious)
  attempting to spoof forwarding/trace headers or break routing by mangling
  Host.
- Bounded input mirrors the rule engine's own normalization budget
  (`MAX_NORMALIZED_METADATA_BYTES`, `MAX_NORMALIZED_HEADERS`,
  `MAX_NORMALIZED_FIELD_BYTES`), so a transform plugin never receives more
  attacker-controlled data than the WAF's own evaluation path already
  bounds.

## Testing / acceptance gate

- SDK: round-trip serialization tests for `TransformRequest`/
  `TransformResponse`.
- `plugin_runtime.rs` fixture tests (new `tests/fixtures/plugins/
  transform_request_v2/` WAT fixture): capability requires `abi_version: 2`;
  missing export is an ABI mismatch at compile time; malformed detect
  output traps; manifest validation enforces the `MIN_TRANSFORM_INPUT_BYTES`
  floor; `transform_plugin()` selection (lowest ID among enabled
  declarers, `None` when no plugin declares the capability, `None` when the
  sole declarer is disabled).
- `proxy.rs` unit tests: fail-open when no plugin manager / no active
  transform plugin / plugin errors — headers proceed untouched; success
  path replaces the header list with the plugin's output; Host/
  X-Forwarded-For/X-Request-Id are always present and correct after
  `upstream_request_filter`, including when a fixture plugin deliberately
  tries to drop or spoof them; oversized/too-many input headers are bounded
  before being sent to the plugin.
- Full workspace fmt/clippy/test acceptance gate, same as prior phases.

## Follow-up increments

- **Phase 13F**: response transform hooks. Requires introducing
  `response_filter`/`response_body_filter` (or equivalent) hook points into
  `ProxyHttp`, which do not exist today — a materially larger change than
  this phase, deliberately scoped out here.
- **Phase 13G** (tentative, per the original Phase 13 roadmap pointer):
  custom load-balancing hooks.
