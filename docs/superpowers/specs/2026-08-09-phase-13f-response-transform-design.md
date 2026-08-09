# Phase 13F: Response Body Transform Hook — Design Spec

Status: Approved for implementation planning.

## Goals

- Add the plugin system's first response-mutating hook: a plugin can
  rewrite the full response body before it is sent to the downstream
  client.
- Reuse the existing ABI, memory, selection, and fail-open conventions from
  Phase 13B/13C/13D/13E so this phase is additive infrastructure, not a new
  pattern.

## Non-goals

- **No header mutation.** Discovered during implementation planning: pingora
  sends the response `Header` task to the downstream client as soon as
  `response_filter` returns — confirmed in `pingora-proxy 0.8.1`'s
  `proxy_h1.rs` (the Header task is filtered and queued for the downstream
  write in its own batch, before body chunks have necessarily even arrived
  from upstream). By the time `response_body_filter`'s `end_of_stream` call
  knows the plugin's output, the headers are already on the wire. There is
  no hook in `ProxyHttp` to hold headers back until a body decision is
  made. Header mutation based on the plugin's output is therefore not
  buildable against this pingora version; this phase covers body-only
  transform. (The original design considered wholesale header replacement
  alongside the body — ruled out for this reason, not by preference.)
- **No streaming/chunked transform.** The plugin only ever sees (and
  returns) the complete response body, never a partial chunk. Bodies larger
  than the buffering cap skip the plugin entirely rather than being
  partially transformed.
- **No compressed-body transform.** Responses with a non-identity
  `Content-Encoding` skip the plugin entirely — decompression/recompression
  is out of scope for this phase.
- **No status-code mutation.** The plugin receives the response status as
  context only.
- **No blocking/verdict semantics.** Same as 13E — this cannot reject or
  replace-with-error a response. That stays the WAF's job.
- **No plugin chaining.** Exactly one active `transform.response` plugin,
  same lowest-ID-wins rule as every other capability.
- **No new ABI version.** Another `abi_version: 2` capability, same
  alloc/write/call/read/dealloc memory convention.

## Architecture

The hook spans two existing (currently unoverridden) `ProxyHttp` methods,
confirmed present in `pingora-proxy 0.8.1`'s trait definition (not newly
introduced — `BeaRustProxy` simply doesn't override them yet):

- `response_filter` (`async fn`) — runs once per response, header-only,
  before the response is sent to the client.
- `response_body_filter` (`fn`, **not** `async`) — runs once per body
  chunk, including a final call with `end_of_stream: true`.

Because `response_body_filter` is synchronous, the `spawn_blocking` +
`.await` pattern 13E used inside the async `upstream_request_filter` does
not apply here. The plugin call instead uses
`tokio::task::block_in_place`, which lets a synchronous call block the
current worker thread while Tokio migrates other queued tasks off it —
preserving the "don't stall the whole runtime" property `spawn_blocking`
gives the async hooks, without needing `async fn`. This assumes BeaRust's
Tokio runtime is multi-threaded; confirming that (and picking a fallback
offload strategy if not) is an implementation-plan verification step, not
a design change.

Flow:

1. `response_filter` checks eligibility: is `plugin_manager` present, is a
   plugin enabled declaring `transform.response`, is the response's
   `Content-Encoding` absent or `identity`, is the status non-informational
   (excluding `101 Switching Protocols`, whose upgraded WebSocket frames
   flow through the same body filter as `HttpTask::UpgradedBody` and must
   keep streaming) and neither `204` nor `304`, is the downstream method
   not `HEAD`, and is the `Content-Type` not `text/event-stream` (an SSE
   stream would otherwise stall until the 1 MiB cap)? If all true, set the
   response version to HTTP/1.1, strip `Content-Length`, and insert
   `Transfer-Encoding: chunked` explicitly. Doing this ourselves is
   required — pingora's auto-chunk step (`proxy_h1.rs:680-697`, which adds
   `Transfer-Encoding: chunked` when a response has neither
   `Content-Length` nor `Transfer-Encoding`) runs *before* it calls
   `self.inner.response_filter(...)`, so it sees the upstream
   `Content-Length` still present and declines. Stripping `Content-Length`
   alone would leave the response with neither framing header, which
   pingora-core treats as close-delimited, disabling downstream HTTP/1.1
   keep-alive on every transformed response. On an HTTP/2 downstream the
   inserted header is harmless: h2 strips `Transfer-Encoding` before
   writing headers. Chunked framing is what makes the eventual (possibly
   different) body length correct without reinstating any header later.
   Mark `ctx` to buffer the body. Otherwise, mark `ctx` for passthrough —
   nothing else in this hook touches the response.
2. `response_body_filter`, while buffering: append each chunk to a
   `ctx`-held buffer, suppressing emission (`*body = None`) until
   `end_of_stream`. If the buffer exceeds the 1 MiB cap before
   `end_of_stream`, abort: flush the accumulated buffer as the next
   emitted chunk and switch `ctx` to passthrough for all remaining chunks.
3. On `end_of_stream` within the cap: build a
   `TransformResponseRequest { status, body: base64(buffer) }` and invoke
   the plugin via `block_in_place`.
4. On success, with output passing validation: decode the plugin's base64
   body and emit it as the final chunk.
5. On any failure (trap, fuel exhaustion, timeout, malformed/oversized
   output, base64 decode failure, `block_in_place` panic): discard the
   plugin's output and emit the original buffered bytes unmodified as the
   final chunk. Every failure class increments a failure counter and logs
   a `tracing::warn!`.

This mirrors 13E's fail-open shape. Headers are never touched by this
hook in either the success or failure path — only `Content-Length`'s
one-time removal in step 1, which is unconditional on eligibility, not on
the transform's outcome.

## Components

### `crates/bearust-plugin-sdk/src/lib.rs`

```rust
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformResponseRequest {
    pub status: u16,
    pub body: String, // base64-encoded
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformResponseResult {
    pub body: String, // base64-encoded
}
```

Guest export contract: `bearust_transform_response(ptr: i32, len: i32) -> i64`
— same packed pointer/length convention as `bearust_transform_request` and
`bearust_waf_detect`. Base64 encode/decode happens host-side in
`src/proxy.rs` using the existing root-crate `base64` dependency; the SDK
crate stays dependency-light (serde/serde_json only), same as today —
guest authors decode/encode the `body` field themselves.

Round-trip serialization tests for both types, following the existing
`TransformRequest`/`TransformResponse` test pattern.

### `src/plugin_runtime.rs`

- `ALLOWED_CAPABILITIES` gains `"transform.response"` (5th entry).
- `CompiledPlugin` gains `has_transform_response: bool`, populated in
  `PluginEngine::compile`'s `abi_version: 2` arm; validates the
  `bearust_transform_response(i32, i32) -> i64` export exists when
  `"transform.response"` is declared.
- `PluginManifest::validate`'s `abi_version != 2` rejection extends to
  cover `"transform.response"`.
- New manifest-validation floor `MIN_TRANSFORM_RESPONSE_INPUT_BYTES =
  1_572_864` (1.5 MiB). Sized for the 1 MiB body cap at ~4/3 base64
  inflation (~1.33 MiB, no JSON-escaping overhead — base64's alphabet
  needs none) plus small JSON structural overhead (`{"status":...,
  "body":"..."}`), rounded up generously for headroom — with no headers
  field in either direction, the real worst case is comfortably under this
  floor. This floor sits far above the default `PluginPolicy::max_output_bytes`
  ceiling (64 KiB) shared by all capabilities — deploying any
  `transform.response` plugin requires an operator to deliberately raise
  that policy ceiling first (see Security). Deliberately its own constant,
  not shared with `MIN_TRANSFORM_INPUT_BYTES` (32 KiB, headers-only,
  request side) — the two capabilities have unrelated worst cases.
- New `CompiledPlugin::transform_response(&self, request:
  &TransformResponseRequest) -> Result<TransformResponseResult,
  PluginError>` — mirrors `transform()`'s alloc/write/call/read/dealloc
  shape exactly, calling `bearust_transform_response` instead of
  `bearust_transform_request`.
- New `PluginManager::transform_response_plugin(&self) ->
  Option<Arc<CompiledPlugin>>` — mirrors `transform_plugin()`'s
  lowest-enabled-ID selection exactly.

### `src/config/mod.rs`

`PluginConfig::validate()` currently hard-caps `plugins.max_output_bytes`
at `1024 * 1024` (1 MiB) — below `MIN_TRANSFORM_RESPONSE_INPUT_BYTES` (1.5
MiB), which would make `transform.response` impossible to enable under any
configuration. This ceiling is raised to `2 * 1024 * 1024` (2 MiB),
comfortable headroom above the new floor, with a doc comment explaining
why. No other capability's behavior changes — this only widens the range
an operator is permitted to configure.

### `src/proxy.rs`

- `BeaRustProxy`'s per-request `CTX` gains buffering state: a byte buffer
  accumulator, a buffering-mode flag, and the captured response status for
  the eventual `TransformResponseRequest`.
- New `response_filter` override: eligibility check (plugin present +
  enabled + `Content-Encoding` absent/identity + non-informational status
  that is neither `204` nor `304` + non-`HEAD` method + non-SSE
  `Content-Type`); when eligible it sets HTTP/1.1, strips `Content-Length`,
  inserts `Transfer-Encoding: chunked`, and flips `ctx` to buffering mode.
  Does not otherwise touch the response's headers.
- New `response_body_filter` override implementing the accumulate /
  overflow-abort / end-of-stream-transform flow described in Architecture,
  calling the plugin via `tokio::task::block_in_place`. On both the
  success and fail-open paths, only the body chunk emitted at
  `end_of_stream` changes — no header mutation happens anywhere in this
  path.

### `src/observability.rs`

`PluginMetrics` gains `transform_response_invocations`,
`transform_response_applied`, `transform_response_failures: AtomicU64`
fields, matching accessor methods and three new `render_prometheus()`
counter blocks: `bearust_plugins_transform_response_invocations_total`,
`bearust_plugins_transform_response_applied_total`,
`bearust_plugins_transform_response_failures_total`. Kept distinct from
13E's request-side trio, consistent with every other capability having its
own counters.

## Data flow

`response_filter` and `response_body_filter` share state through
`BeaRustProxy`'s per-request `CTX` struct (already how WAF/routing state
flows between hooks in this codebase) — no new global or cross-request
state is introduced.

## Error handling

| Condition | Handling |
|---|---|
| No `plugin_manager`, or no plugin enabled with `transform.response` | Passthrough; no buffering, no metrics touched |
| `Content-Encoding` present and not `identity` | Passthrough; no buffering, no metrics touched |
| Buffered body exceeds 1 MiB before `end_of_stream` | Abort buffering, flush partial buffer, passthrough remainder unmodified; no plugin invocation, no metrics touched |
| Trap / fuel exhaustion / timeout | Fail open: original buffered body emitted unmodified, `transform_response_failures` incremented, `tracing::warn!` logged |
| Malformed or oversized plugin output body | Same as above |
| Plugin-returned body fails base64 decode | Same as above |
| `block_in_place` panic | Same as above |
| Plugin succeeds within all bounds | Plugin's body applied as the final chunk; `transform_response_applied` incremented |

## Security

- No new host import, capability escalation, or resource-limit bypass:
  same fuel/memory/timeout limits as every other capability. Every
  guest-controlled pointer/length is bounds-checked identically to the
  Phase 13B health-check path.
- The plugin never receives or returns headers, so there is no header
  injection/spoofing surface for this capability at all — the strongest
  possible mitigation, achieved by scope rather than by filtering.
- `Content-Length` is stripped and `Transfer-Encoding: chunked` inserted
  once, unconditionally on eligibility (not on outcome) — pingora's own
  auto-chunk step has already run by the time this hook is called, so the
  framing must be set explicitly here. The host doesn't need to (and
  structurally cannot) reconstruct `Content-Length` after the fact.
- Compressed responses never reach the plugin, so it can neither
  misinterpret opaque compressed bytes as content nor be used to launder a
  compressed payload past any future response inspection.
- The 1 MiB buffering cap bounds per-request proxy memory from a single
  large upstream response; oversized responses fail open to unmodified
  passthrough rather than partially transforming or blocking.
- **Operational gate, stated explicitly**: `MIN_TRANSFORM_RESPONSE_INPUT_BYTES`
  (1.5 MiB) sits far above the default `PluginPolicy::max_output_bytes`
  ceiling (64 KiB), and above the *pre-13F* hard config ceiling too (see
  Components: `src/config/mod.rs`, raised from 1 MiB to 2 MiB by this
  phase). Enabling any `transform.response` plugin requires an operator to
  deliberately raise `plugins.max_output_bytes` in config — a conscious
  per-deployment opt-in to a materially larger per-request memory
  footprint, not a silent default change. Every other capability's default
  ceiling is unaffected, since each plugin's own `max_output_bytes` is
  independently validated against its declared capabilities.

## Testing / acceptance gate

- SDK: round-trip serialization tests for `TransformResponseRequest`/
  `TransformResponseResult`.
- `plugin_runtime.rs` fixture tests (new
  `tests/fixtures/plugins/transform_response_v2/` WAT fixture): capability
  requires `abi_version: 2`; missing export is an ABI mismatch; manifest
  validation enforces the `MIN_TRANSFORM_RESPONSE_INPUT_BYTES` floor;
  out-of-bounds alloc pointer traps on input write; malformed output
  traps; a fixture round-trips a JSON body; `transform_response_plugin()`
  selection (lowest ID among enabled declarers, `None` when no plugin
  declares the capability, `None` when the sole declarer is disabled).
- `proxy.rs` integration tests: passthrough when no transformer enabled;
  passthrough when `Content-Encoding` present; buffering + successful
  transform (body replaced, headers untouched, `Content-Length` absent in
  favor of chunked framing); overflow abort (body > 1 MiB streams through
  untouched, no plugin call); fail-open on plugin trap/timeout (original
  body emitted, failure counter incremented).
- Observability tests: 3 new counters render correctly on the metrics
  endpoint, mirroring `transform_metrics_render_as_counters`.
- Full workspace fmt/clippy/test acceptance gate, plus a `docs/PRD.md`
  "Phase 13F status" section, same shape as 13E's.

## Follow-up increments

- **Response header transform** remains open. It would need a different
  mechanism than this phase's body hook — e.g. a plugin that only ever
  sees pre-body response headers (mirroring 13E's timing exactly, no body
  awareness) — and is deferred rather than attempted here.
- **Phase 13G** (tentative, per the original Phase 13 roadmap pointer):
  custom load-balancing hooks.
- **Streaming/chunked response transform** remains out of scope
  indefinitely unless a concrete need for it emerges — the 1 MiB
  full-buffer model covers BeaRust's typical API/JSON/HTML traffic per the
  PRD's stated scope.
