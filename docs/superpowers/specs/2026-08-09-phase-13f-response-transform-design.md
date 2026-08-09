# Phase 13F: Response Transform Hook — Design Spec

Status: Approved for implementation planning.

## Goals

- Add the plugin system's first response-mutating hook: a plugin can
  rewrite the response's headers and body before they are sent to the
  downstream client.
- Reuse the existing ABI, memory, selection, and fail-open conventions from
  Phase 13B/13C/13D/13E so this phase is additive infrastructure, not a new
  pattern.
- Unlike Phase 13E (headers only), this phase covers both headers and the
  full response body, per explicit scope decision for this phase.

## Non-goals

- **No streaming/chunked transform.** The plugin only ever sees (and
  returns) the complete response body, never a partial chunk. Bodies larger
  than the buffering cap skip the plugin entirely rather than being
  partially transformed.
- **No compressed-body transform.** Responses with a non-identity
  `Content-Encoding` skip the plugin entirely — decompression/recompression
  is out of scope for this phase.
- **No status-code mutation.** The plugin receives the response status as
  context but cannot change it. Only headers and body are mutable.
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
  right before the response is sent to the client (after caching, if
  caching were ever enabled; BeaRust does not enable caching today).
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
   plugin enabled declaring `transform.response`, and is the response's
   `Content-Encoding` absent or `identity`? If all true, strip
   `Content-Length` from the response headers (final size is unknown until
   the plugin runs) and mark `ctx` to buffer the body. Otherwise, mark
   `ctx` for passthrough — nothing else in this hook touches the response.
2. `response_body_filter`, while buffering: append each chunk to a
   `ctx`-held buffer, suppressing emission (`*body = None`) until
   `end_of_stream`. If the buffer exceeds the 1 MiB cap before
   `end_of_stream`, abort: flush the accumulated buffer as the next
   emitted chunk and switch `ctx` to passthrough for all remaining chunks
   (no correctness issue — `Content-Length` was already stripped in step
   1, so the client falls back to chunked/close-delimited framing).
3. On `end_of_stream` within the cap: build a
   `TransformResponseRequest { status, headers, body: base64(buffer) }`
   and invoke the plugin via `block_in_place`.
4. On success, with output passing validation: decode the plugin's
   base64 body, apply its headers (wholesale replace, minus any
   `Content-Length`/`Transfer-Encoding` it returned — those are always
   host-controlled), set `Content-Length` to the actual decoded body's
   byte length, and emit that body as the final chunk.
5. On any failure (trap, fuel exhaustion, timeout, malformed/oversized
   output, base64 decode failure, `block_in_place` panic): discard the
   plugin's output, set `Content-Length` to the *original* buffered body's
   length, and emit the original buffered bytes unmodified as the final
   chunk. Every failure class increments a failure counter and logs a
   `tracing::warn!`.

This mirrors 13E's fail-open shape, with `Content-Length` correction added
since response bodies (unlike request headers) have no prior equivalent
in the plugin system, and unlike request headers a mismatched length is
independently a wire-level correctness bug, not just a policy concern.

## Components

### `crates/bearust-plugin-sdk/src/lib.rs`

```rust
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformResponseRequest {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String, // base64-encoded
}

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct TransformResponseResult {
    pub headers: Vec<(String, String)>,
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
  needs none) plus the existing 16 KiB header budget at ~1.5x escaping
  overhead (~24 KiB) plus structural overhead, rounded up for headroom.
  This floor sits far above the default `PluginPolicy::max_output_bytes`
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

### `src/proxy.rs`

- `BeaRustProxy`'s per-request `CTX` gains buffering state: a byte buffer
  accumulator and a mode flag (buffering vs. passthrough), plus the
  captured response status for the eventual `TransformResponseRequest`.
- New `response_filter` override: eligibility check (plugin present +
  enabled + `Content-Encoding` absent/identity), strips `Content-Length`
  and flips `ctx` to buffering mode when eligible.
- New `response_body_filter` override implementing the accumulate /
  overflow-abort / end-of-stream-transform flow described in Architecture,
  calling the plugin via `tokio::task::block_in_place`.
- `Content-Length` is always recomputed by the host from the actual
  emitted body's byte length on every path where buffering was attempted
  (success or fail-open) — never trusted from the plugin, never left stale
  from before transform.
- Any `Content-Length` or `Transfer-Encoding` key present in the plugin's
  returned headers is dropped before the wholesale header replacement is
  applied.

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
| Trap / fuel exhaustion / timeout | Fail open: original buffered body emitted unmodified with corrected `Content-Length`, `transform_response_failures` incremented, `tracing::warn!` logged |
| Malformed or oversized plugin output (headers or body) | Same as above |
| Plugin-returned body fails base64 decode | Same as above |
| `block_in_place` panic | Same as above |
| Plugin succeeds within all bounds | Plugin's headers (minus `Content-Length`/`Transfer-Encoding`) + body applied; `Content-Length` recomputed from actual emitted body length; `transform_response_applied` incremented |

## Security

- No new host import, capability escalation, or resource-limit bypass:
  same fuel/memory/timeout limits as every other capability. Every
  guest-controlled pointer/length is bounds-checked identically to the
  Phase 13B health-check path.
- `Content-Length` is never trusted from the plugin — the host always
  derives it from the actual bytes about to be emitted, closing off
  response-splitting/desync conditions a malicious or buggy plugin could
  otherwise create.
- `Transfer-Encoding` from the plugin is dropped for the same reason — the
  host, not the plugin, controls response framing.
- Compressed responses never reach the plugin, so it can neither
  misinterpret opaque compressed bytes as content nor be used to launder a
  compressed payload past any future response inspection.
- The 1 MiB buffering cap bounds per-request proxy memory from a single
  large upstream response; oversized responses fail open to unmodified
  passthrough rather than partially transforming or blocking.
- **Operational gate, stated explicitly**: `MIN_TRANSFORM_RESPONSE_INPUT_BYTES`
  (1.5 MiB) sits far above the default `PluginPolicy::max_output_bytes`
  ceiling (64 KiB). Enabling any `transform.response` plugin requires an
  operator to deliberately raise that deployment-wide ceiling in config —
  a conscious per-deployment opt-in to a materially larger per-request
  memory footprint, not a silent default change. Every other capability's
  default ceiling is unaffected, since each plugin's own
  `max_output_bytes` is independently validated against its declared
  capabilities.

## Testing / acceptance gate

- SDK: round-trip serialization tests for `TransformResponseRequest`/
  `TransformResponseResult`.
- `plugin_runtime.rs` fixture tests (new
  `tests/fixtures/plugins/transform_response_v2/` WAT fixture): capability
  requires `abi_version: 2`; missing export is an ABI mismatch; manifest
  validation enforces the `MIN_TRANSFORM_RESPONSE_INPUT_BYTES` floor;
  out-of-bounds alloc pointer traps on input write; malformed output
  traps; a fixture round-trips JSON body+headers;
  `transform_response_plugin()` selection (lowest ID among enabled
  declarers, `None` when no plugin declares the capability, `None` when
  the sole declarer is disabled).
- `proxy.rs` integration tests: passthrough when no transformer enabled;
  passthrough when `Content-Encoding` present; buffering + successful
  transform (headers and body both replaced, `Content-Length` matches the
  new body); overflow abort (body > 1 MiB streams through untouched, no
  plugin call); fail-open on plugin trap/timeout (original body emitted
  with corrected `Content-Length`, failure counter incremented);
  plugin-supplied `Content-Length`/`Transfer-Encoding` headers are dropped,
  not applied.
- Observability tests: 3 new counters render correctly on the metrics
  endpoint, mirroring `transform_metrics_render_as_counters`.
- Full workspace fmt/clippy/test acceptance gate, plus a `docs/PRD.md`
  "Phase 13F status" section, same shape as 13E's.

## Follow-up increments

- **Phase 13G** (tentative, per the original Phase 13 roadmap pointer):
  custom load-balancing hooks.
- **Streaming/chunked response transform** remains out of scope
  indefinitely unless a concrete need for it emerges — the 1 MiB
  full-buffer model covers BeaRust's typical API/JSON/HTML traffic per the
  PRD's stated scope.
