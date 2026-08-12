# Phase 13G: Custom Load-Balancing Hook — Design Spec

Status: Approved for implementation planning.

## Goals

- Add the plugin system's first backend-selection hook: a plugin can pick
  which upstream backend serves a request, for pools that opt in.
- Reuse the existing ABI, memory, selection, and fail-open conventions from
  Phase 13B–13F so this phase is additive infrastructure, not a new
  pattern.
- Keep this strictly opt-in per pool, with a deterministic fallback that
  makes a misbehaving plugin degrade to safe routing, never to no routing
  at all.

## Non-goals

- **No per-pool plugin assignment.** One active `balance.select` plugin
  (lowest enabled plugin ID, same rule as every other capability) serves
  every pool configured with `algorithm: plugin`. The request payload
  includes the pool's name so a single plugin can branch its logic per
  pool if it manages several; assigning different plugins to different
  pools is deferred.
- **No custom health checking.** The plugin only sees the host's existing
  live health flag per backend (`BackendState::healthy`, already tracked
  by the existing health-check subsystem) — it cannot mark a backend
  healthy/unhealthy itself, and it cannot select a backend the host
  currently considers unhealthy.
- **No new backend discovery.** The plugin picks among the pool's already
  -configured backends by ID; it cannot introduce a new address.
- **No blocking/verdict semantics.** Unlike `waf.detect`, this cannot
  reject a request — it can only choose among the pool's existing healthy
  backends, or (on any failure) let the host's built-in algorithm choose.
- **No new ABI version.** Another `abi_version: 2` capability, same
  alloc/write/call/read/dealloc memory convention.

## Architecture

`Algorithm` (`src/config/mod.rs`) gains a third variant, `Plugin`, in
addition to the existing `RoundRobin`/`LeastConnections`. It's set
per-pool, exactly like the existing two — pools that don't set
`algorithm: plugin` are completely unaffected by anything in this phase.

The hook runs inside `upstream_peer`, which is already `async fn`, so it
reuses Phase 13E's `spawn_blocking` + `.await` pattern (unlike 13F's
`response_body_filter`, there's no synchronous-trait-method constraint
here — `block_in_place` is not needed).

Flow:

1. `upstream_peer` resolves the pool as it does today. If
   `pool.algorithm() == Algorithm::Plugin` and an enabled plugin currently
   declares `balance.select`, build a bounded `LoadBalanceRequest` from:
   - the pool's name and its current candidate list (`pool.candidates()`:
     each backend's id, address, live `healthy` flag, and current inflight
     count), capped at `MAX_BALANCE_CANDIDATES` (128) entries;
   - the downstream request's method/path/query/headers, bounded by the
     same `MAX_NORMALIZED_METADATA_BYTES`/`MAX_NORMALIZED_HEADERS`/
     `MAX_NORMALIZED_FIELD_BYTES` budget `waf_detect_request` and
     `transform_request` already use;
   - `ctx.excluded_backend` (set on a failover retry) as
     `excluded_backend_id`.
2. Invoke the plugin via `spawn_blocking`.
3. On success, validate the returned `backend_id` via
   `pool.select_specific(id, excluded)`: it must name a backend that is
   currently healthy and isn't `excluded_backend_id`. If valid, that lease
   is used directly.
4. On any failure — no plugin, disabled, trap, fuel exhaustion, timeout,
   malformed output, a `spawn_blocking` join failure, or a `backend_id`
   that's unhealthy/excluded/nonexistent — fall back to
   `pool.select(ctx.excluded_backend)`. `PoolState::select`'s existing
   match gains a `Algorithm::Plugin` arm that behaves identically to
   `RoundRobin`, so this fallback is "free": the same function that serves
   non-plugin pools also serves as the plugin path's deterministic
   fallback, with no duplicated selection logic.

Every failure class increments `record_balance_failure()` and logs a
`tracing::warn!`; a valid pick increments `record_balance_applied()`.

## Components

### `src/config/mod.rs`

```rust
pub enum Algorithm {
    RoundRobin,
    LeastConnections,
    Plugin,
}
```

### `src/balancer.rs`

- `PoolState::select`'s match gains `Algorithm::Plugin => { /* identical
  to RoundRobin's arm */ }`.
- New `pool.algorithm(&self) -> Algorithm` accessor (not exposed today).
- New `pool.candidates(&self) -> Vec<BackendCandidate>` — a snapshot of
  every backend's id/address/healthy/inflight, read-only, no side effect.
- New `pool.select_specific(self: &Arc<Self>, id: BackendId, excluded:
  Option<BackendId>) -> Option<BackendLease>` — `None` if `id` doesn't
  exist in the pool, is `excluded`, or its live `healthy` flag is false;
  otherwise increments inflight and returns a lease, mirroring `select`'s
  tail exactly.

### `crates/bearust-plugin-sdk/src/lib.rs`

```rust
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct BackendCandidate {
    pub id: u64,
    pub address: String,
    pub healthy: bool,
    pub inflight: u32,
}

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

#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct LoadBalanceResult {
    pub backend_id: u64,
}
```

Guest export contract: `bearust_balance_select(ptr: i32, len: i32) -> i64`
— same packed pointer/length convention as every other `abi_version: 2`
capability.

### `src/plugin_runtime.rs`

- `ALLOWED_CAPABILITIES` gains `"balance.select"` (6th entry).
- `CompiledPlugin` gains `has_balance_select: bool`, validated in
  `PluginEngine::compile`'s `abi_version: 2` arm exactly like the other
  four v2 capabilities.
- `PluginManifest::validate`'s `abi_version != 2` rejection extends to
  cover `"balance.select"`.
- New manifest-validation floor `MIN_BALANCE_INPUT_BYTES = 49_152`
  (48 KiB). Sized for the existing 16 KiB metadata budget at ~1.5x
  escaping overhead (~24 KiB) plus up to `MAX_BALANCE_CANDIDATES` (128)
  backend candidates at their JSON worst case (~96 bytes each, e.g.
  `{"id":18446744073709551615,"address":"255.255.255.255:65535",
  "healthy":false,"inflight":4294967295}` ≈ 24 KiB total) plus small
  structural overhead — roughly 49 KiB worst case, comfortably under the
  64 KiB default `PluginPolicy::max_output_bytes` ceiling (unlike Phase
  13F, this does not require raising that ceiling). Deliberately its own
  constant, not shared with any existing floor.
- New `CompiledPlugin::balance_select(&self, request:
  &LoadBalanceRequest) -> Result<LoadBalanceResult, PluginError>` —
  mirrors `detect()`/`transform()`'s alloc/write/call/read/dealloc shape
  exactly.
- New `PluginManager::balance_select_plugin(&self) -> Option<Arc<CompiledPlugin>>`
  — mirrors `transform_plugin()`'s lowest-enabled-ID selection exactly.

### `src/proxy.rs`

- `MAX_BALANCE_CANDIDATES: usize = 128` — caps the candidate list built
  from `pool.candidates()` before it's sent to the plugin.
- New `load_balance_request(pool: &Arc<PoolState>, session: &Session,
  excluded: Option<BackendId>) -> bearust_plugin_sdk::LoadBalanceRequest`
  — pure, builds the bounded request the same way `transform_request`
  builds its request from a `RequestHeader`.
- New `async fn apply_load_balancer_plugin(plugin_manager:
  Option<&Arc<PluginManager>>, pool: &Arc<PoolState>, session: &Session,
  excluded: Option<BackendId>) -> Option<BackendLease>` — fails open
  (returns `None`) on every error class described in Architecture step 4;
  the caller falls back to `pool.select(excluded)` when this returns
  `None`.
- `upstream_peer` (`_session` parameter becomes `session` — now read, not
  just passed through) calls `apply_load_balancer_plugin` first when
  `pool.algorithm() == Algorithm::Plugin`, falling back to
  `pool.select(excluded)` otherwise or on `None`.

### `src/observability.rs`

`PluginMetrics` gains `balance_invocations`, `balance_applied`,
`balance_failures: AtomicU64` fields, matching accessor methods and three
new `render_prometheus()` counter blocks: `bearust_plugins_balance_invocations_total`,
`bearust_plugins_balance_applied_total`,
`bearust_plugins_balance_failures_total`.

## Data flow

`upstream_peer` already owns `ctx.route`/`ctx.snapshot` (for the pool) and
`ctx.excluded_backend` (for retries); `session` supplies the request
metadata. No new `CTX` fields are needed.

## Error handling

| Condition | Handling |
|---|---|
| Pool's `algorithm` isn't `Plugin` | Unchanged: `pool.select()` runs directly, no plugin path touched at all |
| `Plugin` algorithm, no plugin manager, or no plugin enabled with `balance.select` | Fall back to `pool.select(excluded)`; no metrics touched |
| Trap / fuel exhaustion / timeout / malformed output / `spawn_blocking` join failure | Fall back to `pool.select(excluded)`, `record_balance_failure()`, `tracing::warn!` |
| Plugin returns a `backend_id` that's unhealthy, `excluded`, or doesn't exist in the pool | Same as above — treated as a failure, not partially honored |
| Plugin returns a valid, healthy, non-excluded `backend_id` | `pool.select_specific(id, excluded)` leases it, `record_balance_applied()` |

## Security

- No new host import, capability escalation, or resource-limit bypass:
  same fuel/memory/timeout limits as every other capability. Every
  guest-controlled pointer/length is bounds-checked identically to the
  Phase 13B health-check path.
- The plugin can only ever pick among backends the host already knows
  about and still gates on the host's own live health flag — it cannot
  invent an address, and it cannot route to a backend the host currently
  considers down.
- The failover-exclusion invariant (`excluded_backend_id`, set when a
  backend just failed a request) is enforced by the host in
  `select_specific`, not trusted from the plugin — a plugin cannot re-pick
  a backend that literally just failed on this request's retry.
- Every failure class degrades to `RoundRobin`, so a buggy or malicious
  balancer plugin can never wedge or blackhole a pool's traffic — only
  make a suboptimal (but still safe, still healthy) pick, exactly once per
  request.
- Bounded input mirrors the rule engine's own normalization budget for the
  request-metadata portion, and a fixed cap (`MAX_BALANCE_CANDIDATES`) for
  the backend-list portion — a balancer plugin never receives more
  attacker-controlled or operator-scale data than any other capability's
  worst case.

## Testing / acceptance gate

- SDK: round-trip tests for `LoadBalanceRequest`/`LoadBalanceResult`/
  `BackendCandidate`.
- `plugin_runtime.rs` fixture tests (new `tests/fixtures/plugins/
  balance_select_v2/` WAT fixture): capability requires `abi_version: 2`;
  missing export is an ABI mismatch; manifest validation enforces
  `MIN_BALANCE_INPUT_BYTES`; out-of-bounds alloc pointer traps; malformed
  output traps; a fixture round-trips a candidate list and returns a fixed
  `backend_id`; `balance_select_plugin()` selection (lowest ID, `None`
  when no plugin declares the capability, `None` when disabled).
- `balancer.rs` unit tests: `candidates()` reflects live health/inflight
  state accurately; `select_specific` rejects an unhealthy id, rejects the
  excluded id, rejects a nonexistent id, accepts a valid pick and
  increments inflight exactly like `select` does; `Algorithm::Plugin`'s
  `select()` fallback behaves identically to `RoundRobin` (same picks,
  same round-robin cursor advancement).
- `proxy.rs` unit tests: a valid plugin pick is honored and leases the
  right backend; falls back to `RoundRobin` on every failure class (no
  plugin/disabled/trap/timeout/malformed/invalid-pick); non-`Plugin` pools
  are completely untouched (no plugin invocation, no metrics) regardless
  of whether a `balance.select` plugin is enabled.
- Full workspace fmt/clippy/test acceptance gate, plus a `docs/PRD.md`
  "Phase 13G status" section.

## Follow-up increments

- Per-pool plugin assignment (letting different pools use different
  balancer plugins, rather than one global active plugin) is deferred —
  the `pool` field in the request payload is the seam a future phase could
  use to split this out without a wire-format change.
- Response header transform (deferred from Phase 13F) remains open and
  independent of this phase.
