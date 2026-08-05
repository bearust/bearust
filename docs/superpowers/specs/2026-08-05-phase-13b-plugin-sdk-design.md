# Phase 13B — Plugin SDK & Memory Conventions Design

**Status:** Design approved; implementation plan pending review

**Scope:** Phase 13B of the BeaRust roadmap. This increment adds a public
`bearust-plugin-sdk` crate and a stable JSON-over-linear-memory convention for
passing structured data between the host and a plugin. It does not add any
traffic hooks, new capabilities, or host imports — the only host-facing
operation remains the health check, now able to carry structured JSON
instead of a bare integer.

## Goals

Phase 13B must let a Rust plugin author (and, by convention, authors in any
language that compiles to `wasm32-wasip1`) exchange structured data with the
host without hand-rolling pointer arithmetic, while preserving every Phase
13A security guarantee. Concretely:

- define a memory convention (allocation, input marshaling, output
  marshaling) that plain WASM modules can implement in any language;
- ship `bearust-plugin-sdk`, a Rust crate that implements the guest side of
  that convention with minimal boilerplate for plugin authors;
- extend the runtime to accept a second ABI version (`2`) that uses the new
  convention, while `abi_version: 1` plugins keep working exactly as today;
- prove the convention end-to-end by upgrading the health check to a
  structured JSON result on `abi_version: 2` plugins; and
- keep every read of guest-controlled pointers/lengths bounds-checked, and
  every existing resource limit (fuel, memory, timeout, output bytes)
  unchanged in what it bounds.

## Non-goals

The following remain outside Phase 13B:

- WAF, request/response, load-balancer, or notification hook execution
  (Phase 13C);
- any new plugin capability beyond `health_check`;
- any host import, WASI capability, filesystem, network, or clock access;
- the WebAssembly Component Model / WIT (the convention stays on plain
  modules, matching Phase 13A and the PRD's stated `wasm32-wasip1` target);
- a `wasm32-wasip1` CI build target — the SDK's guest-side exports are
  proven via a hand-written WAT fixture, matching Phase 13A's approach; and
- registry distribution, signatures, or trust-on-first-use (Phase 14).

## Proposed architecture

### Memory convention

`abi_version: 2` plugins must export, in addition to `bearust_abi_version`:

- `bearust_alloc(len: i32) -> i32` — returns a pointer to a `len`-byte guest
  buffer;
- `bearust_dealloc(ptr: i32, len: i32)` — releases a buffer previously
  returned by `bearust_alloc` or by a guest function's output;
- `bearust_health_check_v2(ptr: i32, len: i32) -> i64` — the new
  health-check entry point.

Host→guest input: the host calls `bearust_alloc(len)` to get a pointer, writes
the JSON-encoded input into guest memory at that pointer, then calls the
target function with `(ptr, len)`.

Guest→host output: the target function returns a single `i64` packing
`(ptr as i64) << 32 | (len as i64)`. The host reads `len` bytes from guest
memory at `ptr`, decodes JSON, then calls `bearust_dealloc(ptr, len)` to let
the guest free the buffer.

Every pointer/length pair the host receives from a guest — whether from
`bearust_alloc`'s return value or from a packed `i64` result — is validated
against the guest's actual memory size before any read. A pointer/length pair
that would read outside the guest's linear memory, or whose length exceeds
the plugin's configured `max_output_bytes`, is treated as `PluginError::Trap`
and the buffer is never dereferenced.

`abi_version: 1` plugins are entirely unaffected: they need none of
`bearust_alloc`/`bearust_dealloc`/`bearust_health_check_v2`, and the existing
`bearust_health_check() -> i32` path is unchanged.

### `bearust-plugin-sdk` crate

A new crate (published alongside the workspace, name `bearust-plugin-sdk`)
implements the guest side of the convention:

- depends only on `serde` + `serde_json` (no host-only dependencies leak into
  the guest target);
- exports `bearust_alloc`/`bearust_dealloc` implementations backed by a
  simple per-call allocation (plugins are short-lived per invocation, so a
  bump allocator or `Box::into_raw`/`Box::from_raw` pairing is sufficient —
  no long-lived heap management is required);
- provides `read_input<T: DeserializeOwned>(ptr: i32, len: i32) -> T` and
  `write_output<T: Serialize>(value: &T) -> i64` helpers that hide the JSON
  encode/decode and pointer-packing;
- provides an `abi_version!(2)` declarative macro that expands to the
  `bearust_abi_version() -> i32` export;
- defines the shared `HealthCheckInput { requested_at_ms: u64 }` and
  `HealthCheckOutput { healthy: bool, detail: Option<String> }` types, which
  `src/plugin_runtime.rs` also depends on, so host and guest share one
  definition instead of two structurally-identical ones that could drift.

A plugin author's entire `abi_version: 2` health check becomes:

```rust
bearust_plugin_sdk::abi_version!(2);

#[no_mangle]
pub extern "C" fn bearust_health_check_v2(ptr: i32, len: i32) -> i64 {
    let _input: bearust_plugin_sdk::HealthCheckInput =
        bearust_plugin_sdk::read_input(ptr, len);
    bearust_plugin_sdk::write_output(&bearust_plugin_sdk::HealthCheckOutput {
        healthy: true,
        detail: None,
    })
}
```

### Runtime changes

- `SUPPORTED_ABI_VERSION: u32 = 1` becomes a bounded set,
  `SUPPORTED_ABI_VERSIONS: RangeInclusive<u32> = 1..=2`; manifest and runtime
  checks reject any `abi_version` outside this range exactly as today's
  exact-match check rejected anything other than `1`.
- `CompiledPlugin` compilation validates, for `abi_version: 2`, that
  `bearust_alloc`, `bearust_dealloc`, and `bearust_health_check_v2` are all
  present with the expected typed signatures; any missing or mistyped export
  is `PluginError::AbiMismatch`, the same fail-closed outcome Phase 13A uses
  for its exports today.
- `CompiledPlugin::health_check()` branches on `abi_version`: the `1` path is
  byte-for-byte unchanged; the `2` path performs alloc → write input → call →
  bounds-check result → read output → dealloc → JSON-decode, mapping any
  failure at any step (trap, oversized claim, malformed JSON, out-of-bounds
  pointer) to an existing `PluginError` variant (`Trap` or `MemoryLimit`).
  Both paths still produce a `HealthResult`; the struct gains an optional,
  length-capped `detail: Option<String>` field populated only by `abi_version:
  2` plugins, so `control_plane/plugins.rs` and `PluginHealthResponse` need
  only a field addition, not a rewrite.

### Control plane and observability

- `PluginHealthResponse` gains the same bounded, optional `detail` field.
  No new endpoints and no new RBAC permission — `plugins.read`/
  `plugins.manage` already cover this surface.
- The existing health-check audit and realtime-event paths add `detail` to
  their allow-listed fields, capped at the same bound the runtime enforces
  (e.g. 4 KiB) — never the plugin's raw, uncapped output.
- Manifest `abi_version` validation in `src/config` widens from `== 1` to
  `∈ {1, 2}`.

## Failure and security behavior

- A pointer/length pair from a guest that would read outside that guest's own
  linear memory is never dereferenced; it produces `PluginError::Trap`.
- Guest allocation requests remain bounded by the plugin's existing
  `max_output_bytes`/`memory_pages` limits — this phase adds a *convention*,
  not a new resource, so no new unbounded-allocation vector is introduced.
- Malformed JSON output, oversized output, or malformed alloc/dealloc
  behavior all map to existing stable `PluginError` codes; no raw `wasmtime`
  trap message or backtrace reaches the API, audit log, or realtime event.
- No plugin gains any capability, host import, or WASI access beyond what
  Phase 13A already denies. `abi_version: 2` changes only how data crosses
  the boundary for the one operation that already exists (health check).
- `abi_version: 1` plugins already loaded or newly installed continue to
  work with zero behavior change.

## Testing and acceptance gate

Tests must cover:

- `abi_version: 1` regression — existing fixture and tests unchanged and
  still passing;
- `abi_version: 2` end-to-end health check via a hand-written WAT fixture
  (`tests/fixtures/plugins/health_ok_v2/`) exercising the full
  alloc/write/call/read/dealloc round trip with real JSON;
- malformed JSON output → `Trap`, not a panic or partial result;
- a guest-claimed pointer/length outside its own memory → `Trap`, not a host
  out-of-bounds read;
- oversized output (over `max_output_bytes`) → `MemoryLimit`;
- a v2 manifest missing any of `bearust_alloc`/`bearust_dealloc`/
  `bearust_health_check_v2` → `AbiMismatch`;
- `abi_version` outside `{1, 2}` (e.g. `0`, `3`) → rejected at manifest
  validation, same as today's out-of-range handling;
- `PluginHealthResponse`/audit/realtime redaction extended to cover the new
  `detail` field, still bounded and never raw;
- `bearust-plugin-sdk` unit tests for `read_input`/`write_output`/pointer
  packing, run on the host target (pure encode/decode logic; only the guest
  *exports* are WASM-specific, and those are covered by the WAT fixture).

The Phase 13B gate is satisfied when:

1. `abi_version: 1` plugins load, health-check, and behave exactly as before
   Phase 13B;
2. an `abi_version: 2` plugin can load and return a structured JSON health
   result through the new convention;
3. no guest-controlled pointer/length can cause an out-of-bounds host read,
   regardless of how malformed or adversarial the value is;
4. no new host import, capability, or resource-limit bypass is introduced;
5. `PluginHealthResponse`, audit, and realtime surfaces remain bounded and
   redacted with the new field included; and
6. Rust formatting, Clippy (`-D warnings`), the full test suite, frontend
   build/tests/locale validation, and `git diff --check` all pass on the
   project's pinned stable toolchain.

## Follow-up increments

Phase 13C will add explicitly reviewed traffic hooks (starting with the
lowest-risk extension point) using this same memory convention, with
explicit input redaction, backpressure, and fail-open/fail-closed semantics
per hook. Phase 14 will handle registry distribution and signature
verification. A project-wide CSRF token contract for mutating control-plane
endpoints (including plugin lifecycle endpoints) remains a separate,
cross-cutting release follow-up tracked outside the Phase 13 sequence.
