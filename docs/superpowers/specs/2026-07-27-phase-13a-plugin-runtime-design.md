# Phase 13A — WASM Plugin Runtime Foundation Design

**Status:** Design approved; implementation plan pending review

**Scope:** Phase 13A of the BeaRust roadmap. This increment establishes a
secure, optional WASM runtime and lifecycle control. It does not implement the
public plugin SDK, traffic hooks, or a community registry.

## Goals

Phase 13A must provide a foundation on which later plugin increments can add
stable hook points without coupling untrusted code to the proxy process. The
runtime must:

- load a local WASM module only after validating a versioned `plugin.toml`
  manifest;
- run each invocation inside a bounded `wasmtime` store with fuel and memory
  limits;
- deny filesystem, network, environment, clock, random, and arbitrary host
  functions by default;
- expose only a minimal versioned ABI for lifecycle health checks, with no
  request or response mutation hooks in this increment;
- atomically publish a new plugin snapshot and remove old instances without
  restarting the proxy;
- isolate traps, timeouts, invalid modules, and resource exhaustion from the
  proxy data path; and
- expose authenticated, administrator-only lifecycle/status operations with
  redacted audit events and bounded metrics.

## Non-goals

The following remain outside Phase 13A:

- WAF, request/response, load-balancer, or notification hook execution;
- arbitrary WASI capabilities, host filesystem or network access;
- plugin-provided configuration mutation or database access;
- remote plugin downloads, registries, signatures, or trust-on-first-use;
- a stable public SDK crate (Phase 13B); and
- frontend marketplace or plugin authoring workflows.

## Proposed architecture

### Runtime boundary

Add a focused `plugin_runtime` module owning manifest validation, module
compilation, instance lifecycle, capability policy, and bounded invocation.
The rest of the application interacts through typed Rust interfaces rather
than `wasmtime` types. A runtime snapshot contains immutable plugin metadata
and compiled modules; an `ArcSwap` publication keeps reads lock-free and
allows load/unload to be transactional.

The runtime is optional. With no configured plugin directory, or when a
plugin is invalid, the proxy starts normally and the plugin is marked
unavailable. A plugin failure is reported to control-plane diagnostics but is
never returned as a proxy request failure.

### Manifest and trust policy

Each plugin directory contains `plugin.toml` and one WASM module. The manifest
contains a lowercase identifier, display name, ABI version, module filename,
requested capabilities, and declared resource limits. Unknown fields,
duplicate capabilities, path traversal, absolute module paths, unsupported ABI
versions, limits above server maxima, and missing files are rejected before
compilation.

The server policy is deny-by-default. Phase 13A accepts only the capability
`health_check`; all future permissions are rejected rather than silently
granted. The module path is resolved beneath the configured plugin directory
and must remain within that directory after canonicalization. A SHA-256 digest
of the loaded module is retained for status and audit correlation, but there is
no signature or remote trust decision in this phase.

### WASM ABI

The initial ABI is deliberately narrow and versioned. The module must export
`bearust_abi_version() -> i32` and may export
`bearust_health_check() -> i32`. No host imports are provided. Health checks
receive no traffic data and return only a bounded integer status. Missing or
malformed exports make the plugin unavailable. ABI errors are stable internal
error codes and are never exposed as raw runtime messages.

### Resource and lifecycle controls

The server clamps every manifest request to configured maxima for memory pages,
fuel, invocation duration, output size, and active plugin count. Every call
uses a fresh store and a cancellation-aware timeout. Fuel exhaustion, a trap,
or timeout marks that invocation failed and increments bounded metrics; it does
not poison other plugins. Compilation and reload happen off the request path.

Load, enable, disable, and unload operations build a complete candidate
snapshot first, then publish it atomically. Existing invocations finish against
their captured instance; later invocations observe the new snapshot. A failed
reload leaves the last valid snapshot active.

### Control plane and observability

Add authenticated admin-only endpoints for listing plugin status and applying
local lifecycle changes. Responses include only identifier, display name, ABI,
digest, enabled/loaded state, last safe error code, and timestamps. Paths,
manifest contents, WASM bytes, runtime backtraces, and capability secrets are
not returned.

Lifecycle changes emit the existing redacted audit and realtime invalidation
events. Metrics use fixed low-cardinality labels (`plugin_id`, `operation`,
`outcome`) with bounded plugin count and no user-controlled free-form labels.

## Failure and security behavior

- Invalid configuration disables only the affected plugin.
- A missing plugin directory is equivalent to an empty installation.
- No plugin can access the host process, filesystem, network, environment,
  secrets, database, or proxy request bytes in this phase.
- Runtime errors are mapped to `invalid_manifest`, `compile_failed`,
  `abi_mismatch`, `disabled`, `timeout`, `fuel_exhausted`, `memory_limit`, or
  `trap`; raw `wasmtime` messages stay in server-side debug logs only when
  explicitly enabled and are redacted.
- Administrative lifecycle requests require the existing RBAC permission and
  CSRF/session protections; unauthorized callers receive the standard safe
  error envelope.
- The proxy remains available if `wasmtime` initialization, compilation, or a
  plugin invocation fails.

## Testing and acceptance gate

Tests must cover manifest parsing and path containment, capability denial,
module digest stability, ABI validation, resource-limit clamping, timeout and
fuel exhaustion, traps, atomic reload/unload, stale snapshot behavior, bounded
metrics, redacted audit/realtime events, admin RBAC, and startup with plugins
disabled or invalid.

The Phase 13A gate is satisfied when:

1. the application starts and serves normal proxy traffic with no plugins;
2. a valid health-check plugin can load, report status, disable, re-enable,
   and unload without restart;
3. invalid or malicious manifests/modules cannot obtain capabilities or escape
   the configured directory;
4. resource exhaustion and runtime traps cannot block or fail the proxy path;
5. lifecycle APIs, audit events, and metrics contain no raw module data or
   secrets; and
6. Rust formatting, Clippy, unit/integration tests, frontend build, and
   `git diff --check` pass.

## Follow-up increments

Phase 13B will define the public SDK, stable memory/serialization conventions,
and signed example plugins. Phase 13C will add one hook at a time with explicit
input redaction, backpressure, and fail-open/fail-closed semantics. Phase 14
will handle registry distribution and signature verification.
