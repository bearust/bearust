# Phase 13A final review

Date: 2026-08-03

## Scope and evidence

Phase 13A is limited to an optional local WASM runtime and health-check ABI.
The implementation and tests cover manifest parsing, unknown-field and
capability denial, ABI validation, module digesting, canonical path
containment (including traversal and symlink escape), bounded memory/fuel/
timeout/output limits, traps, atomic reload/disable/enable/unload snapshots,
stale snapshot isolation, redacted control-plane responses, RBAC, audit and
realtime events, bounded metrics, and startup with plugins disabled or invalid.

The deterministic fixture in
`tests/fixtures/plugins/health_ok/{plugin.toml,health_ok.wat}` is parsed by the
integration suite. It contains no imports or third-party module bytes; the WAT
source is reproducible with the repository's pinned `wat` dev dependency.

## Security review

| Check | Result | Evidence |
| --- | --- | --- |
| Path traversal / symlink escape | Pass | `resolve_module_path` canonicalizes beneath the configured root; focused tests reject `..`, absolute paths, missing files, directories, and symlink escapes. |
| Capability escalation | Pass | Manifest validation accepts only `health_check`; unknown and duplicate capabilities fail closed; linker supplies no host/WASI imports. |
| Unbounded resource use | Pass | Server maxima clamp memory pages, fuel, invocation timeout, output bytes, module bytes, and plugin count; Wasmtime stores have bounded memories/instances/tables. |
| Secret/raw module leakage | Pass | API models expose only bounded status/digest/error code; audit, realtime, metrics, and errors use allow-listed values and omit paths, bytes, manifests, backtraces, request data, and secrets. |
| Proxy-path coupling | Pass | Invocation errors are isolated and startup continues when plugins are disabled, missing, invalid, or unavailable; reload compilation is dispatched to a blocking worker. |

## Acceptance gate — resolved 2026-08-05

The pinned `1.84.1` toolchain could not resolve the dependency graph:
transitive crates (`time-core` via `time` v0.3.55 through `x509-parser`, and
separately `idna_adapter`) began requiring `edition2024`, stabilized in Rust
1.85. Rather than pinning an increasing set of transitive dependencies to
older, potentially unpatched versions, the project's pinned toolchain was
bumped from `1.84.1` to `1.97.1` (current stable), updated consistently in
`rust-toolchain.toml`, `.github/workflows/ci.yml`, and `DEVELOPMENT.md`;
`Cargo.toml`'s `rust-version` was raised to the true MSRV of `1.85`. This is
a project-wide toolchain change, not scoped to plugins.

With the updated toolchain the full gate now passes:

```text
cargo fmt --all -- --check                              PASS
cargo clippy --all-targets -- -D warnings                PASS
DATABASE_URL=sqlite::memory: cargo test --all-targets    PASS (after fixing one stale test, see below)
npm test --prefix frontend -- --run                       PASS (161 tests)
npm run build --prefix frontend                            PASS
npm run validate-locales --prefix frontend                 PASS
git diff --check                                            PASS
```

Running the full suite (previously blocked by disk exhaustion in the review
environment, so never actually executed end-to-end) surfaced one real, unrelated
pre-existing failure: `advisor_migration_is_idempotent_and_seeds_builtin_permissions`
asserted a fixed admin permission list that predated Phase 13A's
`plugins.manage`/`plugins.read` permissions. The test's expected admin list was
updated to include them; this was a test-fixture gap, not a runtime defect —
the actual seeded RBAC data was already correct.

## Deferred scope

Mutating plugin endpoints (and all other mutating control-plane endpoints)
use the existing authenticated RBAC/session contract with a `SameSite=Lax`
session cookie, but do not yet enforce a dedicated CSRF token. This is a
cross-cutting, project-wide gap (not specific to plugins) and remains a
release follow-up rather than a silently waived guarantee.

Phase 13B (public SDK and stable memory/serialization conventions), Phase 13C
(traffic hooks with explicit redaction/backpressure and fail-open/fail-closed
semantics), and Phase 14 (registry distribution, signatures, and trust policy)
are intentionally not implemented. Phase 13A has no signature verification;
operators must install only reviewed local modules from a read-only directory.
