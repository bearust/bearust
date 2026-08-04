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

## Acceptance gate

The plan's required stable-toolchain commands were also checked explicitly:

```text
cargo +1.84.1 fmt --all -- --check                              PASS
cargo +1.84.1 clippy --all-targets -- -D warnings               BLOCKED: transitive edition-2024 crate (`time-core`) cannot be parsed
DATABASE_URL=sqlite::memory: cargo +1.84.1 test --all-targets    BLOCKED: same dependency-graph parse incompatibility (latest-toolchain linker exhaustion observed separately)

For comparison, the latest installed stable toolchain can run the Clippy
command successfully; the pinned project toolchain is `1.84.1` and remains the
release gate.
```

Nightly was used for the focused plugin verification below because it can
resolve the current dependency graph. This toolchain deviation is recorded
explicitly; it does not change the pending status of the full stable gate.

Run from the repository root. Results are recorded here after the final review
run (pre-existing failures, if any, are listed explicitly rather than hidden).

```text
cargo +nightly fmt -- --check                         PASS
cargo +nightly clippy --all-targets -- -D warnings   FAIL (pre-existing unrelated diagnostics)
DATABASE_URL=sqlite::memory: cargo +nightly test --all-targets  BLOCKED by disk exhaustion
npm test --prefix frontend -- --run                    PASS (161 tests)
npm run build --prefix frontend                        PASS
npm run validate-locales --prefix frontend             PASS
git diff --check                                       PASS
```

The focused plugin suite (`DATABASE_URL=sqlite::memory: cargo +nightly test
--test plugin_runtime`) passes all 28 tests. The full Rust test command reached
the linker but exhausted the host filesystem while compiling parallel test
targets; no test assertion failure was reported. Clippy's only diagnostics are
pre-existing unrelated warnings in `src/ai_advisor_redaction.rs` (deprecated
`fetch_update`) and `src/cluster_raft_runtime.rs` (two
`result_large_err` lints). After installing frontend dependencies, the frontend
suite passed all 161 tests, the production build passed, and locale validation
passed.

## Deferred scope

The acceptance gate still has two operational follow-ups: mutating plugin
endpoints use the existing authenticated RBAC/session contract but do not yet
enforce a dedicated CSRF token, and the pinned 1.84.1 dependency graph cannot
be compiled until its transitive minimum-toolchain mismatches are resolved. These are
release blockers, not silently waived security guarantees.

Phase 13B (public SDK and stable memory/serialization conventions), Phase 13C
(traffic hooks with explicit redaction/backpressure and fail-open/fail-closed
semantics), and Phase 14 (registry distribution, signatures, and trust policy)
are intentionally not implemented. Phase 13A has no signature verification;
operators must install only reviewed local modules from a read-only directory.
