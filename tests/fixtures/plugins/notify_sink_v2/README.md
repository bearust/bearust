# Deterministic notification-sink fixture

Local-only, no-import WASM fixture for the Phase 13C `notify.waf_block`
acceptance tests. Exports `bearust_alloc`/`bearust_dealloc`/
`bearust_notify_waf_block` per the memory convention in
`docs/superpowers/specs/2026-08-05-phase-13b-plugin-sdk-design.md`, plus a
trivial `bearust_health_check_v2` stub (required unconditionally of every
`abi_version: 2` module, independent of declared capabilities). It ignores
the host-supplied input and always returns status `0`, so the test suite can
assert an exact outcome while still exercising the full
alloc/write/call/dealloc round trip.

The checked-in WAT source is preferred over a generated binary for the same
reproducibility reasons as `tests/fixtures/plugins/health_ok/`.
