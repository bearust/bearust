# Deterministic backend selector fixture

Local-only, no-import WASM fixture for the Phase 13G `balance.select`
acceptance tests. Exports `bearust_alloc`/`bearust_dealloc`/
`bearust_balance_select` per the memory convention in
`docs/superpowers/specs/2026-08-12-phase-13g-load-balancing-hooks-design.md`,
plus a trivial `bearust_health_check_v2` stub (required unconditionally of
every `abi_version: 2` module, independent of declared capabilities). It
ignores the host-supplied input and always returns the fixed
`{"backend_id":0}`, so the test suite can assert an exact outcome while
still exercising the full alloc/write/call/read/dealloc round trip.

The checked-in WAT source is preferred over a generated binary for the same
reproducibility reasons as `tests/fixtures/plugins/health_ok/`.
