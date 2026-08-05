# Deterministic v2 plugin fixture

Local-only, no-import WASM fixture for the Phase 13B `abi_version: 2`
acceptance tests. Exports `bearust_alloc`/`bearust_dealloc`/
`bearust_health_check_v2` per the memory convention in
`docs/superpowers/specs/2026-08-05-phase-13b-plugin-sdk-design.md`. It
ignores the host-supplied input and always returns a fixed JSON literal, so
the test suite can assert an exact `HealthResult.detail` value while still
exercising the full alloc/write/call/read/dealloc round trip.

The checked-in WAT source is preferred over a generated binary for the same
reproducibility reasons as `tests/fixtures/plugins/health_ok/`.
