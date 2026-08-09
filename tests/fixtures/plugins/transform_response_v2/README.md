# Deterministic response body transformer fixture

Local-only, no-import WASM fixture for the Phase 13F `transform.response`
acceptance tests. Exports `bearust_alloc`/`bearust_dealloc`/
`bearust_transform_response` per the memory convention in
`docs/superpowers/specs/2026-08-09-phase-13f-response-transform-design.md`,
plus a trivial `bearust_health_check_v2` stub (required unconditionally of
every `abi_version: 2` module, independent of declared capabilities). It
ignores the host-supplied input and always returns the fixed body
`aGVsbG8=` (base64 for `hello`), so the test suite can assert an exact
outcome while still exercising the full alloc/write/call/read/dealloc round
trip.

The checked-in WAT source is preferred over a generated binary for the same
reproducibility reasons as `tests/fixtures/plugins/health_ok/`.
