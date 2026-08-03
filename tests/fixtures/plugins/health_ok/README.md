# Deterministic plugin fixture

This directory is a local-only, no-import WASM health-check fixture for the
Phase 13A acceptance tests. `plugin.toml` is the manifest and `health_ok.wat`
is the source. The module exports only the versioned ABI and a constant health
status of `1`; it receives no request data and has no filesystem, network, or
WASI imports.

The checked-in source is preferred over a generated binary so the fixture is
reviewable and reproducible. To exercise a filesystem load manually, compile
it with a pinned WAT compiler (for example `wat2wasm health_ok.wat -o
health_ok.wasm`) and remove the generated binary after the run.
