# Task 2 Report

Implemented host normalization and indexed, segment-aware longest-prefix routing.

## Changes

- Added `Router`, `ResolvedRoute`, `normalize_host`, and boundary-aware path matching in `src/router.rs`.
- Exported `router` from `src/lib.rs`.
- Added routing tests and TOML fixture under `tests/`.

## Verification

- Local `cargo test --test routing`: unavailable (`cargo: command not found`).
- Rust 1.84 Docker `cargo test --test routing`: 2 passed, 1 failed because the prescribed fixture includes a same-host `/` route while the prescribed assertion expects `/apiv2` to return `None`; the required `path_matches` rule explicitly makes `/` match every path.
- Rust 1.84 Docker `cargo test --test config_validation`: passed.
- Rust 1.84 Docker `cargo clippy --all-targets -- -D warnings`: passed.
- Rust 1.84 Docker `cargo fmt -- --check`: passed after formatting.

## Concern

The `/` fixture route and `/apiv2` `None` assertion are internally inconsistent under the exact boundary-matching function in the brief. The implementation follows that function verbatim.
