# Task 1 Report: TLS configuration model and validation

## Status

Complete. Optional native TLS configuration is supported while preserving HTTP-only defaults.

## Commit

- `feat: add optional tls configuration` (final commit; see `git log` for hash)

## Changes

- Added `ServerConfig.tls: Option<TlsConfig>`.
- Added `TlsConfig` with required `cert_path` and `key_path` `PathBuf` fields.
- Added validation rejecting empty certificate/key paths.
- Serde unknown-field denial and required fields reject unknown keys and one-sided TLS blocks.
- Added commented manual TLS example configuration.
- Added parsing and validation tests for accepted, incomplete, empty, and unknown TLS blocks.

## Verification

- `docker run --rm -v "$PWD":/work -w /work rust:1.84.1-bookworm cargo test --test config_validation tls`
  - Passed: 4 tests.
- `docker run --rm -v "$PWD":/work -w /work rust:1.84.1-bookworm cargo test --test config_validation`
  - Passed: 15 tests.
- `docker run --rm -v "$PWD":/work -w /work rust:1.84.1-bookworm cargo fmt --all -- --check`
  - Passed after formatting.
- `git diff --check`
  - Passed.

The first focused test attempt could not build because the base Rust image lacked `cmake`; the passing runs installed `cmake` in the ephemeral container.

## Concerns

- Certificate-root containment and PEM/key parsing are intentionally deferred to Task 2's `CertificateStore`.
