# Task 2 Report: Secure certificate store

## Implemented

- Added `CertificateStore` with custom PEM import, activation, and active snapshot APIs.
- Validates X.509 PEM, private-key PEM, certificate expiry, and public-key correspondence.
- Extracts SAN/CN hostnames and persists non-secret metadata.
- Stores each certificate under a caller-provided root with name/path containment checks.
- Uses temporary files, restrictive `0600` permissions for private keys, fsync, and atomic rename.
- Redacts parsing/storage failures so PEM and private-key contents cannot appear in errors.
- Added focused malformed-input, traversal, and unknown-activation tests.

## Verification

- `cargo fmt --all` completed with Rust 1.84.1 Docker toolchain.
- Full Rust test execution was blocked by the container's crates.io resolution selecting newer transitive crates requiring Cargo/Rust beyond 1.84.1. The source and focused tests were formatted; parent integration should regenerate the lockfile with Rust 1.84-compatible pins.

## Commit

`4b948c8 feat: add secure certificate store`

## Notes

`openssl` is used for robust PEM/X.509 parsing and key matching. `Cargo.lock` intentionally remains unchanged because this worktree cannot resolve the new dependency without upgrading unrelated locked packages.

## Review fixes

- Imports stage certificate, key, and metadata in a unique temporary directory and atomically swap the directory after fsync; failed swaps restore the previous directory.
- Root and named certificate directories reject symlinks, and names cannot traverse outside the root.
- Added valid import/activation, key mismatch, and Unix `0600` permission tests.
- OpenSSL is pinned to `0.10.68` for the Rust 1.84 target. Cargo.lock still needs regeneration in an environment with compatible cached index entries; the available container resolver selected unrelated newer packages.

Fix commit: `86ec277 fix: harden certificate staging and validation`
