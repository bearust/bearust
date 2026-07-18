# Task 3 report: native Pingora TLS listener

## Result

Implemented `tls::settings` using Pingora 0.8.1's native rustls listener API and
selected TLS vs TCP at startup from `server.tls`.  TLS material errors avoid
including PEM contents or private-key paths.  Existing HTTP mode remains the
default when `server.tls` is absent.

## Verification

All commands ran in `rust:1.84.1-bookworm` Docker:

- `cargo fmt --all -- --check` — passed.
- `cargo check --locked --all-targets` — passed.
- `cargo test --locked --all-targets` — passed.
- `cargo clippy --locked --all-targets -- -D warnings` — passed.

## Concerns

The full generated-certificate HTTPS process integration test is still pending;
the module includes a unit test covering missing-material error redaction.
The rustls feature pulls newer transitive crates, so `Cargo.lock` pins
`time` 0.3.36 and `zeroize` 1.8.1 for Rust 1.84 compatibility.
