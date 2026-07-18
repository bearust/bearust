# Task 7 report: certificate renewal scheduling

Implemented renewal scheduling and operational persistence foundations.

## Delivered

- Added `RenewalScheduler` with renewal-window calculation, bounded exponential retry, and last-known-good activation semantics.
- Added `RenewalIssuer` abstraction so ACME issuance remains injectable and outside the request path.
- Added Tokio `run_forever` task and CLI `spawn_renewal_task` hook; Phase 3 will supply the concrete `AcmeManager` command/API wiring.
- Added scheduler tests covering due-window calculation, successful activation, retries, and active-record preservation after repeated failures.
- Mounted writable `/data` and read-only `/etc/bearust/tls` in production and development Compose files.
- Documented custom PEM certificates, HTTP-01/DNS-01 prerequisites, Cloudflare token scope, renewal behavior, and secret handling.

## Verification

- `cargo fmt --all -- --check`: unavailable in this environment (`cargo` is not installed; Rust Docker image also lacked the cargo binary).
- `cargo test --locked --test certificate_renewal`: not run for the same environment limitation.
- `cargo clippy --locked --all-targets -- -D warnings`: not run for the same environment limitation.

The implementation is intentionally limited to the scheduler boundary. It does not add GUI or CLI ACME account/provider configuration; those are Phase 3 concerns.
