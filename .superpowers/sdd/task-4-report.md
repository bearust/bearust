# Task 4 report: ACME certificate lifecycle service

## Implemented

- Added `certificates::AcmeService` with normalized request validation, per-certificate single-flight locking, issue/renew/status/due-renewal methods, redacted audit events, renewal scheduling metadata, and reload callback after activation.
- Added `ConfigReloader::apply_certificate_change` as a backwards-compatible default hook.
- Exported the service from `certificates`.

## Verification

- `git diff --check`: passed.
- `cargo check --locked`: blocked by the repository's Rust 1.84.1 toolchain resolving `clap_lex 1.1.0`, which requires the stabilized Cargo 1.85 `edition2024` feature (`feature edition2024 is required`). No test execution was possible in that toolchain.

## Concerns for integration

- DNS-01 provider selection remains owned by the control-plane/API task; the service currently returns a sanitized configuration error when no provider is injected.
- The existing control-plane edits were concurrently present when the service commit was created and are included in commit `611944f`; parent should retain or split them as desired.

## Implemented

- Added `TlsSnapshot`, an immutable, path-only certificate/key selection. Construction validates readability, PEM parsing, key/certificate correspondence, and Pingora TLS settings before publication.
- Added the optional TLS snapshot to `RuntimeSnapshot`; `RuntimeSnapshot::build` now fails before constructing/publishing an invalid TLS candidate.
- Existing `ArcSwap` transaction remains publish-after-health-start: failed config/TLS/health preparation leaves the prior `Arc<RuntimeSnapshot>` untouched. Request contexts retain their old snapshot, so active requests continue using the previous state while later requests observe the new state.
- Added reload tests for unchanged HTTP mode and invalid TLS replacement fallback.

## Verification (Rust 1.84.1 Docker)

- `cargo test --locked --test reload`: **9 passed** (including valid replacement, invalid fallback, and HTTP compatibility).
- `cargo test --locked --test tls_listener spawned_tls_listener_proxies_to_local_upstream`: **passed**, including supervisor SIGHUP certificate handoff.
- `cargo test --locked --test reload_pid --test shutdown`: **9 passed**.
- `cargo fmt --all -- --check`: **passed**.
- `cargo clippy --locked --all-targets -- -D warnings`: **passed**.
- `cargo check --locked`: **passed**.

## Listener handoff

Pingora 0.8.1 builds each TLS acceptor at startup, so in-process `ArcSwap` alone
cannot replace the certificate used by new handshakes. The supervisor now uses
Pingora's supported graceful-upgrade path: on SIGHUP it starts a replacement
child with `Opt { upgrade: true }`, validates the candidate configuration/TLS
material before bootstrap, waits for a bounded exact `ready\n` marker, then
sends SIGQUIT to the old child. The marker is atomically written only after
config, TLS, and service registration succeed; the replacement then blocks in
Pingora bootstrap until the old process transfers listener FDs. Pingora passes the listening FDs over
its upgrade socket; the replacement accepts new connections while the old
process drains active sessions. If validation, startup, or the readiness
timeout fails, the replacement is terminated and the old child is left serving.
No ACME behavior is included here.

Pingora's upgrade bootstrap necessarily waits for the old process's FD
transfer, so a post-bootstrap readiness marker would deadlock the handoff. The
marker therefore denotes validated pre-bootstrap readiness, while the child
enters bootstrap immediately afterward; the parent requires the exact marker
contents and bounds the wait.
