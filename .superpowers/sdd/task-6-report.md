# Task 6 report: TLS certificate activation reload

## Implemented

- Certificate activation now validates the certificate/private-key pair from
  the repository paths before changing active state.
- The previous active certificate id/name is captured before activation.
- DB active state and the certificate-store active pointer are updated before
  calling `ConfigReloader::apply_certificate_change`.
- Reload failures restore both DB state and `active.json`, and emit the
  `certificate_activation_failed` audit event.
- Added repository helpers for reading certificate paths, reading the active
  id, and setting exactly one active certificate (or none) transactionally.
- Added `CertificateStore::clear_active` for rollback to an empty snapshot.

## Verification

- `git diff --check` — passed.
- `RUSTUP_TOOLCHAIN=1.88.0 CARGO_BUILD_JOBS=1 cargo check --locked` (Docker
  `rust:1.88-bookworm`) — passed.

## Concerns

- The production `NoopReloader` remains a no-op; the runtime integration must
  provide a concrete `ConfigReloader` implementation that rebuilds and
  publishes the proxy/TLS snapshot.
- Rollback is best-effort and records the original reload failure; an I/O
  failure while restoring the pointer is not surfaced to the API response.
