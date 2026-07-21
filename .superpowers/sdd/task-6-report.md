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

---

# Phase 5 Task 6 report: compatibility verification and documentation

## Status

Complete. Documented Phase 5 support and recorded the available verification
results.

## Documentation

- Added a Phase 5 roadmap status note to `docs/PRD.md` covering SQLite as the
  default, PostgreSQL/MySQL via `DATABASE_URL`, SQLx migration guarantees,
  opt-in external-driver tests, Compose profiles, and explicit non-goals.
- Expanded `DEVELOPMENT.md` with startup migration behavior and the deliberate
  backend export/import limitation.
- `README.md` already contains the Phase 5 Compose profile and upgrade guidance
  from Task 5; no duplicate edits were needed.

## Verification

- `cargo fmt --check`: not run; unavailable in this environment (`bash:
  cargo: command not found`, exit 127).
- `cargo test --locked`: not run; unavailable for the same reason (exit 127).
- `cargo clippy --all-targets -- -D warnings`: not run; unavailable for the
  same reason (exit 127).
- `git diff --check`: passed.
- `git diff origin/main...HEAD --stat`: reviewed; includes the Phase 5
  migrations, repository portability changes, integration harness, Compose
  profiles, and documentation.
- Secret scan (`rg -n -i "password|DATABASE_URL"`): matches are documented
  configuration names, test fixtures, and development placeholders only; no
  production credential or secret value was added by this task. Passwords in
  URLs and Compose examples are explicitly marked for replacement/redaction.

The pre-existing `.superpowers/sdd/task-1-report.md` modification was left
unstaged and is unrelated to this task.
