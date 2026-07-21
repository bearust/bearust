# Task 1 Report: Resource context and repository authorization

## Status

Implemented Phase 4E Task 1. `ResourceContext` now distinguishes global resources from an individual proxy host. Centralized `authorize` maps host contexts to the repository scope API. Repository authorization accepts global grants or exact `proxy_host` grants and rejects unknown scope types fail-closed.

## Commit

- `feat: add per-host authorization context`

## Tests

Added async regression tests covering:

- global grants authorizing global and host contexts;
- exact host grant authorization;
- denial for an unassigned host and global context when only scoped access exists;
- denial for unknown scope types.

Verification attempted:

- `cargo test control_plane::rbac::tests -- --nocapture` — unavailable because `cargo` is not installed in this environment.
- `rustfmt --version` — unavailable because `rustfmt` is not installed.
- `git diff --check` — passed.

## Concerns

The focused Rust tests, `cargo fmt --check`, and Clippy must be rerun in a Rust toolchain environment. No handler wiring or role-scope persistence/API changes were made; those belong to later tasks.
