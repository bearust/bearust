# Phase 5 Task 3 Report

## Status

Implemented the control-plane database type port. Repository, RBAC, audit, and ACME certificate service APIs now use `repository::DbPool` (`sqlx::AnyPool`) and row conversion uses `sqlx::AnyRow`.

## Inventory before editing

The initial search found SQLite-specific pool/row types throughout `src/control_plane/repository.rs`, `src/control_plane/rbac.rs`, `src/control_plane/audit.rs`, `src/certificates/acme_service.rs`, and related tests. Nonportable SQL found in source was:

- `BEGIN IMMEDIATE` in initial-admin, role/user administration, and host-scope transactions.
- `INSERT OR IGNORE` in host-scope restoration.
- `datetime('now')` in RBAC test fixtures.

`RETURNING` and `PRAGMA` were present only in tests or migration compatibility code, not in the ported application queries.

## Changes

- Replaced `SqlitePool`/`SqliteRow` signatures with `DbPool`/`AnyRow`.
- Kept `?` bind placeholders and existing return/error semantics.
- Replaced `INSERT OR IGNORE` with `INSERT ... SELECT ... WHERE NOT EXISTS`.
- Replaced `BEGIN IMMEDIATE` with portable `BEGIN`; transaction commit/rollback behavior remains explicit.
- Made RBAC fixtures bind RFC3339 timestamps instead of SQLite `datetime()`.

## Verification

- `rg` confirms no `SqlitePool`, `SqliteRow`, `INSERT OR IGNORE`, or `BEGIN IMMEDIATE` remain in the ported source files.
- `cargo check --locked`: not run; `cargo` is unavailable in this environment.
- `rustfmt --check`: not run; `rustfmt` is unavailable in this environment.

## Concerns for integration

The existing test suite still contains SQLite-specific setup helpers and should be migrated in the external-database harness task. The first-admin transaction currently uses generic `BEGIN`; concurrent setup serialization should be validated against the sentinel strategy introduced by Task 2.
