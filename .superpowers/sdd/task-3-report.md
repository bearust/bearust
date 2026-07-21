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

The external-database harness task should add PostgreSQL/MySQL matrix coverage; the existing fixtures remain SQLite-backed while exercising the backend-agnostic pool API. The first-admin transaction uses generic `BEGIN` and is covered by the concurrent setup regression test.

## Review follow-up

- Removed SQLite `json_each(?)` from role-scope replacement; host IDs are now validated with one portable query per ID.
- Added a process-wide async mutex around first-admin setup and a concurrent setup regression test. This serializes setup attempts consistently across supported backends while preserving the existing transaction and `Ok(None)` semantics.
- Ported affected test pool signatures to `repository::DbPool` and replaced SQLite pool option types with `AnyPoolOptions`.

## Final concurrency hardening

Added migration `0003_setup_lock.sql` with an idempotent singleton sentinel row. First-admin setup now updates that row inside its transaction before checking the user count; the row update acquires the selected backend's write/row lock, preventing concurrent processes from both creating an administrator without backend-specific SQL. The process-local mutex was removed.

## Final review fixes

Migration-order coverage now expects version 3 and verifies the setup sentinel. Every built-in role-permission insert explicitly writes the global scope sentinel (`scope_type=''`, `scope_id=0`), including seed, create, update, and set operations; this prevents nullable legacy schemas from producing grants invisible to RBAC queries.

## Cross-vendor cleanup

Removed MySQL-incompatible `CREATE INDEX IF NOT EXISTS` from the initial migration (migrations are applied once by SQLx). Legacy nullable scope normalization now enumerates role/permission pairs and uses portable `DELETE` plus conditional sentinel insertion, avoiding SQLite `rowid`/PostgreSQL `ctid` assumptions while retaining existing global and scoped grants.

The role-scope index is created idempotently after the migrator with duplicate-index error handling, allowing pre-Phase-5 databases that already contain it to upgrade safely. The legacy fixture covers this pre-existing-index case.
