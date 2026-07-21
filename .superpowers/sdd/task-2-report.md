# Task 2 report: portable control-plane migrations

## Status

Implemented and committed as `0ee8f2b` (`feat: add portable control-plane migrations`).

## Changes

- Added ordered SQLx migrations `0001_initial.sql` and `0002_add_disabled_and_secret_ref.sql`.
- Moved schema creation out of `repository::migrate`; it now runs `sqlx::migrate!("./migrations")` and idempotently seeds ten permissions, three built-in roles, and role-permission assignments with `INSERT ... SELECT ... WHERE NOT EXISTS`.
- Added migration-order, seed-idempotency, and legacy-record-preservation tests.
- Kept the pre-existing unrelated `.superpowers/sdd/task-1-report.md` working-tree change unstaged.

## Verification

- `git diff --check`: passed.
- `cargo test --locked --test control_plane_repository migration_seeds_builtin_roles_and_all_permissions_idempotently -- --nocapture`: not run; `cargo` is unavailable in this environment (`/bin/bash: cargo: command not found`).

## Concerns for follow-up

- Task 1/Task 3 must finish converting repository APIs and tests from `SqlitePool` to `DbPool`; this task only changes the migration entry point and seed logic.
- The additive compatibility migration is a deliberate no-op because columns are present in the initial portable schema. This avoids non-portable conditional `ALTER TABLE` behavior while upgrading legacy databases through the initial migration.
- `INTEGER PRIMARY KEY` is used as requested for portable DDL; verify identity/auto-generation semantics against PostgreSQL and MySQL integration containers in the external-database test task.

## Review blocker fixes

- IDs are now explicitly supplied by the application for repository-created users,
  roles, sessions, proxy hosts, and certificates (UUID-derived positive `i64`);
  deterministic IDs are used for built-in permissions and roles. This avoids
  relying on SQLite's implicit `INTEGER PRIMARY KEY` allocator, which does not
  exist for PostgreSQL/MySQL.
- `role_permissions` now uses the portable non-null global sentinel
  `scope_type=''` and `scope_id=0`; migration startup normalizes nullable rows
  left by legacy SQLite schemas and seed checks use the sentinel.
- `repository::migrate` performs backend-tolerant additive `ALTER TABLE` checks
  for legacy `users.disabled` and `acme_certificates.secret_ref`, ignoring only
  duplicate-column errors and preserving all existing data.
- Added assertions that all 18 built-in global grants exist, are idempotent, and
  contain no nullable scope values.

## Review-fix verification

- `git diff --check`: passed.
- Cargo tests/checks: unavailable (`cargo: command not found`); run the focused
  repository migration tests with the project's Rust 1.88 builder and external
  PostgreSQL/MySQL containers before merging.

## Follow-up review fix

- Corrected legacy scope normalization to match `NULL` values (including
  partially-null rows) instead of the already-normalized sentinel, preserving
  global grants as `('', 0)` while leaving per-host grants unchanged.
- Expanded the legacy fixture with existing roles, permissions, global NULL
  scope rows, scoped rows, and audit data; assertions verify every record after
  migration.
- Verification: `git diff --check` passed; Rust tests remain unavailable because
  `cargo` is not installed in this environment.

## Final robustness fix

- Seed IDs now check for existing legacy rows with a colliding numeric ID and
  fall back to a generated ID, avoiding accidental FK reassignment.
- SQLite legacy duplicate NULL-global grants are deduplicated before sentinel
  normalization; one grant is retained and scoped grants are untouched.
- The legacy regression fixture now includes duplicate NULL grants and asserts
  exactly one normalized global row.
