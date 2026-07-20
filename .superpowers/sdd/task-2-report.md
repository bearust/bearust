# Task 2 Report

Status: implemented, review findings fixed, and committed.

Commits:
- `71131c6` feat: persist roles and permissions
- `58d6170` fix: support persistent custom role assignments
- `ad712d1` fix: allow update users custom roles
- `3745a16` fix: accept custom roles in user handlers
- `f23b5d4` fix: serialize custom role deletion
- pending final delete transaction fix commit

Implementation:
- Added serializable role/permission DTOs and role create/patch request models in `src/control_plane/models.rs`.
- Added additive SQLite `roles`, `permissions`, and `role_permissions` migrations.
- Added idempotent seeds for all ten permission keys and system-managed admin/operator/viewer roles and assignments.
- Added repository APIs for role CRUD, permission replacement/reading, role lookup, and global user permission checks with system-role and assigned-role protections.
- `insert_user`, `update_user_role`, and `update_user` accept existing persistent custom role slugs while rejecting unknown slugs. Built-in role compatibility and last-active-admin transaction protections remain intact.
- Added shared async handler role-existence validation for POST `/api/users` and PATCH `/api/users/{id}`, preserving safe `invalid_input` responses for unknown roles.
- Restored Task 1 repository coverage and `tests/control_plane_roles.rs`.
- Added HTTP regression coverage for custom-role creation/update and unknown-role rejection in `tests/control_plane_users.rs`.
- Changed `delete_role` to acquire a connection and execute `BEGIN IMMEDIATE` before lookup, assignment check, and delete. Every failure path explicitly rolls back; no-row and success paths explicitly commit.
- Restored `docs/superpowers/plans/2026-07-20-phase-4d1-rbac-audit.md` and `docs/superpowers/specs/2026-07-20-phase-4d1-rbac-audit-design.md`.

Exact commands/output:
- `cargo test --test control_plane_repository --test control_plane_roles`
  - Exit 127: `/bin/bash: line 1: cargo: command not found`
- `git diff --check`
  - Passed with no output before committing this fix.

Concerns:
- The Rust toolchain is unavailable in this environment, so compilation, focused tests, and formatting could not be run.
