# Task 2 Report

Status: implemented, review findings fixed, and committed.

Commits:
- `71131c6` feat: persist roles and permissions
- pending fix commit (created after this report update)

Implementation:
- Added serializable role/permission DTOs and role create/patch request models in `src/control_plane/models.rs`.
- Added additive SQLite `roles`, `permissions`, and `role_permissions` migrations.
- Added idempotent seeds for all ten permission keys and system-managed admin/operator/viewer roles and assignments.
- Added repository APIs for role CRUD, permission replacement/reading, role lookup, and global user permission checks with system-role and assigned-role protections.
- Fixed `insert_user` and `update_user_role` to accept existing persistent custom role slugs while rejecting unknown slugs. Existing built-in role parsing and last-active-admin invariants remain enforced; custom roles can be assigned without weakening the admin guard.
- Restored Task 1 repository coverage and `tests/control_plane_roles.rs`, including migration seed idempotency and custom-role assignment, permission changes, and assigned-role deletion protection.

Exact commands/output:
- `cargo test --test control_plane_repository --test control_plane_roles`
  - Exit 127: `/bin/bash: line 1: cargo: command not found`
- `git diff --check`
  - Passed with no output before committing the fixes.

Concerns:
- The Rust toolchain is unavailable in this environment, so compilation, focused tests, and formatting could not be run.
