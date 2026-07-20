# Task 2 Report

Status: implemented, review findings fixed, and committed.

Commits:
- `71131c6` feat: persist roles and permissions
- `58d6170` fix: support persistent custom role assignments
- pending fix commit for `update_user` custom-role assignment

Implementation:
- Added serializable role/permission DTOs and role create/patch request models in `src/control_plane/models.rs`.
- Added additive SQLite `roles`, `permissions`, and `role_permissions` migrations.
- Added idempotent seeds for all ten permission keys and system-managed admin/operator/viewer roles and assignments.
- Added repository APIs for role CRUD, permission replacement/reading, role lookup, and global user permission checks with system-role and assigned-role protections.
- `insert_user`, `update_user_role`, and now `update_user` accept existing persistent custom role slugs while rejecting unknown slugs. Built-in role compatibility and last-active-admin transaction protections remain intact.
- Restored Task 1 repository coverage and `tests/control_plane_roles.rs`.
- Added focused regression test `update_user_accepts_existing_custom_role_slug`, which creates a custom role, creates a user, reassigns the user through `update_user`, and asserts the resulting role.

Exact commands/output:
- `cargo test --test control_plane_repository --test control_plane_roles`
  - Exit 127: `/bin/bash: line 1: cargo: command not found`
- `git diff --check`
  - Passed with no output before committing this fix.

Concerns:
- The Rust toolchain is unavailable in this environment, so compilation, focused tests, and formatting could not be run.
