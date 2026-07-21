# Phase 4E Task 2 Report

Implemented scoped role persistence and API support.

## Changes

- Added serializable `RolePermissionScope` and additive `scopes` fields to role create, patch, and detail models.
- Added normalized scope reads and atomic replacement in the repository. Global role permission rows are preserved while only `proxy_host` rows are replaced.
- Validates supported scoped permissions, positive/unique host IDs, existing proxy hosts, and rejects built-in role mutation.
- Added scoped role creation/update repository variants and wired HTTP handlers to return validation errors.
- Role responses now include scopes; successful scoped mutations emit `role_scopes_changed` and `roles.changed` after commit.
- Added repository regression tests for replacement/clear, global-row preservation, unknown hosts, invalid permissions, duplicate IDs, and built-in role rejection.
- Added a query index for scope lookups.

## Verification

- `git diff --check` passed.
- `cargo check` / tests could not run because `cargo` is unavailable in this environment (`cargo: command not found`).
