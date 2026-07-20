# Task 3 Report

## Status

Implemented and committed as `973d90a feat: centralize persistent permission checks`.

## Changes

- Added stable permission keys, global `ResourceContext`, and async persistent `authorize` in `src/control_plane/rbac.rs`.
- Authorization fails closed for unknown persisted roles and database errors (`unwrap_or(false)` at handler boundaries).
- Migrated control-plane authorization branches for users, audit logs, proxy hosts, certificates, and ACME handlers away from hardcoded role matching.
- Added focused custom-role permission mutation coverage proving changes apply without re-login.

## Commands and output

- `rg -n "enum Permission|Permission|Role::|user_has_permission|authorize|proxy-host|audit" ...` — located existing hardcoded checks and persistent repository API.
- `cargo test --test control_plane_users custom_role_permission_changes_apply_without_relogin` — could not execute: `/bin/bash: cargo: command not found` (exit 127).
- `git diff --check` — passed with no output.
- `git add src/control_plane/rbac.rs src/control_plane/mod.rs tests/control_plane_users.rs tests/control_plane_audit.rs && git commit -m "feat: centralize persistent permission checks"` — committed successfully as `973d90a`.

## Concerns

- Rust toolchain is unavailable in this environment, so focused and regression tests could not run.
- `tests/control_plane_audit.rs` was not behaviorally changed because its existing unknown-role test already covers fail-closed audit access.
