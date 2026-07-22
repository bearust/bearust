# Phase 7B Task 3 Report

Status: complete

Commits: `f67aa1185e1e227ed40755fb055d94a46b5a93e6` (`feat: add bot policy admin api`), `b59c729` (`fix: make bot policy imports atomic`), `bc0fd0e` (`fix: rollback bot rule reload failures`).

Implemented:

- Added `bot_protection.manage` RBAC permission and seeded it for administrators.
- Added authenticated `GET/PATCH /api/bot/config` with monitor default and bounded validation.
- Added trusted-crawler list/create/update/delete endpoints with normalized persistence and reload.
- Added bounded TOML import/export endpoints at `/api/bot/config/import` and `/api/bot/config/export`.
- Wired `BotStore` into control-plane state and emits redacted audit records plus `bot.changed` events.
- Added frontend API types and functions without exposing signing keys.
- Added endpoint regression tests for authorization, monitor defaults, and crawler CRUD.
- Added transactional TOML replacement, reload rollback, strict body/list bounds, and import regression coverage.

Verification:

- `cargo +stable test --test control_plane_bot` — 3 passed.
- `cargo +stable test --all-targets` — passed.
- `cargo +stable clippy --all-targets --all-features -- -D warnings` — passed.
- `git diff --check` — passed.

Concern:

- Frontend Vitest could not run in this worktree because the `frontend` dependencies are not installed (`vitest: not found`).
