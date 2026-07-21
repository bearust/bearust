# Phase 5 Task 4 Report

## Status

Complete. Added an opt-in external database integration test for PostgreSQL and
MySQL, shared environment/diagnostic helpers, and developer commands.

## Changes

- Added `tests/external_database.rs`.
  - Skips with an explicit message when `DATABASE_URL_EXTERNAL` is absent.
  - Connects through `repository::connect`, runs migrations twice, and checks
    idempotency.
  - Verifies all ten seeded permissions, all three system-managed roles, and
    the administrator role's complete permission set.
  - Creates and reads a user, then deletes it for repeatability on shared test
    databases.
- Added `external_database_url` and `redacted_database_target` to
  `tests/support/mod.rs`.
- Documented opt-in PostgreSQL and MySQL commands in `DEVELOPMENT.md`.

## Redaction review

Connection and migration failures include only the parsed scheme and host in
panic text. Credentials, ports, paths, query parameters, and the original URL
are never formatted. A regression test covers password-bearing IPv6 URLs.

## Verification

- `git diff --check`: passed.
- `cargo fmt --check`: not run; `cargo` is unavailable in this environment
  (`/bin/bash: cargo: command not found`).
- External PostgreSQL/MySQL integration commands: not run; no external
  database services are configured in this environment.

## Commit

`e5ba2a7 test: add external database integration harness`

The pre-existing `.superpowers/sdd/task-1-report.md` modification was left
unstaged and is unrelated to this task.
