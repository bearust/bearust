# Phase 7B Task 2 report

## Status

Implemented persistence, validation, immutable `BotStore` reload, and redacted detection telemetry. Commit: `03343e4` (`feat: persist bot protection policy`).

## Changes

- Added idempotent `0005_bot_protection.sql` with monitor defaults, singleton config, trusted-rule uniqueness, and bounded policy fields. The initial fingerprint key is empty; first load generates and persists a per-install random key instead of shipping public key material.
- Added `BotConfigRecord`/`BotRuleRecord` control-plane model views.
- Added repository CRUD (`get_bot_config`, `update_bot_config`, `list_bot_rules`, `insert_bot_rule`, `update_bot_rule`, `delete_bot_rule`) with normalization and bounded validation before writes.
- Added `BotStore::{load,snapshot,reload,record_detection}` backed by `ArcSwap`; failed reloads do not publish a partial snapshot.
- Added focused SQLx repository tests covering idempotent migration, failed-reload atomicity, normalization, and validation.
- Rule listing now fetches one extra row and fails instead of silently returning a truncated policy.

## Verification

- `cargo +stable test --test bot_repository`: passed (3 tests).
- `cargo +stable test --all-targets`: existing migration-order assertion fails because the repository baseline expects exactly four migrations; the new Phase 7B migration correctly makes the list `[1,2,3,4,5]`.
- `cargo +stable clippy --all-targets --all-features -- -D warnings`: blocked by pre-existing Task 1 lint (`clippy::byte_char_slices` in `src/bot_protection.rs`).
- `git diff --check`: passed.

## Concerns

- Existing `control_plane_repository::migrations_record_order_and_seed_exact_permissions` must be updated by the phase-level test task to expect migration 5.
- Task 1 should fix the byte-string Clippy warning before the final Phase 7B gate.
