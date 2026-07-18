# Task 1 Fix Report

## Commit

- `89710fc8a5939aef4add9dfc71266212ac0be201 fix: harden ACME request validation and persistence`

## Changes

- Enforced DNS hostname label syntax, length, hyphen placement, and empty-label checks.
- Rejected malformed wildcards and single-label/TLD wildcards; HTTP-01 wildcard rejection remains enforced.
- Made ACME certificate insertion transactional, including certificate existence verification and hostname update.
- Invalid persisted enum values and hostname JSON now return repository errors instead of silently defaulting.
- Added deterministic malformed-hostname and missing-certificate atomicity tests.

## Verification

- `git diff --check` — passed.
- Focused Docker test attempt was blocked by the image's Rust 1.84 toolchain resolving a dependency requiring Cargo edition2024; host has no Cargo.

## Concerns

Run the focused test with the project's normal Rust 1.88 builder before integration. The existing task report was included in the same commit because it was already staged in the shared worktree.
