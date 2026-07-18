# Task 1 Report: ACME certificate lifecycle metadata

## Status

Implemented and committed. Added serializable ACME request/status models with hostname normalization and challenge validation; added an idempotent SQLite metadata table and repository lifecycle operations. Metadata responses contain no certificate private-key or provider-token fields.

## Commit

- `803f9e9 feat: add acme certificate lifecycle metadata`

## Verification

- `git diff --check` — passed.
- `cargo fmt --all -- --check` — unavailable on host (`cargo: command not found`).
- Focused `cargo test --locked --test acme_repository` — unavailable because the provided Rust Docker image in this environment does not expose `cargo` (`bash: cargo: command not found`).

The deterministic test target is included at `tests/acme_repository.rs` and covers migration, normalization/deduplication, wildcard rules, status updates, due selection, and redaction.

## Concerns

- Full compile/test verification should be run in the project’s normal Rust 1.88 builder image before integration. Repository API uses `update_acme_status(pool, certificate_id, renewal_state, next_renewal_at, last_attempt_at, last_error_code)` and `list_due_acme_certificates(pool, at)`.
