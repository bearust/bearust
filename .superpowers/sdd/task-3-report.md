Task 3 implementation completed in commit a942c02.
- Added audit::record_state(AppState, ...) writing existing audit row then publishing redacted `audit` event.
- Added safe domain invalidation hooks for auth sessions, users, roles, proxy hosts, and certificates; events only after successful mutations.
- Added focused test for state audit publication and secret-free payload.
- `git diff --check` passed. Docker cargo check --tests was started but still compiling dependencies at report time.
Concerns: broad mutation publication integration test from brief was not added; existing handlers with denial paths still use non-publishing audit as intended. Certificate/host validation denials retain prior behavior (no audit on some malformed requests).

## Review fixes

- Replaced all state-aware `audit::record(&s.db, ...)` and
  `audit::record(&state.db, ...)` calls in auth and control-plane handlers with
  `audit::record_state`, so denial/failure audit paths publish the realtime
  `audit` invalidation. The pool-only helper remains for low-level callers.
- Domain events remain success-only; denial paths emit no domain change event.
- Added `publishes_domain_events_without_secrets`, covering successful user
  creation (`audit` and `users.changed`) and an invalid denied mutation (`audit`
  only), with assertions that serialized events contain no passwords, setup
  tokens, private key material, or PEM blocks.
- Adjusted the SSE ID assertion to accept any monotonic ID after setup/login
  audit events consume earlier IDs.

## Verification

- `cargo test --locked --test control_plane_realtime` (Rust 1.88 Docker): 6 passed.
- `cargo test --locked --test control_plane_users --test control_plane_audit` (Rust 1.88 Docker): 13 passed.
- `git diff --check`: passed.
