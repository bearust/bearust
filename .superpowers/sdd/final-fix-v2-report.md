# Phase 4D.2 final review fixes

- Background ACME renewals now attach to the control-plane realtime hub and publish `certificates.changed` only after a successful renewal and configuration reload. The hook is optional for embedded certificate-service callers and never exposes renewal errors.
- Successful user role/disabled updates publish `sessions.changed` alongside `users.changed`, ensuring connected clients refresh `/api/auth/me` and session authorization. Successful role permission updates also publish `sessions.changed`.
- Added a realtime integration assertion covering the user-disabled mutation event sequence.

Verification:

- `cargo test --locked --test control_plane_realtime --test control_plane_users --test control_plane_roles` (Docker, Rust 1.88): passed.
- `cargo test --locked --test control_plane_realtime` (Docker, Rust 1.88): passed (6 tests).
- `git diff --check`: passed.
