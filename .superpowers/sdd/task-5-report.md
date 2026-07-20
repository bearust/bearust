# Task 5 report

Implemented administrative session revocation.

- Added `POST /api/users/{id}/sessions/revoke` using centralized `Permission::SessionsRevoke` authorization.
- Rejects self-targeting, handles missing users and database failures with generic responses, revokes active sessions only, and returns `{ "revoked": <count> }`.
- Added safe `sessions_revoked` and `session_revoke_denied` audit events without token/session material.
- Added repository and HTTP-focused tests.

Verification: `cargo` is unavailable in the environment (`/bin/bash: cargo: command not found`), so focused tests could not run. `git diff --check` passed.

Commit: `f2a4444 feat: add administrative session revocation`
