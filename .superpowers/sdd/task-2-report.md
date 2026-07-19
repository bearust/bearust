# Task 2 report: admin user management API

## Status

Implemented and verified. The control plane now exposes admin-only user lifecycle endpoints:

- `GET /api/users`
- `POST /api/users`
- `PATCH /api/users/{id}`
- `DELETE /api/users/{id}`

Handlers authenticate through the existing session cookie and token hash, authorize through the centralized `UsersManage` permission, hash passwords with the existing Argon2 helper, and return redacted `User` summaries only. Input validation covers email, role, and minimum password length. Duplicate email, invalid input, missing users, forbidden access, last-active-admin violations, and self-disable/self-delete are mapped to stable error envelopes. Successful and denied mutations emit redacted audit events. Disabled accounts cannot authenticate because the existing repository login/session lookups exclude them; disabling also revokes active sessions through the Task 1 repository lifecycle API.

## Tests

Focused API tests:

```text
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked --test control_plane_users
2 passed; 0 failed
```

Full backend suite:

```text
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked
completed successfully with no failures
```

## Notes

Task 2 uses the repository's transactional last-admin checks for role demotion, disable, and deletion. The API rejects self-disable and self-delete before mutating state. The frontend Users screen remains Task 3.

## Review follow-up

Addressed review findings:

- Combined role/disabled PATCH updates now run in one `BEGIN IMMEDIATE` transaction, including last-admin validation, session revocation, and account update.
- User mutation audit records use redacted target metadata (`target_user_id` or `target=redacted`) and explicit reasons for success, authorization, validation, not-found, self-mutation, duplicate, and last-admin denials. Passwords and request secrets are never recorded.
- Expanded API coverage for operator/viewer 403 responses, disabled-login rejection, self/last-admin invariants, atomic PATCH behavior, and audit rows.

Focused test rerun:

```text
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked --test control_plane_users
3 passed; 0 failed
```

Full backend suite rerun:

```text
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked
completed successfully; all test targets passed with 0 failures
```
