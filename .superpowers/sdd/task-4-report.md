# Task 4 report: Phase 4B documentation and verification

## Documentation

- Updated `README.md` with the setup-to-admin transition and one-time setup example.
- Documented `GET/POST /api/users`, `PATCH /api/users/{id}`, and `DELETE /api/users/{id}`, including response shape and error codes.
- Documented the fixed `admin`/`operator`/`viewer` role matrix, disabled-account login/session behavior, last-admin and self-mutation protections, and redacted audit events.
- Clarified the Phase 4B boundary (local users and fixed RBAC) versus Phase 4C (audit-log viewer/filtering), plus out-of-scope per-host permissions, custom permissions, and SSO.

## Verification

All required commands exited with status 0:

```text
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked
  result: 0 failed; all unit, integration, and doc tests passed (including 3 control_plane_users tests and 4 control_plane_repository tests)

npm test --prefix frontend -- --run
  Test Files 2 passed; Tests 10 passed

npm run build --prefix frontend
  tsc -b and vite build passed; production bundle emitted

git diff --check
  passed
```

## Completion review and gap

The Phase 4B design's user CRUD, role validation, admin-only API/UI, setup invariant, disabled-account behavior, session invalidation, last-admin/self-mutation protection, secret redaction, audit events, and frontend flows are implemented and covered by the current tests.

One design completion criterion remains only partially evidenced: the backend test suite does not contain explicit regression assertions that an operator can write proxy hosts/certificates while a viewer receives `403` on each existing write route. The route handlers use the centralized RBAC checks and the existing suite passes, but dedicated role-regression tests should be added before declaring Phase 4B complete.

Therefore this task verifies documentation and build health; it does not mark Phase 4B complete.

Documentation commit: `8349e40 docs: document phase 4b user management`.

## Regression gap closure

- Added `operator_can_write_hosts_and_certificates_while_viewer_is_read_only` to `tests/control_plane_users.rs`. It exercises successful operator proxy-host creation, update (`PATCH`), and deletion (`DELETE`), with viewer `403 Forbidden` assertions for each existing host write route. It also exercises custom certificate upload and activation (`POST /api/certificates/{id}/activate`) as an operator, with viewer `403 Forbidden` assertions for activation and upload.
- Added `initial_setup_normalizes_email_like_admin_user_creation`, covering trimming and lowercasing of the first administrator email before persistence/login.
- Setup initialization now applies the same `trim().to_ascii_lowercase()` normalization already used by the admin user-creation endpoint.

Focused verification:

```text
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked --test control_plane_users
  5 passed; 0 failed

docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked
  all backend unit, integration, and doc tests passed

npm test --prefix frontend -- --run
  6 tests passed

npm run build --prefix frontend
  tsc -b and vite build passed

git diff --check
  passed
```
