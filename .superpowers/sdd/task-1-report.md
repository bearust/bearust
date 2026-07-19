# Task 1 Report: User account lifecycle repository operations

## Status

Implemented and committed. Added the `disabled` account status with an idempotent migration, disabled-account authentication filtering, password-free user listings, role/status lifecycle operations, active-admin protection, and session revocation on disable/delete.

## Commit

- `efa31c574a16d77df6eaa45afd496a33d898247c` (`feat: add user lifecycle repository operations`)

## Verification

- Focused repository suite: `4 passed; 0 failed`.
- Full backend suite: passed; all unit, integration, and doc tests passed.
- Commands used both with `RUSTUP_TOOLCHAIN=1.88.0` and `CARGO_BUILD_JOBS=1` in `rust:1.88-bookworm`.

## Concerns

- `UserCreate`, `UserPatch`, and `UserSummary` are defined for the follow-on API task; password handling remains outside repository response types.
- Repository lifecycle mutations reject demoting, disabling, or deleting the last active administrator.

## Review fixes

- `insert_user` now parses and canonicalizes roles through `Role::parse`; invalid role values are rejected before any insert.
- User and ACME column migrations now ignore only SQLite duplicate-column errors and return all other ALTER failures.
- Last-admin-sensitive role, disable, and delete operations now use SQLite `BEGIN IMMEDIATE`, preventing concurrent writers from passing the active-admin check simultaneously; failed invariants explicitly roll back.
- Added a focused regression assertion that invalid roles cannot be inserted.

## Review-fix verification

Focused command:

```text
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked --test control_plane_repository
```

Result: `4 passed; 0 failed`.

Full command:

```text
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked
```

Result: all unit, integration, and doc tests passed; one pre-existing long-running proxy test remains ignored.
