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
## Status

Complete. Added the process-local bounded realtime hub and wired it into `AppState`.

## Commit

- `bffdef78a1edea55c396318f2c47fc047533eddb` — `feat: add control plane realtime hub`

## Tests

- TDD red-phase command: `cargo test --test control_plane_realtime hub_assigns_monotonic_ids_and_drops_slow_subscribers_without_blocking`
  - Could not execute locally because `cargo` is not installed.
- Focused Docker command (Rust 1.88): same test command with `rust:1.88-bookworm`.
  - Build reached dependency compilation but failed before compiling the crate because the image does not include `cmake` (`libz-ng-sys` build script: `cmake: No such file or directory`).
- `git diff --check`: passed.

## Self-review

- `RealtimeHub` uses a bounded Tokio broadcast channel, an atomic monotonic sequence, millisecond RFC3339 UTC timestamps, and non-blocking publish semantics.
- `RealtimeEvent` is cloneable and serde serializable, with only safe invalidation metadata.
- `AppState` initializes a 256-event hub through `build_state`; `build_state_with_acme` inherits the same initialized hub.
- No Task 2+ endpoint or frontend changes were made.

## Concerns

- The focused test still needs to be rerun in an environment with Cargo and CMake available (or a prebuilt dependency cache). The implementation is otherwise limited to the requested Task 1 scope.

## Review Fix: `RealtimeHub` ownership type

### Status

Complete. Changed `RealtimeHub::new` to return `Self` (instead of `Arc<Self>`) and retained `Arc::new(...)` at the `AppState` construction site, avoiding an accidental `Arc<Arc<RealtimeHub>>` and restoring the intended public constructor interface.

### Commit

Pending until this fix is committed.

### Verification

- Focused Docker command: `docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked --test control_plane_realtime`
- Result: unable to compile because the `rust:1.88-bookworm` image does not include `cmake`; `libz-ng-sys` failed with `cmake: No such file or directory` before crate tests ran.
- `git diff --check`: passed.
