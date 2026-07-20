# Task 2 commit rollback report

## Change made
- Updated `src/control_plane/repository.rs` so both explicit `COMMIT` paths in `delete_role` attempt `ROLLBACK` if `COMMIT` fails, then return the original commit error.
- Preserved `BEGIN IMMEDIATE` and the existing rollback behavior on all other early-return paths.
- Added a regression test in `tests/control_plane_roles.rs` that forces a busy commit condition with a second SQLite connection and now asserts the role remains present after the blocker is released.
- This closes the remaining review gap by checking role preservation after the lock is released, not just the error path.

## Verification
- Attempted to run `cargo test -q --test control_plane_roles -- --nocapture`.
- Result: `cargo` is unavailable in this environment (`/bin/bash: cargo: command not found`).

## Notes
- The fix is limited to the two explicit commit sites in `delete_role`.
- No unrelated behavior changes were introduced.
