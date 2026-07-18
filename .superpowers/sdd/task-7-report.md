# Task 7 report

Implemented the `bearust` CLI (`serve`, `validate`, `reload`), PID-file ownership and stale-PID replacement, reload signaling via SIGHUP, and Pingora service bootstrap wiring.

Evidence (Rust 1.84 Docker):

- `cargo fmt --all` completed.
- `cargo clippy --all-targets -- -D warnings` completed with exit 0.
- `cargo test --test reload --test websocket --test proxy_http` completed: 8 passed, 1 ignored.

Concerns: Pingora's `run_forever` owns its process-wide lifecycle, so signal-driven graceful shutdown/reload orchestration remains delegated to Pingora/process signal handling; the CLI keeps the runtime store alive for the server lifetime. Process-level lifecycle tests were not added in this worktree because no stoppable Pingora API is exposed by the current dependency.

Follow-up remediation (commit 17913e5):

- Added an explicit Unix signal loop in `reload::signal_loop`: SIGHUP calls `RuntimeStore::reload` and logs/rejects invalid candidates without replacing the active snapshot; SIGINT/SIGTERM stop health workers with a bounded graceful-shutdown timeout.
- `cli::serve` now runs Pingora in a blocking task while the Tokio runtime owns lifecycle signals and waits for server task completion.
- PID-file writes now call `sync_all` after flush for durable ownership metadata.
- Added CLI contract tests for validate, actionable missing config errors, and version output.

Verification (Rust 1.84 Docker): `cargo fmt --all`, `cargo test --all-targets`, and `cargo clippy --all-targets -- -D warnings` all passed.
- Added `tests/shutdown.rs`, which drives the real Tokio SIGHUP/SIGTERM handlers and verifies invalid reload preservation plus clean worker shutdown.

Test-quality remediation:

- `tests/reload_pid.rs` now uses the Cargo-provided executable path, cleans child processes on panic, covers live-PID acquisition rejection, malformed PID replacement, and stale replacement.
- `PidFileGuard::acquire` now uses create-if-absent first and inode-stable stale-file removal to reduce stale-owner replacement races.
- `tests/shutdown.rs` includes a real TCP backend with a 200ms response, checks listener refusal after SIGTERM, and asserts the drained response and child status.

Verification (Rust 1.84 Docker): `cargo fmt --all` and `cargo test --test reload_pid` passed (6 tests). The process-level shutdown test reaches Pingora's graceful listener shutdown but Pingora 0.8.1's `Server::run` does not return after the service runtime exits, so its 2-second process-exit assertion currently fails; this is reported as an upstream/runtime integration limitation rather than hidden.
