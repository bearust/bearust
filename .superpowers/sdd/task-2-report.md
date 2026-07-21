# Task 2 Report: Authenticated SSE endpoint

## Status

Complete. Commit: `1f4e03a` (`feat: expose authenticated realtime event stream`).

## Changes

- Registered `GET /api/events` in the control-plane router.
- Authenticates with the existing session cookie and returns the existing JSON error envelope with HTTP 401 when unauthenticated.
- Emits an initial `ready` SSE event, forwards realtime hub events with monotonic SSE IDs and JSON payloads, and emits a `reconnect` event when the broadcast receiver lags.
- Explicitly ignores `Last-Event-ID` because the process-local hub has no replay buffer.
- Configured a 15-second SSE comment heartbeat and `Cache-Control: no-cache, no-transform`.
- Added `futures-util` as a runtime dependency for the async stream adapter.
- Added focused endpoint tests covering authentication, headers, ready/event frames, and no-replay behavior.

## Verification

- TDD red phase: `cargo test --test control_plane_realtime events_endpoint` initially failed because the route was not registered; after implementation it exposed and fixed the cache-control header assertion.
- Final focused test (Docker, Rust 1.88):

  ```text
  running 2 tests
  test events_endpoint_requires_auth_and_streams_ready_and_published_events ... ok
  test events_endpoint_ignores_last_event_id_and_does_not_replay_history ... ok

  test result: ok. 2 passed; 0 failed
  ```

- `git diff --check`: passed.
- `cargo fmt -- --check`: unavailable in the Rust 1.88 Docker image (`cargo-fmt` component not installed); no formatting command was run.

## Self-review and concerns

- Authentication occurs before subscribing, so unauthorized requests do not consume hub resources.
- The endpoint deliberately does not replay historical events; clients must refresh their state after the `ready` frame and on `reconnect`.
- Stream termination on broadcast closure is graceful. Live session revocation behavior remains governed by the existing session checks on subsequent requests/reconnects and is outside this task's endpoint scope.

## Review fix: live session revalidation

The endpoint now revalidates the captured session with the centralized
`current(&state, &headers)` helper every 15 seconds. Revalidation runs in the
same `tokio::select!` as the broadcast receiver, so event delivery remains
non-blocking; an invalid or revoked session terminates the stream. Existing
ready, event, reconnect, no-replay, headers, and bounded broadcast behavior is
preserved. A heartbeat comment is emitted on successful revalidation.

Added `events_stream_closes_after_session_revocation`, which revokes the
authenticated session and verifies the body reaches end-of-stream on the next
revalidation interval.

Verification (Docker, Rust 1.88):

```text
cargo test --locked --test control_plane_realtime events_endpoint
test result: ok. 2 passed; 0 failed; ... finished in 0.63s

cargo test --locked --test control_plane_realtime events_stream_closes_after_session_revocation
test result: ok. 1 passed; 0 failed; ... finished in 15.62s

git diff --check
passed with no output
```
