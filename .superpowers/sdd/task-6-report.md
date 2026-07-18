### Task 6 report

Implemented `src/proxy.rs` and `src/observability.rs`, exported from `lib.rs`.

Evidence:
- `docker run --rm -v "$PWD":/app -w /app rust:1.84 cargo check` passed.
- `docker run --rm -v "$PWD":/app -w /app rust:1.84 cargo test --lib` passed (request ID validation test).

Concerns:
- Runtime binary/integration harness is not present in this worktree, so local-process HTTP/WebSocket tests were not added.
- Pingora peer timeout and retry hooks require additional API wiring; current callbacks select healthy leases, preserve Host, add forwarding/request ID headers, and release leases in logging.
