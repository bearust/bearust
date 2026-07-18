### Task 6 report

Implemented Pingora proxy integration and forwarding semantics in `src/proxy.rs`, `src/observability.rs`, and `src/runtime.rs`.

Evidence (Rust 1.84.1 Docker toolchain):

- `docker run --rm -v "$PWD":/app -w /app rust:1.84-slim cargo test --all-targets` — passed; 2 unit tests and 30 integration tests.
- `docker run --rm -v "$PWD":/app -w /app rust:1.84-slim cargo clippy --all-targets -- -D warnings` — passed.
- `docker run --rm -v "$PWD":/app -w /app rust:1.84-slim cargo fmt --all -- --check` — passed after formatting.

Behavior covered:

- `http_service` constructs a real Pingora `Service` from `BeaRustProxy` for runtime wiring.
- Route-selected pools are used directly; no dummy peer is created when no backend is healthy, and the request returns a clean 503 error.
- Pool connect/read/write timeouts are applied to `HttpPeer::options`.
- `X-Forwarded-For` appends client IP without a port, including bracketed IPv6; `Host`, `X-Forwarded-Proto`, and validated request IDs are preserved/set.
- Failover state excludes the failed backend and permits exactly one retry only before upstream transmission; `error_while_proxy` disables retries once transmission begins. `BackendLease` remains RAII-released on every path.
- Structured request completion logging includes request ID, method, path, status, and duration.

The full local-process HTTP/WebSocket harness depends on Task 7's binary and listener lifecycle; direct proxy/upgrade header tests are included in `tests/proxy_http.rs` and `tests/websocket.rs`.
