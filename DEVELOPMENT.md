# Development

Native development needs Rust 1.84.1, Cargo, clang, cmake, make, perl, and pkg-config. Without local Rust, run `docker compose -f docker-compose.dev.yml up --build`; the repository and Cargo caches are mounted and cargo-watch reruns the server.

Tests in `src/` and `tests/` cover routing, balancing, health, reload, logs, HTTP, WebSocket, and shutdown. Use `cargo test --locked`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings`.

Focused TDD: add a minimal regression test, run it to observe failure, implement the smallest change, then rerun the focused test and the full suite.
