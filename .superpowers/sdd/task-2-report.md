# Task 2 report: bounded runtime store and identity extraction

Status: implementation complete; integration verification is pending Task 1 API merge.

Commit: `1ac792d feat: add bounded rate limiter store`

Implemented `RateLimiterStore` with a mutex-protected `HashMap`, idle-TTL cleanup, deterministic oldest-entry eviction, explicit maximum cardinality, and monitor/fail-open behavior for disabled or invalid policies. Added `IpNetSet` CIDR matching and `client_ip` extraction that ignores forwarding headers from untrusted peers and accepts validated `Forwarded`/`X-Forwarded-For` addresses only from trusted networks. Added unit tests for trust boundaries, TTL/capacity eviction, concurrent bounded calls, and monitor defaults.

Verification:

- `rustfmt --edition 2021 src/rate_limit_store.rs tests/rate_limit_store.rs src/lib.rs` passed.
- `git diff --check` passed for the task files.
- Targeted Cargo tests and Clippy could not run in this worktree before Task 1's `rate_limit` module/API was available; run `cargo test --test rate_limit_store` and `cargo clippy --test rate_limit_store -- -D warnings` after cherry-picking Task 1.

Concern: `src/lib.rs` had concurrent Task 1 edits in the shared workspace, so the store module declaration was not included in this isolated commit. Add `pub mod rate_limit_store;` when integrating (the current working tree already contains it).
