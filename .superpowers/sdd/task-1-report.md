# Task 1 Report — Pure policy and token-bucket engine

## Status

Complete. Commit: `7365f2f` (`feat: add bounded rate limit engine`).

## Implementation

- Added serde-compatible `RateLimitPolicy`, monitor/block actions, proxy-host/IP
  key scope, strict bounds, and validation errors.
- Added shared `RateLimitKey` and deterministic monotonic `TokenBucket` math.
- Decisions expose bounded remaining-token metadata and a bounded `Retry-After`.
- Added focused tests for defaults, bounds, burst consumption, refill, zero and
  backwards clock deltas, and retry-after clamping.

## Verification

- `rustfmt --check src/rate_limit.rs tests/rate_limit.rs` — passed.
- `git diff --cached --check` — passed.
- `cargo test --test rate_limit` — unable to run in this environment: the
  installed Cargo 1.84.1 cannot parse cached `clap_lex 1.1.0`, which requires
  the unstable `edition2024` feature. No source/test failure was observed.

## Concerns / follow-up

The runtime store should use `RateLimitKey`, `TokenBucket::from_policy`, and the
`Decision` variants exported by `rate_limit`.
