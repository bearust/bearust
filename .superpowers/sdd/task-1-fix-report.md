# Task 1 Fix Report — Oversized request cost

## Status

Complete. Commit: `918ac97` (`fix: bound oversized rate limit costs`).

## Finding and fix

`TokenBucket::try_consume` now explicitly rejects a cost greater than bucket
capacity with a bounded `Decision::Limited` and `MAX_RETRY_AFTER`. Such a cost
can never become admissible through refill, so this avoids futile retry loops
and preserves bucket state.

## Verification

- Added `cost_above_capacity_is_bounded_and_never_admitted`.
- `rustfmt --check src/rate_limit.rs tests/rate_limit.rs` — passed.
- `git diff --check` — passed.
- `cargo test --test rate_limit` remains unavailable in this environment:
  Cargo 1.84.1 cannot parse cached `clap_lex 1.1.0`, which requires unstable
  `edition2024` support.
