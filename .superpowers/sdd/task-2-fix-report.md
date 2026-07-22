# Task 2 review fixes

## Historical changes

- Added challenge-mode selection to `AcmeTransport`, with explicit HTTP-01 or
  DNS-01 selection and per-authorization token metadata for SAN orders.
- DNS-01 issuance accepts multi-SAN requests and computes one TXT value per
  authorization; CSR generation includes all requested SANs.
- Secret-store roots reject symlinks and malformed persisted credentials.
- ACME polling/finalization remains bounded by the client operation deadline.

## Historical verification

The ACME and frontend focused tests were run by the earlier Task 2 agent. The
legacy `new_order` API remains source-compatible and rejects multi-host calls;
the production manager uses the explicit challenge-aware path.

---

# Phase 7C Task 2 review-fix report

## Changes

- Replaced the invalid `refill_per_second = 0.0` eviction fixture with the
  smallest valid policy value (`0.001`), so the capacity and idle-TTL checks
  execute instead of taking the invalid-policy fail-open path.
- Added `MAX_STORE_ENTRIES` (100,000) and clamp `RateLimiterStore::new` input
  to that bound, preventing accidental unbounded HashMap growth.
- Removed `expect`-based panic paths from evaluation and length inspection;
  poisoned mutexes are recovered and bucket construction fails open.
- Exposed `RateLimiterStore::len` for boundedness/telemetry checks and added a
  regression test for max-entry clamping.

## Verification

Commands run:

```text
rustfmt --edition 2021 src/rate_limit_store.rs tests/rate_limit_store.rs
git diff --check
cargo +stable test --test rate_limit_store
```

Result:

```text
running 6 tests
test result: ok. 6 passed; 0 failed
```

`cargo fmt --all -- --check` remains noisy because unrelated pre-existing
files in this shared worktree are not rustfmt-clean; only the touched files
were formatted.
