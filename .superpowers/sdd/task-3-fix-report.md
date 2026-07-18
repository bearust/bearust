# Task 3 Fix Report

## Findings addressed

- Cloudflare challenge tracking previously stored one record ID per `(name,
  value)`, so concurrent ACME orders overwrote one another and leaked a TXT
  record during cleanup.
- Challenge cleanup now tracks a list of provider-created IDs and consumes one
  ID per cleanup call. Missing IDs remain a no-op, so pre-existing records are
  never deleted.
- Added deterministic local-server regression tests for partial `present`
  failure and concurrent identical challenges.

## Verification

The focused Cargo test could not be run in this environment because the
available Docker image does not contain `cargo` (`cargo: command not found`).
Run `cargo test --locked --test acme_dns01` (and the normal workspace checks)
in the Rust toolchain image before integration.
