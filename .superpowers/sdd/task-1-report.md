# Phase 7B Task 1 report

## Status

Complete. Added the bounded bot-protection domain model, immutable snapshot
compiler, deterministic evaluator, keyed request fingerprint, and integration
module export. Follow-up hardening addressed trusted-crawler bypasses,
post-filter header bounds, score aggregation, empty keys, and UTF-8 path
canonicalization.

## Changes

- Canonicalized method/path and bounded all request fields and allowlisted
  headers; invalid or oversized contexts cannot produce blocking signals.
- Added stable signal categories, capped rule weights, deterministic category
  ordering, and monitor/challenge/block action mapping.
- Added trusted crawler matching with strict non-empty user-agent and Host
  predicates (without X-Forwarded-For/IP bypass), bounded trusted-rule count,
  and snapshot validation for threshold, TTL, fingerprint key, required
  predicates, and rule field limits. Numeric IP hosts are rejected as crawler
  identities.
- Applied the header cap after allowlist filtering, capped aggregate score at
  100, and made percent-decoded paths UTF-8 safe.
- Added focused domain tests for canonicalization, fingerprinting, trusted
  crawler rejection cases, header bounds, score caps, action mapping, and
  snapshot limits.

## Commit

`97bd12b feat: add bounded bot evaluator`

`b2b54e4 fix: harden bounded bot evaluator predicates`

`533c70d fix: reject unsafe trusted crawler identities`

## Verification

- Docker Rust 1.88 (`cargo test --locked --test bot_protection`) passed (8/8
  tests) after the final review fixes.
- `git diff --check` passed.
- The focused source and test changes are committed and the worktree is clean.

## Concerns

No blocking concerns remain. Trusted-crawler domain matching is deliberately
local and does not perform DNS lookups; runtime integration must supply a
normalized Host hostname when evaluating an exception.
