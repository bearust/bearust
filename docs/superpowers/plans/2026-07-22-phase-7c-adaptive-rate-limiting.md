# Phase 7C Adaptive Rate Limiting Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a bounded token-bucket rate limiter with monitor/block modes, authenticated control-plane management, safe client identity extraction, and redacted telemetry.

**Architecture:** Add a pure `rate_limit` module for policy validation and token-bucket math, plus a bounded concurrent runtime store. Attach the store and immutable policy snapshot to `BeaRustProxy`; evaluate it after WAF/bot decisions and before upstream selection. Extend the existing control-plane repository, router, audit, realtime, and frontend patterns rather than introducing a second configuration system.

**Tech Stack:** Rust, Tokio, ArcSwap, Axum, SQLx SQLite migrations, Pingora, React/TypeScript, Vitest.

## Global Constraints

- Monitor-only is the default and must never reject traffic.
- Only trusted proxy peers may influence forwarded client identity.
- State is bounded, process-local, and reset on restart.
- Audit, SSE, and UI payloads must not contain raw IPs, request bodies, headers, credentials, or tokens.
- Existing WAF and bot-protection precedence remains unchanged.

### Task 1: Pure policy and token-bucket engine

**Files:**
- Create: `src/rate_limit.rs`
- Modify: `src/lib.rs`
- Test: `tests/rate_limit.rs`

**Interfaces:**
- `RateLimitAction::{Monitor, Block}`
- `RateLimitKeyScope::ProxyHostIp`
- `RateLimitPolicy::validate() -> Result<(), RateLimitConfigError>`
- `TokenBucket::try_consume(now: Instant, cost: u32) -> Decision`

- [ ] Write tests for default policy, bounds, burst capacity, refill, zero/overflow clock deltas, and bounded `Retry-After` calculation.
- [ ] Run `cargo test --test rate_limit` and confirm the new tests fail before implementation.
- [ ] Implement constants, serde-compatible policy types, deterministic monotonic token math, and generic decision metadata.
- [ ] Run the targeted test until all cases pass; run `cargo fmt --check`.
- [ ] Commit `feat: add bounded rate limit engine`.

### Task 2: Bounded runtime store and identity extraction

**Files:**
- Create: `src/rate_limit_store.rs`
- Modify: `src/lib.rs`
- Test: `tests/rate_limit_store.rs`

**Interfaces:**
- `RateLimiterStore::new(max_entries: usize, idle_ttl: Duration)`
- `RateLimiterStore::evaluate(key: RateLimitKey, policy: &RateLimitPolicy, now: Instant) -> Decision`
- `client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &IpNetSet) -> IpAddr`

- [ ] Add tests proving untrusted forwarding headers are ignored, trusted peers select the validated forwarded address, entries are evicted at TTL/capacity, and concurrent calls remain bounded.
- [ ] Implement a lock-protected map with deterministic eviction and no unbounded allocations; hash/redact keys only for telemetry.
- [ ] Run targeted store tests and `cargo clippy --test rate_limit_store -- -D warnings`.
- [ ] Commit `feat: add bounded rate limiter store`.

### Task 3: Proxy enforcement and telemetry

**Files:**
- Modify: `src/proxy.rs`
- Modify: `src/runtime.rs` or snapshot/config wiring as required
- Test: `tests/proxy_rate_limit.rs`

**Interfaces:**
- `BeaRustProxy::with_rate_limiter(store: Arc<RateLimiterStore>)`
- `RequestContext.rate_limit_decision: Option<RateLimitDecision>`

- [ ] Add failing integration tests for monitor pass-through, block `429`, generic response body, `Retry-After`, WAF/bot precedence, and telemetry redaction.
- [ ] Evaluate only after WAF and bot decisions and before upstream lease creation; use normalized route host and safely extracted client IP.
- [ ] Emit bounded `rate_limit_detection` telemetry and preserve existing completion/error contracts.
- [ ] Run `cargo test --test proxy_rate_limit --test proxy_waf --test proxy_bot`.
- [ ] Commit `feat: enforce adaptive rate limiting in proxy`.

### Task 4: Persistence and authenticated admin API

**Files:**
- Create: `migrations/0006_rate_limit.sql`
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/repository.rs`
- Modify: `src/control_plane/mod.rs`
- Test: `tests/control_plane_rate_limit.rs`

**Interfaces:**
- `GET/PATCH /api/rate-limit/config`
- `RateLimitConfigPatch { enabled, action, capacity, refill_per_second, key_scope }`
- `repository::{get_rate_limit_config, update_rate_limit_config}`

- [ ] Add migration and repository tests for idempotent defaults and strict bounds.
- [ ] Add admin-only GET/PATCH routes with `deny_unknown_fields`, atomic validation, redacted audit event, and SSE invalidation.
- [ ] Wire reload to publish the immutable active policy without partially applying invalid input.
- [ ] Run control-plane targeted tests, migration checks, RBAC tests, and `cargo clippy --all-targets -- -D warnings`.
- [ ] Commit `feat: add rate limit control plane`.

### Task 5: TOML configuration and frontend controls

**Files:**
- Modify: `src/config/mod.rs`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/ui.tsx`
- Create/modify: `frontend/src/rateLimit.test.tsx`
- Modify: `docs/PRD.md`, `README.md`, `DEPLOY.md`

- [ ] Add strict TOML parsing/validation for the rate-limit policy and fixtures covering defaults and rejection bounds.
- [ ] Add an admin dashboard card with monitor/block selector, enable toggle, capacity/refill fields, loading/error states, accessible labels, and SSE-triggered refresh.
- [ ] Ensure viewer/operator roles cannot mutate policy and UI never renders raw telemetry identifiers.
- [ ] Run frontend tests/build and Rust config tests.
- [ ] Commit `feat: add rate limit configuration UI and docs`.

### Task 6: Final verification and completion review

**Files:**
- Modify: `.superpowers/sdd/progress.md`
- Create: `.superpowers/sdd/phase7c-final-review.md`
- Modify: `docs/PRD.md`

- [ ] Run `cargo +stable test --all-targets`, `cargo +stable clippy --all-targets -- -D warnings`, `cargo +stable fmt --check`, frontend test/build, Compose config checks, and diff checks.
- [ ] Review denial precedence, memory bounds, trusted-proxy parsing, race behavior, and redaction with a fresh security pass.
- [ ] Document deferred per-route, adaptive tuning, CAPTCHA, persistence, and cross-node work.
- [ ] Commit `docs: complete phase 7c adaptive rate limiting`.
