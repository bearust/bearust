# Phase 7B Bot Protection Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded deterministic bot detection, signed challenges, trusted-crawler CRUD/admin controls, while preserving monitor-only as the default. Runtime crawler bypass is deferred until cryptographically signed ingress metadata is implemented.

**Architecture:** A new `bot_protection` domain module evaluates a bounded request context against an immutable `BotSnapshot`. A `BotStore` publishes snapshots and redacted telemetry, while control-plane handlers persist policy/rules and expose challenge verification. The proxy combines bot action with the existing WAF decision, with explicit WAF blocks remaining dominant.

**Tech Stack:** Rust 1.88, Axum, Pingora, SQLx migrations, ArcSwap, HMAC-SHA256, Serde/TOML, React/TypeScript, Vitest.

## Global Constraints

- Monitor-only is the default for fresh installs and upgrades.
- No external network calls, DNS lookups, machine learning, or unbounded allocation in the request path.
- Raw IP addresses, User-Agent values, cookies, bodies, authorization values, and signing keys never enter audit/realtime payloads.
- All admin mutations use existing RBAC and publish redacted audit plus `bot.changed` realtime events.
- Existing WAF explicit block decisions remain dominant over bot actions.
- Challenge inputs, token fields, rule counts, and proof-of-work are strictly bounded.

---

### Task 1: Bot domain model, bounded evaluator, and immutable snapshot

**Files:**
- Create: `src/bot_protection.rs`
- Modify: `src/lib.rs`
- Test: `tests/bot_protection.rs`

**Interfaces:**
- Consumes: request method/path/selected headers and persisted `BotConfig`/`BotRule` values.
- Produces: `BotMode`, `BotInspectionContext`, `BotEvaluation`, `BotAction`, `BotSnapshot`, `compile_snapshot`, and `evaluate` for Tasks 2–5.

- [ ] **Step 1: Write failing unit tests** for canonicalization, bounded fingerprinting, deterministic scores, trusted-crawler matching, and monitor/challenge/block action mapping.
- [ ] **Step 2: Run `cargo test --test bot_protection`** and verify the new tests fail because the domain module is absent.
- [ ] **Step 3: Implement the bounded evaluator** with fixed header allowlist, maximum field sizes, keyed fingerprint hashing, capped signal weights, and stable category identifiers. Invalid/oversized values must produce no blocking-only signal.
- [ ] **Step 4: Implement immutable `BotSnapshot` compilation** with validation for mode, threshold, TTL, and trusted-rule limits.
- [ ] **Step 5: Run `cargo test --test bot_protection`** and verify all domain tests pass.
- [ ] **Step 6: Commit** with `git add src/bot_protection.rs src/lib.rs tests/bot_protection.rs && git commit -m "feat: add bounded bot evaluator"`.

### Task 2: Persistence, migration, and BotStore reload/telemetry

**Files:**
- Create: `migrations/<next>_bot_protection.sql`
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/repository.rs`
- Create or modify: `src/bot_store.rs`
- Modify: `src/lib.rs`
- Test: `tests/bot_repository.rs`

**Interfaces:**
- Consumes: Task 1 `BotConfig`, `BotRule`, and `compile_snapshot`.
- Produces: repository functions `get_bot_config`, `update_bot_config`, `list_bot_rules`, `insert_bot_rule`, `update_bot_rule`, `delete_bot_rule`, and `BotStore::{load,snapshot,reload,record_detection}`.

- [ ] **Step 1: Write failing SQLx tests** asserting monitor defaults, idempotent migration, rule normalization, bounded limits, and atomic reload failure behavior.
- [ ] **Step 2: Run `cargo test --test bot_repository`** and verify failures identify missing schema/repository APIs.
- [ ] **Step 3: Add the portable migration** for singleton bot configuration and trusted crawler rules, including defaults and uniqueness constraints.
- [ ] **Step 4: Add model and repository validation** so malformed mode, threshold, TTL, patterns, and oversized lists return control-plane errors without partial writes.
- [ ] **Step 5: Implement `BotStore`** using ArcSwap and redacted audit/realtime emission; reload must publish only after complete compilation.
- [ ] **Step 6: Run the repository tests and `cargo test --all-targets`**; verify they pass.
- [ ] **Step 7: Commit** with `git add migrations src/control_plane/models.rs src/control_plane/repository.rs src/bot_store.rs src/lib.rs tests/bot_repository.rs && git commit -m "feat: persist bot protection policy"`.

### Task 3: Admin policy and trusted-crawler API

**Files:**
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/rbac.rs`
- Test: `tests/control_plane_bot.rs`
- Modify: `frontend/src/api.ts`

**Interfaces:**
- Consumes: Task 2 repository and `BotStore` APIs.
- Produces: `GET/PATCH /api/bot/config`, CRUD `/api/bot/trusted-crawlers`, and WAF-compatible TOML import/export fields.

- [ ] **Step 1: Write failing endpoint tests** for admin authorization, monitor default, validation errors, CRUD, redacted audit, and `bot.changed` events.
- [ ] **Step 2: Run `cargo test --test control_plane_bot`** and verify endpoint failures.
- [ ] **Step 3: Implement handlers** with existing error envelopes, RBAC permission checks, atomic persistence/reload, and bounded Serde/TOML payloads.
- [ ] **Step 4: Add API client types/functions** for policy and crawler management without exposing secret material.
- [ ] **Step 5: Run endpoint tests and existing control-plane tests**; verify all pass.
- [ ] **Step 6: Commit** with `git add src/control_plane frontend/src/api.ts tests/control_plane_bot.rs && git commit -m "feat: add bot policy admin api"`.

### Task 4: Signed challenge issuance and verification

**Files:**
- Create: `src/bot_challenge.rs`
- Modify: `src/control_plane/mod.rs`
- Modify: `src/secrets.rs`
- Test: `tests/bot_challenge.rs`

**Interfaces:**
- Consumes: Task 1 fingerprint/action types and Task 2 secret/configuration access.
- Produces: bounded `Challenge`, `issue_challenge`, `verify_solution`, and `signed_token` helpers plus challenge HTTP endpoints used by Task 5.

- [ ] **Step 1: Write failing tests** for issuance, valid proof-of-work, expiry, tampering, wrong fingerprint, replay, maximum attempts, and generic failure responses.
- [ ] **Step 2: Run `cargo test --test bot_challenge`** and verify failures.
- [ ] **Step 3: Implement HMAC-SHA256 token format** with version, nonce hash, fingerprint prefix, issue/expiry timestamps, and bounded proof-of-work difficulty. Store only one-time nonce digests with expiry.
- [ ] **Step 4: Add challenge endpoints** that set Secure/HttpOnly/SameSite cookie attributes and never serialize the signing key or raw request data.
- [ ] **Step 5: Run challenge tests and Clippy for the touched targets**; verify pass with `-D warnings`.
- [ ] **Step 6: Commit** with `git add src/bot_challenge.rs src/control_plane/mod.rs src/secrets.rs tests/bot_challenge.rs && git commit -m "feat: add signed bot challenges"`.

### Task 5: Proxy integration and WAF precedence

**Files:**
- Modify: `src/proxy.rs`
- Modify: `src/runtime.rs` or startup wiring that constructs `BearustProxy`
- Test: `tests/proxy_bot.rs`

**Interfaces:**
- Consumes: Task 1 `evaluate`, Task 2 `BotStore`, and Task 4 token verification.
- Produces: request-path enforcement where monitor forwards, challenge returns a non-cacheable challenge, valid tokens bypass challenge, and block returns `403`.

- [ ] **Step 1: Write failing proxy tests** for each mode, rejection of spoofed trusted-crawler markers, valid/invalid challenge cookie, WAF block dominance, and redacted telemetry.
- [ ] **Step 2: Run `cargo test --test proxy_bot`** and verify failures.
- [ ] **Step 3: Add bot context/evaluation fields to `RequestContext`** without retaining raw sensitive headers after evaluation.
- [ ] **Step 4: Evaluate bot policy before upstream selection**, skip challenge for valid tokens, and combine action with WAF so WAF block wins and bot challenge never forwards upstream.
- [ ] **Step 5: Emit bounded tracing/audit metadata** and ensure body buffering limits remain unchanged.
- [ ] **Step 6: Run proxy bot, WAF, and HTTP regression tests**; verify pass.
- [ ] **Step 7: Commit** with `git add src/proxy.rs src/runtime.rs tests/proxy_bot.rs && git commit -m "feat: enforce bot protection in proxy"`.

### Task 6: Admin dashboard controls and challenge UX

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/App.test.tsx`
- Modify: `docs/PRD.md`

**Interfaces:**
- Consumes: Task 3 API and Task 4 challenge response contract.
- Produces: policy mode/threshold/TTL controls, trusted-crawler CRUD, redacted status display, and a minimal proof-of-work challenge page.

- [ ] **Step 1: Write failing component tests** for monitor default, saving policy, crawler validation, and challenge completion/error states.
- [ ] **Step 2: Run the targeted Vitest suite** and verify failures.
- [ ] **Step 3: Implement controls using existing design-system/Tailwind v4 patterns**, with accessible labels, disabled/loading states, and no secret/token display.
- [ ] **Step 4: Update PRD Phase 7 status** to document delivered 7B scope and deferred CAPTCHA/adaptive rate limiting.
- [ ] **Step 5: Run frontend tests and `npm run build --prefix frontend`**; verify pass.
- [ ] **Step 6: Commit** with `git add frontend docs/PRD.md && git commit -m "feat: add bot protection dashboard"`.

### Task 7: Final verification and Phase 7B completion review

**Files:**
- Modify: `.superpowers/sdd/progress.md`
- Create: `.superpowers/sdd/phase7b-final-review.md`

- [ ] **Step 1: Run** `cargo +stable test --all-targets` and targeted bot/WAF/proxy suites; record exact results.
- [ ] **Step 2: Run** `cargo +stable clippy --all-targets --all-features -- -D warnings`, `git diff --check`, frontend tests/build, and both Compose config checks.
- [ ] **Step 3: Review telemetry and challenge code** for raw sensitive data, unbounded allocations, replay gaps, and mode precedence.
- [ ] **Step 4: Document any pre-existing formatting drift explicitly** rather than masking unrelated changes.
- [ ] **Step 5: Update the Phase 7B ledger and write the final review report** with commit range, tests, and deferred scope.
- [ ] **Step 6: Commit** with `git add .superpowers/sdd/progress.md .superpowers/sdd/phase7b-final-review.md && git commit -m "docs: complete phase 7b bot protection"`.

## Plan Self-Review

- Spec coverage: fingerprint/evaluator (Task 1), persistence/reload (Task 2), admin/RBAC/TOML (Task 3), signed challenge protocol (Task 4), proxy flow/WAF precedence (Task 5), UX/PRD status (Task 6), and verification/deferred scope (Task 7).
- Placeholder scan: no TODO, TBD, or unspecified “handle errors” steps; each task names files, interfaces, commands, and expected outcomes.
- Type consistency: Task 1 produces `BotSnapshot` and `evaluate`; Task 2 wraps it in `BotStore`; Tasks 3–5 consume those exact boundaries; Task 4 owns token helpers consumed by Task 5.
