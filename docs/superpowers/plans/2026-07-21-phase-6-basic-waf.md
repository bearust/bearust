# Phase 6 Basic WAF Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a safe, configurable in-process Basic WAF with built-in and custom signatures, monitor/block modes, audit events, TOML management, and dashboard controls.

**Architecture:** A database-backed control plane owns versioned WAF configuration and validates rules before publishing an immutable compiled snapshot. A shared `WafStore` exposes that snapshot to the Pingora proxy through `ArcSwap`; request inspection is bounded and synchronous in the data plane, while control-plane mutations publish existing SSE invalidation events.

**Tech Stack:** Rust 1.84, Pingora 0.8.1, Axum 0.8, SQLx 0.8 (SQLite/PostgreSQL/MySQL), `regex`, Serde/JSON, TOML 0.8, React/TypeScript, Vitest.

## Global Constraints

- Fresh installations default to global `monitor-only` mode.
- Per-rule actions are `inherit`, `allow`, `log`, or `block`; effective precedence is `block` > `log` > `allow`.
- Built-in rules are seeded idempotently and cannot be deleted or have their identity/source changed.
- Custom rule writes and TOML imports are validated and transactional; invalid input never replaces the active snapshot.
- Request body inspection is bounded and must not buffer an oversized body solely for WAF inspection.
- Security/audit records never include credentials, tokens, private data, full request bodies, or raw database errors.
- Existing proxy, RBAC, audit, SSE, and external-database tests must remain green.

---

### Task 1: Persist WAF configuration and seed built-in rules

**Files:**
- Create: `migrations/0004_basic_waf.sql`
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/repository.rs`
- Test: `tests/waf_repository.rs`

**Interfaces:**
- Produces `WafMode`, `WafAction`, `WafRule`, `WafConfig`, and repository functions `get_waf_config`, `update_waf_mode`, `list_waf_rules`, `insert_waf_rule`, `update_waf_rule`, `delete_waf_rule`, and `seed_builtin_waf_rules`.

- [ ] **Step 1: Write failing migration/repository tests** for a fresh SQLite database: default mode is `monitor-only`, four built-ins exist, seeding twice does not duplicate rows, and custom rule CRUD round-trips matcher JSON and timestamps.
- [ ] **Step 2: Run `cargo test --test waf_repository`** and confirm failures for missing schema/functions.
- [ ] **Step 3: Add `waf_config` and `waf_rules` tables** with portable SQL types, unique built-in keys, `source`, `category`, `severity`, `enabled`, `action`, `matcher_json`, and timestamps; add idempotent built-in inserts for SQLi, XSS, path traversal, and command injection.
- [ ] **Step 4: Implement typed models and SQLx repository functions** using the existing database abstraction and application-supplied IDs.
- [ ] **Step 5: Run `cargo test --test waf_repository`** and expect all repository tests to pass on SQLite.
- [ ] **Step 6: Commit with `git commit -m "feat: persist basic waf configuration"`.**

### Task 2: Build the bounded WAF matcher/evaluator

**Files:**
- Create: `src/waf.rs`
- Modify: `src/lib.rs`
- Test: `tests/waf_engine.rs`

**Interfaces:**
- Produces `InspectionContext`, `MatcherDefinition`, `CompiledRule`, `WafSnapshot`, `WafDecision`, and `evaluate(&WafSnapshot, &InspectionContext) -> Evaluation`.

- [ ] **Step 1: Write failing unit tests** for normalization, each built-in signature, disabled rules, per-rule actions, global monitor/block mode, and deterministic precedence.
- [ ] **Step 2: Run `cargo test --test waf_engine`** and confirm the evaluator types are absent.
- [ ] **Step 3: Implement bounded context extraction** for method, path, query, headers, and a body capped by `MAX_INSPECTION_BODY_BYTES`; reject unsupported fields and invalid regex definitions during compilation.
- [ ] **Step 4: Implement built-in matchers and `regex::Regex`-based custom matching** with normalized case-insensitive comparisons and no backtracking-capable engine.
- [ ] **Step 5: Implement decision precedence** so all matched rule IDs/categories are returned while the effective action is `block`, then `log`, then `allow`; runtime matcher errors produce a sanitized diagnostic and never panic.
- [ ] **Step 6: Run `cargo test --test waf_engine`** and expect all tests to pass.
- [ ] **Step 7: Commit with `git commit -m "feat: add bounded waf evaluation engine"`.**

### Task 3: Load and share immutable WAF snapshots with the proxy

**Files:**
- Create: `src/waf_store.rs`
- Modify: `src/lib.rs`
- Modify: `src/control_plane/mod.rs`
- Modify: `src/cli.rs`
- Modify: `src/proxy.rs`
- Test: `tests/proxy_waf.rs`

**Interfaces:**
- Produces `WafStore::load(db)`, `WafStore::snapshot()`, and `WafStore::reload(db)`; `BearustProxy::with_waf_store(Arc<WafStore>)` consumes it.

- [ ] **Step 1: Write failing proxy tests** that send a matching request in monitor mode (upstream receives it) and block mode (client receives generic 403 and upstream is not contacted).
- [ ] **Step 2: Run `cargo test --test proxy_waf`** and confirm the proxy has no WAF store integration.
- [ ] **Step 3: Implement `WafStore` with `ArcSwap<WafSnapshot>`**, loading persisted config/rules at startup and retaining the last valid snapshot when reload validation fails.
- [ ] **Step 4: Add the store to `AppState`, initialize it after migrations/seeding, and pass the same `Arc<WafStore>` from CLI bootstrap into `BearustProxy`.
- [ ] **Step 5: Integrate evaluation before route forwarding in `request_filter`; use Pingora's bounded body-filter hook for body bytes, and never buffer beyond the configured cap. Return 403 with a non-reflective body for effective blocks.
- [ ] **Step 6: Run `cargo test --test proxy_waf` and the existing `cargo test --test proxy_http`; expect both to pass.
- [ ] **Step 7: Commit with `git commit -m "feat: enforce waf decisions in proxy"`.**

### Task 4: Add authenticated WAF control-plane APIs and TOML import/export

**Files:**
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/repository.rs`
- Test: `tests/control_plane_waf.rs`

**Interfaces:**
- Adds `GET/PATCH /api/waf/config`, `GET/POST /api/waf/rules`, `PATCH/DELETE /api/waf/rules/{id}`, `POST /api/waf/rules/import`, and `GET /api/waf/rules/export`.

- [ ] **Step 1: Write failing authenticated API tests** for admin success, non-admin 403, config mode changes, built-in immutability, custom CRUD, TOML round-trip, and atomic rejection of invalid imports.
- [ ] **Step 2: Run `cargo test --test control_plane_waf`** and confirm missing routes/handlers.
- [ ] **Step 3: Add strict request/response DTOs** with `deny_unknown_fields`, bounded matcher lengths, valid categories/actions, and stable versioned TOML schema.
- [ ] **Step 4: Implement admin authorization, transactional repository mutations, WafStore reload, and structured sanitized errors for every route.
- [ ] **Step 5: Run `cargo test --test control_plane_waf`; expect all API tests to pass.
- [ ] **Step 6: Commit with `git commit -m "feat: expose waf management api"`.**

### Task 5: Add security audit events and realtime invalidation

**Files:**
- Modify: `src/control_plane/audit.rs`
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/realtime.rs`
- Test: `tests/control_plane_waf.rs`

- [ ] **Step 1: Add failing assertions** that rule/config mutations emit `waf.changed`, detections emit redacted security events, and request bodies/tokens are absent from serialized audit details.
- [ ] **Step 2: Implement sanitized event builders** containing only rule ID/category/severity/action, route context, and timestamp; publish `waf.changed` after successful mutations.
- [ ] **Step 3: Run the focused test and existing audit/realtime tests:** `cargo test --test control_plane_waf --test control_plane_audit --test control_plane_realtime`.
- [ ] **Step 4: Commit with `git commit -m "feat: audit waf detections and invalidations"`.**

### Task 6: Build the WAF dashboard and TOML workflow

**Files:**
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/ui.tsx`
- Modify: `frontend/src/styles.css`
- Create: `frontend/src/waf.test.tsx`

- [ ] **Step 1: Write failing component tests** for displaying mode/rules, admin-only controls, changing monitor/block mode, rule action overrides, validation errors, and TOML import/export controls.
- [ ] **Step 2: Run `npm test -- --run frontend/src/waf.test.tsx`** and confirm missing API/UI behavior.
- [ ] **Step 3: Add typed API methods and a WAF management section** using existing Tailwind v4 primitives, with explicit monitor/block status and severity/action badges.
- [ ] **Step 4: Connect realtime `waf.changed` invalidation to reload configuration and rules; keep non-admin users read-only or hidden according to existing RBAC patterns.
- [ ] **Step 5: Run `npm test -- --run frontend/src/waf.test.tsx` and `npm run build`; expect both to pass.
- [ ] **Step 6: Commit with `git commit -m "feat: add waf management dashboard"`.**

### Task 7: End-to-end verification and documentation

**Files:**
- Modify: `README.md`
- Modify: `DEVELOPMENT.md`
- Modify: `docs/PRD.md`
- Create: `tests/waf_end_to_end.rs`

- [ ] **Step 1: Write an end-to-end test** covering fresh-install defaults, custom TOML import, monitor detection, block enforcement, audit redaction, and external-database persistence when `DATABASE_URL_EXTERNAL` is set.
- [ ] **Step 2: Run the complete verification suite:** `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `cargo test --all-targets`, `npm test -- --run`, and `npm run build`.
- [ ] **Step 3: Document WAF defaults, rule format, TOML examples, monitor-to-block rollout, body limits, and Docker usage; update the PRD Phase 6 status only after all checks pass.
- [ ] **Step 4: Commit with `git commit -m "docs: document phase 6 basic waf"`.**

