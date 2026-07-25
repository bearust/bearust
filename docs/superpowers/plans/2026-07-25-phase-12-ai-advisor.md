# Phase 12 AI Advisor Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver an optional, privacy-first AI Advisor that runs asynchronously outside the proxy path and produces auditable, admin-approved insights and configuration drafts.

**Architecture:** Add a control-plane `AiAdvisorService` with a bounded Tokio worker queue, a provider adapter for OpenAI-compatible chat completions, and a deterministic redaction boundary. Persist only redacted structured jobs/results/drafts, expose authenticated API routes, and reuse existing configuration mutation, RBAC, audit, and realtime services for approval. Add a conditionally rendered localized React section and end-to-end coverage.

**Tech Stack:** Rust 2021, Tokio, Axum 0.8, Reqwest 0.12, Serde/JSON, SQLx 0.8 migrations for SQLite/PostgreSQL/MySQL, existing RBAC/audit/SSE services, React/Vite, i18next, Vitest, Playwright.

## Global Constraints

- `LLM_API_URL` and `LLM_API_KEY` are both required; otherwise the module is disabled and hidden.
- All provider calls are asynchronous, bounded by finite timeouts, response-size limits, queue capacity, and circuit-breaker state.
- Redaction is enabled by default; raw request bodies, secrets, private keys, credentials, tokens, and unrestricted audit data never cross the provider boundary or enter persistence.
- LLM output is untrusted structured data; it is never executed or applied without a fresh administrator authorization and validation check.
- Existing proxy traffic, WAF enforcement, authentication, certificate operations, and non-AI startup must remain available when the provider is absent or failing.
- Database changes are additive, idempotent, and portable across SQLite, PostgreSQL, and MySQL.
- User-facing copy must use the Phase 11 locale catalog (`en`, `id`, `ja`); technical identifiers remain unchanged.
- Every task ends with focused tests and an intentional commit.

---

### Task 1: Define advisor domain contracts and safe configuration

**Files:**
- Create: `src/ai_advisor.rs`
- Modify: `src/lib.rs`
- Modify: `src/control_plane/mod.rs:1-110,317-390`
- Modify: `src/main.rs` (control-plane startup wiring)
- Test: `tests/ai_advisor.rs`

**Interfaces:**
- Produces `AiAdvisorService`, `AdvisorStatus`, `AdvisorWorkflow`, `AdvisorJobId`, `AdvisorJobStatus`, `AdvisorErrorCode`, and bounded request/response structs.
- `AiAdvisorService::disabled()` is cheap, cloneable, and has no worker; `AiAdvisorService::from_env(...)` returns a sanitized configuration error or an enabled service.
- `AppState` gains `ai_advisor: Arc<AiAdvisorService>` and startup attaches it without changing the proxy runtime.

- [ ] **Step 1: Write failing tests** for missing env variables, whitespace-only values, valid OpenAI-compatible URL normalization, finite default timeout/queue limits, and disabled status serialization.
- [ ] **Step 2: Run the focused test** with `cargo +stable test --test ai_advisor config -- --nocapture`; verify the new contracts are missing.
- [ ] **Step 3: Implement the domain enums/config parser** with explicit defaults (30-second request timeout, 2 MiB response cap, queue capacity 32, two workers, three-attempt circuit threshold) and no secret in `Debug`/status output.
- [ ] **Step 4: Wire `AiAdvisorService::disabled()` into `build_state` and `AppState`**; environment lookup must not fail control-plane startup.
- [ ] **Step 5: Run `cargo +stable test --test ai_advisor` and `cargo +stable fmt --all -- --check`**; commit `feat: add AI advisor domain contracts`.

### Task 2: Implement deterministic redaction and provider circuit breaker

**Files:**
- Modify: `src/ai_advisor.rs`
- Create: `src/ai_advisor_redaction.rs`
- Test: `tests/ai_advisor_redaction.rs`

**Interfaces:**
- `Redactor::redact(value: &serde_json::Value) -> RedactedValue` removes/replaces IPs, authorization/cookie fields, tokens, passwords, private-key blocks, request bodies, and configured secret keys.
- `ProviderGuard` exposes `allow_request()`, `record_success()`, and `record_failure(now)` with closed/open/half-open behavior and finite cooldown.
- `RedactedValue` contains only bounded JSON plus a SHA-256 correlation hash; it never implements a raw-value logging path.

- [ ] **Step 1: Write failing tests** covering nested sensitive keys, header case variants, IPv4/IPv6 replacement, PEM replacement, request-body omission, deterministic output/hash, maximum serialized size, and circuit transitions.
- [ ] **Step 2: Run `cargo +stable test --test ai_advisor_redaction`; confirm failures identify the missing redaction/guard behavior.
- [ ] **Step 3: Implement the redactor** using an allowlist of safe fields plus recursive bounded traversal; reject over-large input before prompt construction.
- [ ] **Step 4: Implement the circuit breaker** with atomic state and monotonic `Instant`; do not sleep or retry inside the proxy path.
- [ ] **Step 5: Run focused tests plus `cargo clippy --test ai_advisor_redaction -- -D warnings`**; commit `feat: add advisor redaction and circuit breaker`.

### Task 3: Add provider adapter and bounded worker queue

**Files:**
- Modify: `src/ai_advisor.rs`
- Create: `src/ai_advisor_provider.rs`
- Test: `tests/ai_advisor_provider.rs`

**Interfaces:**
- `trait LlmProvider: Send + Sync { async fn complete(&self, request: ChatCompletionRequest) -> Result<ChatCompletionResponse, ProviderError>; }`
- `OpenAiCompatibleProvider::new(reqwest::Client, ProviderConfig)` sends `POST {base_url}/v1/chat/completions` with bearer auth and bounded JSON parsing.
- `AiAdvisorService::enqueue(AdvisorRequest) -> Result<AdvisorJobId, AdvisorErrorCode>` persists/queues work and returns `advisor_busy` when capacity is full.

- [ ] **Step 1: Write failing mock-server tests** for URL/path, authorization header, JSON payload, timeout, non-2xx mapping, malformed response, response-size rejection, success recording, and breaker-open short-circuit.
- [ ] **Step 2: Run `cargo +stable test --test ai_advisor_provider`; verify the adapter and worker are not implemented.
- [ ] **Step 3: Implement the provider adapter** with `reqwest::Client`, connect/request deadlines, explicit `Content-Type`, and sanitized error enums; never include response body in errors.
- [ ] **Step 4: Implement the Tokio worker queue** with a bounded `mpsc`, cancellation on shutdown, finite concurrency, and a single result transition per job.
- [ ] **Step 5: Run focused tests and `cargo +stable fmt --all -- --check`; commit `feat: add bounded advisor provider worker`.

### Task 4: Persist jobs, results, drafts, and advisor permissions

**Files:**
- Create: `migrations/0015_ai_advisor.sql`
- Modify: `src/control_plane/repository.rs`
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/rbac.rs`
- Test: `tests/control_plane_ai_advisor.rs`

**Interfaces:**
- Migration creates portable `ai_advisor_jobs` records with owner/workflow/status, redacted input/result, error code, provider model, timestamps, expiry, and config version/hash; indexes support owner/status/newest queries.
- Repository functions: `insert_advisor_job`, `claim_advisor_job`, `finish_advisor_job`, `list_advisor_jobs`, `get_advisor_job`, `mark_advisor_draft_decision`.
- Add permission keys `ai_advisor.read`, `ai_advisor.request`, and `ai_advisor.approve`; seed built-in roles consistently with existing role migration behavior.

- [ ] **Step 1: Write failing SQLite repository tests** for migration idempotency, every status transition, bounded fields, expiry, list pagination, and built-in permission seeds; add opt-in external-driver coverage using the existing `DATABASE_URL_EXTERNAL` harness.
- [ ] **Step 2: Run `cargo +stable test --test control_plane_ai_advisor`; confirm migration/repository/permission failures.
- [ ] **Step 3: Write `0015_ai_advisor.sql`** using SQL supported by all three drivers and additive nullable-safe columns only.
- [ ] **Step 4: Implement repository queries** with typed status/workflow conversion and no raw provider/error serialization.
- [ ] **Step 5: Run SQLite tests, external test skip/execute behavior, and `cargo +stable fmt --all -- --check`; commit `feat: persist advisor jobs and permissions`.

### Task 5: Add authenticated advisor API, workflows, audit, and approval

**Files:**
- Create: `src/control_plane/ai_advisor.rs`
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/audit.rs`
- Modify: `src/control_plane/realtime.rs`
- Modify: `src/ai_advisor.rs`
- Test: `tests/control_plane_ai_advisor.rs`

**Interfaces:**
- Handlers implement `GET /api/ai-advisor/status`, `POST /api/ai-advisor/analyses`, `GET /api/ai-advisor/insights`, `POST /api/ai-advisor/drafts/{id}/approve`, and `POST /api/ai-advisor/drafts/{id}/reject`.
- `AnalysisInput` has bounded `workflow`, `host_id`, time range, and natural-language command fields; unknown JSON fields are rejected.
- Workflow validators produce structured `InsightResult`/`ConfigurationDraft` values; draft approval calls existing host/WAF mutation services after fresh RBAC, version/hash, and validation checks.

- [ ] **Step 1: Write failing authenticated API tests** for disabled status, permission matrix, input limits, queued jobs, sanitized failures, redacted responses, workflow schema rejection, and SSE/audit events.
- [ ] **Step 2: Write failing approval tests** for non-admin rejection, stale/expired draft rejection, successful atomic approval, duplicate approval conflict, and no partial mutation on validation failure.
- [ ] **Step 3: Implement the four workflow schemas and bounded prompt builders** using only redacted analytics/WAF/anomaly snapshots and locale-aware output instructions.
- [ ] **Step 4: Implement handlers and route registration** using existing `current`, `authorize`, `audit::record_state`, and realtime publication patterns; map all provider/database failures to stable neutral error codes.
- [ ] **Step 5: Implement approval/rejection** through existing mutation services, emit `ai_advisor.changed`, and persist only sanitized audit details.
- [ ] **Step 6: Run `cargo +stable test --test control_plane_ai_advisor -- --test-threads=1` and `cargo +stable clippy --all-targets -- -D warnings`; commit `feat: add advisor workflows and approval API`.

### Task 6: Add typed frontend API and localized Advisor dashboard

**Files:**
- Create: `frontend/src/aiAdvisor.tsx`
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/ui.tsx`
- Test: `frontend/src/aiAdvisor.test.tsx`

**Interfaces:**
- Types mirror server enums: `AdvisorStatus`, `AdvisorWorkflow`, `AdvisorJob`, `AdvisorInsight`, `AdvisorDraft`, and `AdvisorErrorCode`.
- API methods: `aiAdvisorStatus`, `startAiAnalysis`, `listAiInsights`, `approveAiDraft`, `rejectAiDraft`.
- `AiAdvisorSection` accepts `{ user: User; onChanged?: () => void }`, hides itself when disabled, and renders approval controls only for `admin`.

- [ ] **Step 1: Write failing Vitest tests** for disabled omission, enabled status, workflow selection, localized loading/error/result states, redacted diff rendering, admin-only controls, stale approval handling, and realtime refresh.
- [ ] **Step 2: Run `npm test --prefix frontend -- --run aiAdvisor.test.tsx`; confirm missing types/API/component failures.
- [ ] **Step 3: Add typed API methods and implement `AiAdvisorSection`** with bounded polling fallback, existing `sanitizeError`, existing cards/buttons, and no provider details in rendered UI.
- [ ] **Step 4: Mount the section in `App.tsx`** behind status activation while preserving existing responsive layout and role checks.
- [ ] **Step 5: Run the focused frontend test, `npm run build --prefix frontend`, and `npm run validate-locales --prefix frontend`; commit `feat: add localized advisor dashboard`.

### Task 7: Add locale catalog, documentation, metrics, and operational controls

**Files:**
- Modify: `frontend/src/locales/en.json`
- Modify: `frontend/src/locales/id.json`
- Modify: `frontend/src/locales/ja.json`
- Modify: `frontend/src/catalog-keys.test.ts`
- Modify: `DEVELOPMENT.md`
- Modify: `DEPLOY.md`
- Modify: `docker-compose.yml`
- Modify: `docker-compose.dev.yml`
- Modify: `config/bearust.example.toml`
- Modify: `src/observability.rs`
- Test: `frontend/src/aiAdvisorLocale.test.tsx`

**Interfaces:**
- Locale keys cover status, workflows, redaction notice, job states, approval/rejection, stale/expired/provider-busy errors, and accessibility labels in all three catalogs.
- Documentation describes `LLM_API_URL`, `LLM_API_KEY`, optional model/timeout/queue variables, default redaction, retention, self-hosted endpoints, and safe disablement.
- Metrics expose bounded counters/gauges for queued, completed, failed, breaker-open, and approval outcomes without labels containing user input or provider data.

- [ ] **Step 1: Write failing locale tests** for key parity and rendered English/Indonesian/Japanese advisor states.
- [ ] **Step 2: Add all catalog entries and update the locale validation command**; no component may contain new user-facing prose outside translation resources.
- [ ] **Step 3: Add example/development/production environment documentation** with empty defaults and an explicit warning not to commit API keys.
- [ ] **Step 4: Add bounded advisor metrics** and verify labels are fixed enums only.
- [ ] **Step 5: Run locale tests, frontend build, `git diff --check`; commit `docs: document AI advisor operations and locales`.

### Task 8: Verify end-to-end behavior and release gate

**Files:**
- Create: `frontend/e2e/ai-advisor.spec.ts`
- Modify: `frontend/playwright.config.ts`
- Modify: `.superpowers/sdd/progress.md`
- Test: existing Rust/frontend suites plus the new Playwright spec

**Interfaces:**
- Playwright mocks the provider-facing backend API, never a real external LLM, and verifies disabled/enabled UI, redacted output, admin approval, non-admin read-only behavior, localized copy, and responsive layouts.

- [ ] **Step 1: Add Playwright scenarios** at 390px, 768px, and 1280px for `en`, `id`, and `ja`; assert no horizontal overflow and no provider secret/raw payload appears.
- [ ] **Step 2: Run the focused browser suite** with `npm run test:e2e --prefix frontend -- ai-advisor.spec.ts`; fix only bounded, in-scope failures.
- [ ] **Step 3: Run the complete acceptance gate:**
  ```bash
  cargo +stable test --all-targets -- --test-threads=1
  cargo +stable fmt --all -- --check
  cargo +stable clippy --all-targets -- -D warnings
  npm test --prefix frontend -- --run
  npm run validate-locales --prefix frontend
  npm run build --prefix frontend
  npm run test:e2e --prefix frontend
  git diff --check
  ```
- [ ] **Step 4: Record results and any transient-test reproduction in `.superpowers/sdd/progress.md`** without staging unrelated user changes.
- [ ] **Step 5: Commit only release documentation/ledger updates** after all gates pass, using `docs: verify phase 12 AI advisor`.

## Review checkpoints

- Review Tasks 1–3 together before persistence work begins; the proxy must have no dependency on provider availability.
- Review Task 4 migration and permission compatibility before enabling API routes.
- Review Task 5 specifically for redaction, approval authorization, stale-draft handling, and audit payloads.
- Review Tasks 6–7 for locale parity, hidden-disabled behavior, and responsive UI before end-to-end testing.
- Run the full gate in Task 8 before claiming Phase 12 complete.
