# BeaRust Phase 12 — AI Advisor Design

**Date:** 2026-07-25  
**Status:** Proposed  
**Scope:** Phase 12 from `docs/PRD.md`

## Goal

Add an optional, privacy-first AI Advisor that explains WAF and anomaly
activity, produces traffic/security summaries, and proposes validated
configuration changes without ever entering the proxy traffic path or applying
changes without explicit administrator approval.

## Requirements

Phase 12 must satisfy the following product requirements:

- The module is active only when both `LLM_API_URL` and `LLM_API_KEY` are set.
- The provider contract is compatible with OpenAI Chat Completions at
  `/v1/chat/completions`, including self-hosted providers such as Ollama,
  vLLM, and LM Studio.
- WAF/anomaly explanations, security summaries, rule-tuning suggestions, and
  natural-language configuration drafts are supported as separate workflows.
- LLM calls are asynchronous, bounded, and out-of-band from request handling;
  provider failures cannot affect proxy availability or latency.
- Sensitive data is redacted by default before leaving the control plane.
- Suggestions and configuration drafts are read-only until an administrator
  explicitly approves them.
- All requests, outcomes, approvals, rejections, and failures are auditable
  with redacted details.
- The feature is hidden from the GUI when disabled and remains compatible with
  SQLite, PostgreSQL, and MySQL.

## Recommended approach

Implement a control-plane `AiAdvisorService` backed by a bounded asynchronous
worker queue and a small provider adapter. Keep provider-specific HTTP and
response parsing behind a trait so the rest of the application depends on a
validated internal response format rather than OpenAI wire details.

Use structured JSON prompts and responses for every workflow. Validate the
response against an allowlisted schema before persistence. Store only the
redacted input summary, structured result, status, timestamps, provider model
label, and a request/response hash; never persist raw prompts, raw responses,
API keys, or unredacted event payloads.

The default operational mode is read-only. A draft can be approved only by an
administrator with the existing centralized permission checks. Approval
reuses the existing configuration mutation services and their validation,
audit, and realtime invalidation paths; the advisor itself has no direct
write access to proxy state.

## Architecture

### Activation and configuration

At startup, parse `LLM_API_URL`, `LLM_API_KEY`, optional model and timeout
settings, and bounded queue/concurrency limits. If either required variable is
missing, construct a disabled service and expose only a non-sensitive disabled
status to authenticated API consumers. Invalid configuration disables the
module with a sanitized startup diagnostic; it must not prevent the control
plane or proxy from starting.

The provider adapter uses an async HTTP client, fixed connect/request
deadlines, response-size limits, cancellation, and a circuit breaker. A
breaker-open or timeout result marks the job failed and schedules no unbounded
retry. The worker queue has a finite capacity and rejects excess work with a
neutral `advisor_busy` error.

### Data flow

```text
authenticated request
        |
        v
advisor API -> redact + bound input -> persist queued job -> worker queue
                                                     |
                                                     v
                                      provider adapter (async HTTP)
                                                     |
                              validate structured response + persist result
                                                     |
                                  SSE invalidation + sanitized audit event
```

The worker reads immutable analytics, WAF, anomaly, and configuration
snapshots. It never reads private key material, secret configuration values,
raw request bodies, or unrestricted audit records. The proxy request path has
no dependency on the worker, provider, database job status, or SSE delivery.

### Redaction boundary

Create one reusable redaction pipeline before prompt construction. It removes
or replaces IP addresses, authorization/cookie headers, API keys, passwords,
private keys, session identifiers, request bodies, and other configured secret
patterns. Redaction is deterministic and testable. The persisted input is the
same redacted representation sent to the provider, plus a non-reversible hash
for correlation.

### Workflows

Each workflow has a fixed input schema, system instruction, output schema, and
permission requirement:

| Workflow | Output | Minimum permission |
|---|---|---|
| Incident explanation | severity/context explanation and evidence references | `waf.read` or `analytics.read` |
| Security summary | bounded period summary and notable trends | `analytics.read` |
| Rule tuning suggestion | proposed rule/action/threshold diff with confidence and rationale | `waf.read` |
| Configuration draft | validated, non-applied proxy/WAF draft with explicit diff | `proxy_hosts.read` and relevant read permission |

Draft approval is a separate admin-only operation. The server re-reads current
configuration, verifies the draft version/hash has not become stale, validates
the proposed mutation through normal services, and then commits atomically.
Stale or invalid drafts are rejected without partial changes.

### Persistence and API

Add an additive, idempotent migration for advisor jobs/results/drafts. Statuses
are `queued`, `running`, `completed`, `failed`, `approved`, `rejected`, and
`expired`; records include owner, workflow, timestamps, bounded error code,
redacted result, and configuration version/hash where applicable.

Expose authenticated endpoints:

- `GET /api/ai-advisor/status`
- `POST /api/ai-advisor/analyses`
- `GET /api/ai-advisor/insights`
- `POST /api/ai-advisor/drafts/{id}/approve`
- `POST /api/ai-advisor/drafts/{id}/reject`

All request bodies have explicit size and enum limits. Responses never include
provider errors, API keys, raw prompts, raw responses, or database details.
Successful state changes emit existing authenticated SSE invalidations and
redacted audit events.

### Frontend and localization

Add an Advisor section only when the status endpoint reports enabled. The UI
supports starting an analysis, polling/reloading bounded job status through the
existing realtime mechanism, viewing redacted insight cards, and reviewing
draft diffs. Approval/rejection controls are rendered only for administrators.
All copy uses the Phase 11 locale catalog; technical identifiers and values are
not translated. Disabled, unavailable, timeout, and stale-draft states have
explicit localized messages.

## Delivery increments

### 12A — Foundation

- Configuration parsing and disabled-mode behavior.
- Provider adapter, structured request/response types, timeout, size limits,
  circuit breaker, bounded queue, and worker lifecycle.
- Deterministic redaction pipeline and hashing.
- Database migration/repository for jobs and results.
- Status and analysis API with RBAC, sanitized errors, audit, and SSE events.

### 12B — Advisor workflows and approval

- Incident explanation, security summary, tuning suggestion, and configuration
  draft schemas/prompts.
- Schema validation, stale-version checks, draft expiry, approval/rejection,
  and reuse of existing configuration mutation services.
- Provider failure metrics, bounded retry policy, and operational diagnostics.
- Rust integration tests across SQLite and opt-in external database drivers.

### 12C — Frontend and operations

- Localized Advisor dashboard, job/result states, diff review, and admin
  approval controls.
- Responsive and accessibility coverage for English, Indonesian, and Japanese.
- Documentation for provider setup, redaction guarantees, data retention,
  self-hosted endpoints, and troubleshooting.
- Frontend, Playwright, Rust, locale, formatting, Clippy, and security gates.

## Error handling and security

- Missing or invalid provider configuration disables the module safely.
- Provider timeouts, non-success responses, malformed JSON, schema violations,
  breaker-open state, queue saturation, and stale drafts map to bounded,
  user-safe error codes.
- No automatic retry loop may grow without a finite attempt/deadline budget.
- LLM output is untrusted input: it is treated as text/data, never executable
  configuration, SQL, HTML, or a permission decision.
- Approval requires a fresh server-side authorization and validation check.
- Logs, audit events, metrics labels, and UI errors are redacted and must not
  contain credentials, payloads, private keys, raw prompts, or provider body
  content.
- Feature disablement and provider failure do not alter proxy routing, WAF
  enforcement, certificate operations, or authentication.

## Testing and acceptance criteria

Tests must cover:

1. Disabled mode with missing variables and safe startup.
2. Provider request compatibility, auth headers, timeout, response limits, and
   circuit-breaker transitions using a local mock server.
3. Redaction of every sensitive field and absence of raw data in persistence,
   audit, logs, and API responses.
4. Queue bounds, cancellation, failure mapping, schema validation, and no
   proxy-path dependency.
5. RBAC for each workflow, admin-only approval, stale/expired draft rejection,
   atomic mutation, audit records, and SSE invalidations.
6. SQLite migration and repository behavior plus opt-in PostgreSQL/MySQL
   compatibility tests.
7. Frontend hidden-disabled behavior, localized loading/error/result states,
   responsive draft review, and Playwright approval flow.

The Phase 12 acceptance gate is:

- The complete application starts and serves proxy traffic with AI disabled.
- Provider failures cannot block or slow the proxy path.
- No unredacted sensitive data crosses the provider boundary or is persisted.
- All four workflows produce validated, bounded results when configured.
- No draft changes state without an explicit, authorized admin approval.
- Audit and realtime events are redacted and deterministic.
- SQLite, PostgreSQL, and MySQL code paths remain compatible.
- Rust/frontend tests, Playwright, locale validation, `cargo fmt`, Clippy, and
  `git diff --check` pass.

## Explicit non-goals

- Local or in-process model hosting.
- Automatic WAF/configuration mutation or autonomous enforcement.
- Sending raw traffic, request bodies, secrets, private keys, or full audit
  history to an external provider.
- Training, fine-tuning, or retaining a provider-side user corpus.
- Cross-node advisor job execution/replay beyond the existing Phase 10
  control-plane guarantees.
- A general chat assistant, arbitrary code execution, or unrestricted SQL/API
  command generation.
