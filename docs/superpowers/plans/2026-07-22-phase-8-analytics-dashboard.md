# Phase 8 Analytics Dashboard Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add bounded process-local analytics, authenticated query APIs, Prometheus output, and an admin dashboard for proxy and security metrics.

**Architecture:** A dedicated `analytics` module owns a one-minute ring buffer and immutable snapshots. Proxy and security paths emit redacted completion events without blocking traffic. Control-plane handlers expose bounded JSON queries and `/metrics`; the frontend fetches summaries/timeseries and refreshes through an SSE invalidation event.

**Tech Stack:** Rust, Tokio, Axum, Serde, existing SQLx control plane, React/TypeScript, Vitest, SSE, Prometheus text exposition.

## Global Constraints

- The collector is process-local and resets on restart.
- Default retention is 24 hours with one-minute buckets and a maximum of 1,440 buckets per host.
- Analytics never stores raw IP addresses, complete URLs, headers, bodies, credentials, tokens, or secrets.
- Maximum hosts per query is 100 and maximum returned timeseries buckets is 1,440.
- Analytics failures are fail-open and never reject or materially delay proxy traffic.
- Viewer/operator access is read-only; all analytics endpoints require authentication except a configurable internal-only Prometheus endpoint.
- Per-route analytics, durable history, Redis/cross-node aggregation, anomaly detection, adaptive tuning, and alerting are deferred.

---

### Task 1: Bounded analytics engine

**Files:**
- Create: `src/analytics.rs`
- Modify: `src/lib.rs`
- Test: `tests/analytics.rs`

**Interfaces:**
- Produces `AnalyticsEvent`, `AnalyticsCollector::record(event)`, `AnalyticsCollector::summary(filter)`, `AnalyticsCollector::timeseries(filter)`, and `AnalyticsSnapshot`.
- `AnalyticsEvent` contains `proxy_host_id: i64`, UTC timestamp, status code, latency milliseconds, and redacted security counters.

- [ ] **Step 1: Write failing tests** for one-minute rollover, 24-hour eviction, bounded host cardinality, concurrent recording, percentile ordering, and empty snapshots.
- [ ] **Step 2: Run `cargo +nightly test --test analytics` and confirm the new API/tests fail before implementation.**
- [ ] **Step 3: Implement a fixed-capacity ring buffer.** Use `Mutex<State>` with preallocated/ bounded maps, clamp host and bucket limits, evict oldest buckets, and aggregate latency into fixed histogram bins rather than retaining samples.
- [ ] **Step 4: Implement snapshot queries.** Clamp time range and host count, return UTC RFC3339 bucket timestamps, counts, status classes, security counters, and p50/p95/p99 derived from histogram bins.
- [ ] **Step 5: Run `cargo +nightly test --test analytics`; expected result is all focused tests passing.**
- [ ] **Step 6: Commit `feat: add bounded analytics collector`.**

### Task 2: Proxy and security instrumentation

**Files:**
- Modify: `src/proxy.rs`
- Modify: `src/waf.rs`, `src/bot_store.rs`, `src/rate_limit_store.rs` only where event hooks are required
- Test: `tests/proxy_analytics.rs`

**Interfaces:**
- Consumes `Arc<AnalyticsCollector>` from the proxy builder.
- Produces exactly one completion event per request and redacted WAF/bot/rate-limit counters.

- [ ] **Step 1: Add failing tests** asserting one event per completed request, status/latency capture, and no request failure when collector recording returns a bounded error.
- [ ] **Step 2: Run `cargo +nightly test --test proxy_analytics` and confirm failure.**
- [ ] **Step 3: Add `with_analytics(Arc<AnalyticsCollector>)` to `BearustProxy` and record completion after response status is known.**
- [ ] **Step 4: Map security decisions to aggregate counters only; do not pass IP, URL, headers, body, or token data.**
- [ ] **Step 5: Run focused proxy analytics and existing proxy WAF/bot/rate-limit tests.**
- [ ] **Step 6: Commit `feat: instrument proxy analytics`.**

### Task 3: Authenticated analytics API

**Files:**
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/auth.rs` only if shared read authorization helper is needed
- Test: `tests/control_plane_analytics.rs`

**Interfaces:**
- Add `GET /api/analytics/summary` and `GET /api/analytics/timeseries`.
- Query parameters: `proxy_host_id`, `from`, `to`, and bounded `limit`; malformed or oversized ranges return `400`.

- [ ] **Step 1: Write failing API/RBAC tests** for authenticated viewer read access, unauthenticated rejection, bounded filters, empty data, and redacted JSON.
- [ ] **Step 2: Run the focused test and confirm failure.**
- [ ] **Step 3: Add handlers that read collector snapshots without holding locks across response serialization.**
- [ ] **Step 4: Enforce viewer/operator/admin read access and return stable error envelopes for invalid ranges.**
- [ ] **Step 5: Run `cargo +nightly test --test control_plane_analytics`.**
- [ ] **Step 6: Commit `feat: add authenticated analytics API`.**

### Task 4: Prometheus endpoint

**Files:**
- Create: `src/analytics_prometheus.rs`
- Modify: `src/control_plane/mod.rs`, `src/config/mod.rs`, `src/cli.rs`
- Test: `tests/prometheus.rs`

**Interfaces:**
- Add `GET /metrics` with stable names `bearust_requests_total`, `bearust_request_duration_ms`, `bearust_security_events_total`, and `bearust_rate_limit_events_total`.
- Labels are limited to configured proxy host and status class.

- [ ] **Step 1: Write failing tests** for disabled-by-default behavior, internal bind/auth guard, stable names, escaping, and bounded labels.
- [ ] **Step 2: Run the focused tests and confirm failure.**
- [ ] **Step 3: Implement text exposition from an immutable analytics snapshot; escape label values and cap output size.**
- [ ] **Step 4: Wire configuration defaults and CLI state without exposing the endpoint externally by default.**
- [ ] **Step 5: Run `cargo +nightly test --test prometheus` and `cargo +nightly check --all-targets`.**
- [ ] **Step 6: Commit `feat: add bounded prometheus analytics endpoint`.**

### Task 5: Realtime and frontend dashboard

**Files:**
- Modify: `src/control_plane/realtime.rs`
- Modify: `frontend/src/api.ts`, `frontend/src/realtime.ts`, `frontend/src/App.tsx`
- Create: `frontend/src/analytics.test.tsx` if not created earlier
- Test: frontend Vitest suite

**Interfaces:**
- SSE invalidation event: `analytics.changed` with no metric payload.
- API client methods `getAnalyticsSummary(params)` and `getAnalyticsTimeseries(params)`.

- [ ] **Step 1: Write failing UI tests** for loading, empty, error, host/time filters, summary cards, chart/table rendering, and SSE refresh.
- [ ] **Step 2: Run `npm test -- --run frontend/src/analytics.test.tsx` and confirm failure.**
- [ ] **Step 3: Add typed API clients and dashboard components following existing accessible WAF/bot patterns.**
- [ ] **Step 4: Subscribe to `analytics.changed` and refetch bounded data with debounced refresh.**
- [ ] **Step 5: Run the focused frontend suite and existing frontend tests.**
- [ ] **Step 6: Commit `feat: add analytics dashboard`.**

### Task 6: Documentation and verification gate

**Files:**
- Modify: `docs/PRD.md`, `README.md`, `docs/DEVELOPMENT.md`
- Create: `docs/superpowers/reviews/phase-8-final-review.md`

- [ ] **Step 1: Document defaults, endpoint authentication, Prometheus exposure, retention/reset behavior, and deferred multi-node history.**
- [ ] **Step 2: Run `cargo +nightly fmt --all -- --check`, `cargo +nightly check --all-targets`, focused Rust tests, and frontend tests.**
- [ ] **Step 3: Run `git diff --check` and inspect the complete branch diff for redaction, bounds, and RBAC regressions.**
- [ ] **Step 4: Record exact commands, counts, failures, and deferred scope in the final review.**
- [ ] **Step 5: Commit `docs: complete phase 8 analytics dashboard`.**
