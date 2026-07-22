# Phase 8: Analytics Dashboard Design

## Goal

Add bounded operational analytics for proxy traffic and security decisions,
with an authenticated dashboard and a Prometheus-compatible scrape endpoint.
The first increment is process-local and intentionally resets on restart.

## Scope

Phase 8 records request count, response status classes/codes, latency
percentiles, 4xx/5xx error rates, and WAF, bot-protection, and rate-limit
events. Data is keyed by proxy host and time bucket; per-route dimensions,
historical database retention, Redis synchronization, and cross-node rollups
are deferred.

The collector uses a bounded ring buffer with one-minute buckets and a default
24-hour retention window. Every configured limit is clamped to a safe maximum.
Events contain no raw IP addresses, complete URLs, headers, bodies, tokens,
credentials, or secret material.

## Components

1. `analytics` module: event types, bounded ring buffer, percentile/error
   aggregation, and snapshot queries.
2. Proxy instrumentation: record a single completion event per request and
   redacted security decisions from existing WAF, bot, and rate-limit paths.
3. Control-plane API: authenticated summary and time-series endpoints with
   bounded host/time-range parameters. Viewer/operator access is read-only.
4. Prometheus adapter: `/metrics`, disabled or internal-only by default, with
   bounded label cardinality (proxy host and status class only).
5. Frontend dashboard: host/time filters, summary cards, latency/error chart,
   security-event panels, loading/error/empty states, and SSE invalidation.

## Data flow

The proxy emits a completion event after response status and elapsed time are
known. Security middleware emits redacted counters at the decision point.
The collector updates the current minute bucket under a short lock. API and
Prometheus handlers read immutable snapshots and never block request handling
for long-running aggregation. SSE publishes only an `analytics.changed`
invalidation event; clients refetch bounded results.

## Defaults and limits

- retention: 24 hours;
- bucket width: one minute;
- maximum retained buckets: 1,440 per host;
- maximum hosts returned per query: 100;
- maximum time-series buckets returned: 1,440;
- maximum Prometheus label values: configured proxy hosts only;
- monitor-only security modes remain unchanged.

All timestamps are UTC RFC3339 in JSON responses. Percentiles use a bounded
histogram rather than storing unbounded individual samples.

## Failure and security behavior

Analytics failures are fail-open: a dropped metric never rejects or delays a
proxy request. Lock poisoning, invalid ranges, and oversized requests return
safe defaults or a bounded client error. Audit and realtime payloads contain
event names and aggregate counts only. Prometheus output never exposes raw
request metadata.

## Verification criteria

- Unit tests cover bucket rollover, retention eviction, percentile calculation,
  concurrent updates, invalid query bounds, and redaction.
- Proxy tests prove one completion event per request and no request failure when
  the collector is unavailable.
- API/RBAC tests cover viewer read access, bounded filters, and authentication.
- Prometheus tests validate stable names, bounded labels, and disabled-by-default
  behavior.
- Frontend tests cover loading, empty, error, filters, and realtime refresh.
- `cargo +nightly check --all-targets` and focused tests pass before merge.

## Deferred work

Durable historical storage, Redis/cross-node aggregation, per-route analytics,
custom retention, anomaly detection, adaptive tuning, and alerting remain
future phases.
