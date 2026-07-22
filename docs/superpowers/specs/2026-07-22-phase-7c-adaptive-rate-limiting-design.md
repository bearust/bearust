# Phase 7C: Adaptive Rate Limiting Design

## Goal

Add a bounded, deterministic adaptive rate limiter that protects each proxy
host from abusive client traffic while preserving the existing monitor-only
default and WAF/bot-protection precedence.

## Scope

Phase 7C covers an in-process token-bucket limiter keyed by
`proxy_host_id + client IP`. Per-route keys, distributed coordination,
persistent counters, and external Redis storage are deferred to later phases.

## Architecture

`RateLimitPolicy` is part of the immutable proxy/security snapshot. It contains
`enabled`, `action` (`monitor` or `block`), `capacity`, `refill_per_second`, and
`key_scope` (initially only `proxy_host_ip`). Reloads publish a complete,
validated snapshot atomically.

Runtime bucket state lives in a separate bounded `RateLimiterStore`. Each entry
tracks tokens and the last monotonic timestamp. The store enforces a maximum
entry count, evicts idle entries by TTL, and falls back to deterministic oldest
entry eviction. Restarting the process resets runtime state.

Client identity uses the peer address by default. `Forwarded` or
`X-Forwarded-For` is considered only when the peer is in the configured trusted
proxy set; untrusted client-supplied forwarding headers are ignored.

## Request flow

The enforcement order is:

1. Explicit security deny.
2. Signature/semantic WAF decision.
3. Bot challenge or block decision.
4. Rate-limit evaluation.
5. Upstream connection.

In monitor mode, a limited request proceeds and emits bounded telemetry. In
block mode, a limited request returns `429 Too Many Requests` with a generic
body and a bounded `Retry-After` value; no upstream connection is opened.

## Configuration and control plane

Administrators can read and update policy through the authenticated API and
dashboard. Numeric values have explicit lower and upper bounds and invalid
policies are rejected without changing the active snapshot. Updates emit a
redacted audit event and an authenticated SSE invalidation event.

The default policy is disabled/monitor-only. No policy accepts a route key or
unbounded cardinality in this increment.

## Telemetry and privacy

Events expose only proxy-host identifier, action, decision, remaining token
count, and bounded retry duration. Raw IP addresses, forwarding headers,
request bodies, credentials, and tokens are never written to audit records,
SSE payloads, or the dashboard.

## Failure handling

If policy parsing, trusted-proxy parsing, or limiter state validation fails,
the request follows fail-open monitor behavior and records a safe diagnostic
category. The limiter must never panic, allocate unbounded state, or make an
untrusted header authoritative.

## Verification

Tests cover token-bucket burst/refill behavior, monotonic-clock boundaries,
idle/oldest eviction, concurrent access, monitor/block responses, precedence
against WAF and bot decisions, trusted-proxy parsing, RBAC/API validation,
redaction, audit/SSE invalidation, and frontend policy controls. The completion
gate is Rust tests, Clippy with `-D warnings`, formatting, frontend tests/build,
and the repository's Compose/diff checks.

## Deferred work

Per-route policies, adaptive tuning feedback, CAPTCHA integrations, persisted
counters, cross-node synchronization, and Redis-backed coordination remain
deferred to later roadmap phases.
