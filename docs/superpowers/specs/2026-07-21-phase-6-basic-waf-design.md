# Phase 6 Basic WAF — Design Specification

**Date:** 2026-07-21  
**Status:** Approved for implementation planning

## Goal

Add a basic, configurable Web Application Firewall to BeaRust's request path. The first increment protects common HTTP attack classes while preserving safe rollout: new installations run in `monitor-only` mode, and administrators can switch to blocking behavior.

## Scope

Phase 6 includes:

- Built-in signatures for SQL injection, cross-site scripting, path traversal, and command injection.
- Custom rules managed through the dashboard and TOML import/export.
- Global WAF mode with `monitor-only` as the default and an administrator-controlled `block` mode.
- Per-rule action overrides: `inherit`, `allow`, `log`, or `block`.
- Matching against HTTP method, path, query string, headers, and a bounded request body.
- Persistence in all supported databases: SQLite, PostgreSQL, and MySQL.
- Audit/security events for detections and blocks, with sensitive values redacted.
- Authenticated CRUD APIs and dashboard controls for rule and mode management.
- Realtime invalidation through the existing SSE event hub after rule changes.

Out of scope: advanced semantic detection, bot management, adaptive rate limiting, distributed rule synchronization, plugin-based rules, automatic rule updates, and a full OWASP CRS port. Those belong to later phases or separate design work.

## Architecture

The WAF evaluator runs in-process in the proxy request pipeline. A request is normalized into a bounded inspection context, then evaluated against an immutable compiled rule snapshot. The evaluator returns a decision (`allow`, `log`, or `block`) and matched rule metadata. The proxy applies the decision without waiting on the control plane or any external service.

Rule definitions are stored in the control-plane database. Built-in rules are seeded idempotently and remain identifiable as built-in; custom rules are administrator-managed. Updates validate and compile matchers before replacing the active snapshot, so an invalid rule cannot disrupt the currently active configuration. Successful mutations publish a redacted SSE invalidation event so dashboard clients reload their WAF data.

## Rule model and precedence

Each rule contains an identifier, display name, source (`builtin` or `custom`), category, severity, enabled flag, matcher definition, and action. `inherit` follows the global mode; `allow`, `log`, and `block` override it for that rule. Disabled rules never produce a match.

When multiple rules match, the evaluator records all safe match metadata and applies the strongest effective action using this order: `block` > `log` > `allow`. An explicit `allow` can suppress a lower-priority detection, but it cannot override a `block` rule. Rule evaluation must be deterministic.

Matchers use bounded, safe operations (including Rust's linear-time regex implementation where regex matching is needed). Request body inspection is capped by a configured maximum; oversized or unavailable bodies are not buffered solely for WAF inspection. Invalid matcher syntax, unsupported fields, or unsafe limits are rejected during validation.

## Configuration and APIs

- Global WAF configuration exposes the current mode and inspection limits.
- Administrators can list, create, update, enable/disable, and delete custom rules.
- Built-in rules can be enabled/disabled and have action overrides, but their identity and source cannot be changed.
- TOML import validates the complete document before applying changes; export emits a stable, versioned schema.
- Authorization follows existing RBAC. WAF management is administrator-only in this phase; detection records are visible through the existing authenticated audit viewer according to its current permissions.
- API errors return structured validation messages and never expose raw database errors or request contents.

## Request handling and observability

In `monitor-only`, a match is logged and the request proceeds. In `block`, an effective block returns HTTP 403 with a generic response and no reflected payload. Security events include rule ID/category/severity, action, route context, and timestamp, while omitting credentials, tokens, private data, and full request bodies.

The evaluator must fail safe for malformed configuration (reject the change and retain the last valid snapshot). Runtime matcher errors are treated as non-blocking evaluator failures and emitted as sanitized diagnostics; they must not panic or take down the proxy.

## Testing and acceptance criteria

- Unit tests cover every built-in signature, normalization, action precedence, disabled rules, and invalid matcher rejection.
- Integration tests verify monitor versus block behavior through the proxy, 403 responses, redacted audit events, and SSE invalidation.
- Persistence tests run against SQLite and the existing opt-in external database harness for PostgreSQL/MySQL.
- TOML round-trip tests prove stable export/import and transactional rejection of invalid documents.
- Bounded-input tests verify body and header limits do not cause unbounded memory or CPU use.
- Existing proxy, RBAC, audit, and external database test suites remain green.

Phase 6 is complete when all acceptance tests pass, the default mode is monitor-only on fresh installations, administrators can safely switch to block and override individual rules, and no sensitive request data is exposed in API responses, UI, logs, or audit records.

