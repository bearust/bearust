# Phase 4C — Audit Log Viewer Design

## Goal

Expose a safe, read-only audit history in the control-plane API and dashboard so authenticated users can investigate configuration and account events.

## Scope

### In scope

- `GET /api/audit-logs` for authenticated `admin`, `operator`, and `viewer` users.
- Filters for event, actor id, time range, and free-text search over safe event details.
- Offset pagination with a bounded page size and newest-first ordering.
- Dashboard audit-log panel with filters, loading/empty/error states, and pagination.
- Redacted response fields only: event id, actor label, event, safe details, and timestamp.
- Tests and documentation for authorization, filtering, pagination, and redaction.

### Out of scope

- Audit-log mutation or deletion.
- Export, archival, retention policies, or external log shipping.
- Custom roles, per-host scopes, SSO, or a separate auditor role.
- Rewriting existing audit events or changing their write paths.

## API contract

`GET /api/audit-logs?event=&actor_id=&from=&to=&q=&page=&page_size=`

The response is:

```json
{
  "items": [
    {
      "id": 42,
      "actor": "admin@example.com",
      "event": "user_created",
      "details": "target_user_id=7;reason=success",
      "created_at": "2026-07-20T10:00:00Z"
    }
  ],
  "page": 1,
  "page_size": 25,
  "total": 120
}
```

`actor` is resolved with a `LEFT JOIN users`. Deleted actors are represented as `deleted-user` and system events as `system`. Passwords, session hashes, setup tokens, private keys, provider credentials, request bodies, and other secrets are never selected or serialized.

The default page is 1 with page size 25. Page size is clamped/rejected outside 1–100 according to the existing validation envelope. All filters are bound SQL parameters. Results are ordered by newest `created_at`, then descending id for deterministic pagination.

## Authorization and error handling

The handler requires an active session and permits all three existing roles. Invalid filter values return the existing `invalid_input` envelope. Authentication failures use the existing generic `401` response. Read failures return the existing sanitized server-error response without SQL details.

## Frontend

Add an Audit Log section to the authenticated dashboard. It renders a responsive table with timestamp, actor, event, and details; controls for event, actor, date range, and search; and previous/next pagination. The UI uses the existing API client and generic error sanitization. It must not render secrets or expose raw server errors.

## Testing and completion criteria

Backend tests cover role authorization, default and bounded pagination, every filter, deterministic ordering, deleted/system actors, invalid inputs, and secret redaction. Frontend tests cover rendering for authenticated users, filter requests, pagination, empty state, and sanitized errors. Rust tests, frontend tests, frontend production build, and `git diff --check` must pass.

Phase 4C is complete when the API and dashboard viewer work for all authenticated roles, no audit mutation path exists, sensitive fields remain absent, documentation is updated, and all verification commands pass.
