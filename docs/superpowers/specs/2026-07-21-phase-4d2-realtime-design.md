# Phase 4D.2 Realtime Updates Design

## Goal

Add authenticated server-to-browser realtime updates to the control-plane GUI without periodic polling. The first implementation uses Server-Sent Events (SSE) because the required flow is server-to-client invalidation and the existing session cookie already provides authentication.

## Scope

### Included

- `GET /api/events` SSE endpoint protected by the existing session authentication.
- A bounded internal broadcast bus for redacted realtime events.
- Stable event envelopes with monotonic IDs per process, event type, timestamp, and safe metadata.
- Heartbeats, bounded reconnect behavior, and `Last-Event-ID` acceptance.
- Publishing invalidation events for audit-backed mutations across hosts, certificates, users, roles, and sessions.
- React subscription that refetches only the affected resource and continues to work when SSE is unavailable.
- Backend and frontend tests for authorization, stream framing, heartbeat, reconnect metadata, redaction, publication, and UI refresh.

### Excluded

- WebSocket transport or client-to-server messages.
- Cross-process or clustered event delivery; the bus is intentionally process-local in this phase.
- Durable event replay or an event history API.
- Periodic polling as a replacement transport.
- Per-host permission scopes and the Phase 4D.3 frontend design system.

## Architecture

`AppState` owns an `Arc<RealtimeHub>`. The hub contains a bounded `tokio::sync::broadcast::Sender<RealtimeEvent>` and an atomic sequence counter. A mutation records its existing redacted audit row and publishes an invalidation event through the same state-owned hub. The event payload never contains credentials, session material, private keys, request bodies, or raw database errors.

The SSE handler authenticates the request with the existing `current` session path before subscribing. It emits an initial `ready` event, then forwards broadcast events and periodic comment heartbeats. A lagging receiver is reported as a reconnect-required event rather than blocking the server. `Last-Event-ID` is parsed for observability and future replay compatibility; this phase does not replay historical events.

Event types are stable strings:

- `audit` — a safe audit event was written.
- `proxy_hosts.changed`
- `certificates.changed`
- `users.changed`
- `roles.changed`
- `sessions.changed`

Each event is an invalidation signal. The frontend maps the type to an existing API loader, so authorization and response redaction remain centralized in the current endpoints.

## API contract

### `GET /api/events`

Request requires the existing HTTP-only session cookie. Responses:

- `200 OK`
- `Content-Type: text/event-stream`
- `Cache-Control: no-cache, no-transform`
- `Connection: keep-alive`

Example frames:

```text
event: ready
id: 1
data: {"type":"ready","created_at":"2026-07-21T00:00:00Z"}

event: users.changed
id: 2
data: {"type":"users.changed","created_at":"2026-07-21T00:00:01Z"}

: heartbeat

```

The server sends a heartbeat at a fixed interval shorter than common reverse-proxy idle timeouts. The stream ends with an unauthorized response on the next reconnect after session revocation; an already-open stream is closed when its session no longer validates.

## Frontend behavior

The authenticated dashboard owns one `EventSource('/api/events', { withCredentials: true })` subscription. Events are deduplicated by ID and trigger the existing loaders:

| Event | Reloaded data |
|---|---|
| `audit` | audit log list |
| `proxy_hosts.changed` | proxy hosts |
| `certificates.changed` | certificates |
| `users.changed` | users |
| `roles.changed` | roles and user role options |
| `sessions.changed` | current user/session state |

The client uses bounded exponential reconnect delay and displays a non-blocking connection status. No mutation is considered successful or failed based on SSE delivery; HTTP mutation responses remain authoritative.

## Error handling and security

- Unauthenticated stream requests return the same generic `401` envelope as other authenticated APIs.
- No event contains secret values or raw backend errors.
- A full broadcast channel does not block mutation handlers; slow consumers receive a reconnect hint and must reconnect.
- Shutdown closes active streams through the hub sender lifecycle.
- Frontend errors use the existing sanitization helper and never render event payloads as trusted HTML.

## Testing strategy

Backend tests will cover authenticated and unauthenticated connections, response headers, ready and heartbeat frames, event publication after representative mutations, safe JSON payloads, `Last-Event-ID` parsing, and lagged receiver behavior. Frontend tests will mock `EventSource`, assert event-to-loader mapping, deduplication, reconnect backoff bounds, and graceful handling of unsupported or failed streams. Existing full Rust and Vitest suites remain required gates.

## Success criteria

1. A logged-in browser receives a framed SSE event after another authorized session mutates a covered resource.
2. The affected dashboard data refreshes without a timer-driven request.
3. Unauthorized users cannot subscribe, and revoked sessions cannot establish a new stream.
4. Event payloads remain redacted under the existing audit safety rules.
5. All focused and full test suites pass.
