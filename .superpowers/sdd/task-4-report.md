# Task 4 report: React realtime subscription

Implemented the authenticated dashboard realtime subscription.

## Changes

- Added `frontend/src/realtime.ts` with `useRealtimeUpdates(loaders)` and `RealtimeStatus`.
- Opens one credentialed `EventSource` at `/api/events` for the dashboard lifecycle.
- Maps `proxy_hosts.changed`, `certificates.changed`, `users.changed`, `roles.changed`, and `audit` events to the corresponding loaders.
- Tracks numeric SSE event IDs and ignores duplicate/older events and unknown event kinds.
- Reports `connecting`, `connected`, and `disconnected` status, with bounded explicit reconnect scheduling and cleanup on unmount.
- Integrated host, certificate, user, role, and audit loaders into the authenticated dashboard and added a non-blocking status label.
- Added mocked-`EventSource` Vitest coverage for event mapping, deduplication, credentials, status, reconnect cap, and cleanup.

## Verification

- `cd frontend && npm test -- --run src/realtime.test.tsx` — passed (2 tests)
- `cd frontend && npm test -- --run` — passed (4 files, 18 tests)
- `cd frontend && npm run build` — passed
- `git diff --check` — passed

