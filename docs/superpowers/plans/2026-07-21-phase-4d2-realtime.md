# Phase 4D.2 Realtime Updates Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add an authenticated SSE stream and React subscription that refreshes affected control-plane data after redacted realtime events without periodic polling.

**Architecture:** `AppState` owns a bounded `RealtimeHub` backed by `tokio::sync::broadcast`. The SSE handler authenticates with the existing session path, sends a ready frame and heartbeats, then forwards safe invalidation envelopes. Audit/mutation paths publish through the hub; the frontend maps event types to existing API loaders.

**Tech Stack:** Rust 2021, Axum 0.8 SSE primitives, Tokio broadcast/time/sync, Serde JSON, React, TypeScript, Vitest, existing SQLite/session/RBAC layers.

## Global Constraints

- Use the existing HTTP-only session cookie and centralized authorization; unknown roles fail closed.
- Event payloads must exclude credentials, password/session hashes, tokens, private keys, request bodies, and raw database errors.
- The event bus is process-local and bounded; slow consumers must not block mutations.
- SSE is server-to-client only; do not add WebSocket transport, durable replay, or periodic polling.
- Existing full Rust and frontend test suites must remain green.

---

### Task 1: Build the process-local realtime hub

**Files:**
- Create: `src/control_plane/realtime.rs`
- Modify: `src/control_plane/mod.rs`
- Test: `tests/control_plane_realtime.rs`

**Interfaces:**
- Produces `RealtimeHub::new(capacity: usize)`, `RealtimeHub::publish(kind: &'static str) -> RealtimeEvent`, `RealtimeHub::subscribe() -> broadcast::Receiver<RealtimeEvent>`, and serializable `RealtimeEvent { id: u64, kind: String, created_at: String }`.
- `AppState` exposes `pub realtime: Arc<RealtimeHub>` and constructors initialize it with capacity `256`.

- [ ] **Step 1: Write failing hub tests**

```rust
#[tokio::test]
async fn hub_assigns_monotonic_ids_and_drops_slow_subscribers_without_blocking() {
    let hub = RealtimeHub::new(1);
    let mut receiver = hub.subscribe();
    hub.publish("users.changed");
    let first = receiver.recv().await.unwrap();
    assert_eq!(first.id, 1);
    hub.publish("roles.changed");
    hub.publish("certificates.changed");
    assert!(matches!(receiver.recv().await, Err(tokio::sync::broadcast::error::RecvError::Lagged(1))));
}
```

- [ ] **Step 2: Run the focused test and verify it fails**

Run: `cargo test --test control_plane_realtime hub_assigns_monotonic_ids_and_drops_slow_subscribers_without_blocking`

Expected: FAIL because `realtime` and `AppState.realtime` do not exist.

- [ ] **Step 3: Implement the hub and state wiring**

Use an `AtomicU64` sequence and `broadcast::channel(capacity)`. `publish` constructs an RFC3339 UTC timestamp with millisecond precision, sends with `let _ = sender.send(event.clone())`, and returns the event. Add `pub mod realtime;`, a `realtime` field to `AppState`, and initialize it in both `build_state` paths through `build_state`.

- [ ] **Step 4: Run focused tests**

Run: `cargo test --test control_plane_realtime hub_assigns_monotonic_ids_and_drops_slow_subscribers_without_blocking`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/control_plane/realtime.rs src/control_plane/mod.rs tests/control_plane_realtime.rs
git commit -m "feat: add control plane realtime hub"
```

### Task 2: Add the authenticated SSE endpoint

**Files:**
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/realtime.rs`
- Test: `tests/control_plane_realtime.rs`

**Interfaces:**
- Produces `GET /api/events` with `text/event-stream` output and `Cache-Control: no-cache, no-transform`.
- Consumes `AppState.realtime`, `current(&state, &headers)`, `Last-Event-ID`, and the hub receiver.

- [ ] **Step 1: Write failing endpoint tests**

Add tests that call `/api/events` without a cookie and assert `401`, then create a session, call the endpoint, assert status `200` and headers, publish `users.changed`, and assert the body begins with `event: ready`, includes `id: 1`, and includes `event: users.changed`. Add a test that passes `Last-Event-ID: 17` and asserts the stream still starts at a new ready event without replaying old data.

- [ ] **Step 2: Run endpoint tests to verify failure**

Run: `cargo test --test control_plane_realtime events_endpoint`

Expected: FAIL because the route is not registered.

- [ ] **Step 3: Implement SSE framing and stream lifecycle**

Use Axum `response::sse::{Event, KeepAlive, Sse}` and a `tokio_stream::wrappers::BroadcastStream`-style stream (or an equivalent `async_stream`-free `futures_util::stream::unfold`). Authenticate before subscribing. Emit a `ready` event, forward broadcast events as `event: <kind>` with JSON data, convert lagged receivers into a `reconnect` event, ignore `Last-Event-ID` for replay, and configure a 15-second comment heartbeat. Return generic `401` using the existing error envelope for unauthenticated requests.

- [ ] **Step 4: Run focused endpoint tests**

Run: `cargo test --test control_plane_realtime events_endpoint`

Expected: PASS with correct headers and frames.

- [ ] **Step 5: Commit**

```bash
git add src/control_plane/mod.rs src/control_plane/realtime.rs tests/control_plane_realtime.rs
git commit -m "feat: expose authenticated realtime event stream"
```

### Task 3: Publish safe invalidation events from mutations

**Files:**
- Modify: `src/control_plane/audit.rs`
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/auth.rs`
- Test: `tests/control_plane_realtime.rs`

**Interfaces:**
- Produces `audit::record_state(&AppState, Option<i64>, event, details)` which writes the existing redacted audit row and publishes `audit`.
- Mutation handlers publish one domain event after successful host, certificate, user, role, or session changes; denial paths publish only `audit`.

- [ ] **Step 1: Add failing publication tests**

Subscribe to `state.realtime`, perform authenticated create-user, create-role, proxy-host, certificate activation, and session-revoke requests using the existing test helpers, collect events with a bounded timeout, and assert the matching domain kinds plus `audit`. Assert serialized event JSON does not contain passwords, setup tokens, cookie values, or private-key markers.

- [ ] **Step 2: Run the publication tests to verify failure**

Run: `cargo test --test control_plane_realtime publishes_domain_events_without_secrets`

Expected: FAIL because handlers currently only write SQLite audit rows.

- [ ] **Step 3: Introduce state-aware audit publication and domain hooks**

Keep `audit::record(&SqlitePool, ...)` for repository-only callers, add `record_state` for handlers with `AppState`, and replace handler calls in auth, users, roles, proxy hosts, and certificates where the state is available. Publish `users.changed`, `roles.changed`, `proxy_hosts.changed`, `certificates.changed`, or `sessions.changed` only after the corresponding mutation succeeds. Preserve non-fatal audit write behavior and redacted detail strings.

- [ ] **Step 4: Run focused and regression tests**

Run: `cargo test --test control_plane_realtime --test control_plane_audit --test control_plane_roles --test control_plane_users`

Expected: all tests PASS, including existing audit assertions.

- [ ] **Step 5: Commit**

```bash
git add src/control_plane/audit.rs src/control_plane/mod.rs src/control_plane/auth.rs tests/control_plane_realtime.rs
git commit -m "feat: publish safe control plane change events"
```

### Task 4: Add the React realtime subscription

**Files:**
- Create: `frontend/src/realtime.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/api.ts`
- Test: `frontend/src/realtime.test.ts`

**Interfaces:**
- Produces `useRealtimeUpdates(loaders)` and `RealtimeStatus` (`connecting | connected | disconnected`).
- Consumes browser `EventSource`, `withCredentials`, existing `api` loaders, and the authenticated dashboard lifecycle.

- [ ] **Step 1: Write failing Vitest tests**

Mock `globalThis.EventSource`, mount the hook with `auditLogs`, `hosts`, and `certificates` spies, dispatch `users.changed`, `proxy_hosts.changed`, `audit`, duplicate IDs, and an `error` callback, then assert only mapped loaders run and reconnect delay is capped. Assert `EventSource` is closed on unmount.

- [ ] **Step 2: Run the frontend test to verify failure**

Run: `cd frontend && npm test -- --run src/realtime.test.ts`

Expected: FAIL because the hook/module is missing.

- [ ] **Step 3: Implement the subscription hook**

Create one `EventSource('/api/events', { withCredentials: true })`, track the last numeric event ID in a ref, ignore duplicates and unknown kinds, map kinds to supplied async loaders, and set status on open/error. Use a bounded reconnect timer only when the browser does not automatically reconnect; always clear timers and close the source during cleanup. Do not add any interval-based fetch.

- [ ] **Step 4: Integrate it into the authenticated dashboard**

Pass existing loaders for hosts, certificates, users, roles, and audit logs from the authenticated `App` branch. Render a small non-blocking `Realtime: connected/disconnected` status and keep HTTP mutation responses authoritative.

- [ ] **Step 5: Run frontend tests and build**

Run: `cd frontend && npm test -- --run && npm run build`

Expected: all Vitest tests PASS and Vite production build exits `0`.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/realtime.ts frontend/src/realtime.test.ts frontend/src/App.tsx frontend/src/api.ts
git commit -m "feat: refresh dashboard from realtime events"
```

### Task 5: Final verification and documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/PRD.md`

- [ ] **Step 1: Document Phase 4D.2 status and operational limits**

Add a concise status section stating SSE endpoint, session-cookie authentication, process-local delivery, heartbeat/reconnect behavior, and that cross-node replay is deferred.

- [ ] **Step 2: Run all verification gates**

Run:

```bash
docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked
cd frontend && npm test -- --run && npm run build
cd .. && git diff --check
```

Expected: Rust tests, frontend tests, frontend build, and whitespace checks all pass. If `cargo fmt --check` reports unrelated pre-existing formatting, record it without mass-formatting unrelated files.

- [ ] **Step 3: Commit documentation and verify status**

```bash
git add README.md docs/PRD.md
git commit -m "docs: mark phase 4d2 realtime updates complete"
git status --short --branch
```

Expected: only the known untracked `.claude/` workspace metadata remains, and `main` contains the Phase 4D.2 commits.
