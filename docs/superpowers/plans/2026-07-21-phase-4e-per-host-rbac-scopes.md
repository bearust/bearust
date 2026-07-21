# Phase 4E Per-host RBAC Scopes Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add safe per-proxy-host RBAC scopes for custom roles while preserving global permissions and existing clients.

**Architecture:** Store scoped assignments in the existing `role_permissions` table using `scope_type = 'proxy_host'` and `scope_id = proxy_hosts.id`. Centralize authorization in `user_has_permission`/`authorize`, then pass a `ProxyHost(id)` context from host handlers. Role APIs expose additive scope data; the frontend edits scopes through the existing role-management flow.

**Tech Stack:** Rust, Axum, SQLx SQLite, serde, React/TypeScript, Tailwind CSS v4, Vitest.

## Global Constraints

- Global permission assignments continue to grant access to every proxy host.
- Only `proxy_hosts.read` and `proxy_hosts.write` may be scoped in Phase 4E.
- Built-in roles remain immutable.
- Scoped-only users cannot create proxy hosts.
- Unauthorized host detail/update/delete responses must not reveal host existence.
- Certificate permissions remain global in this increment.
- Authorization failures are fail-closed and audit details contain no secrets.

---

### Task 1: Resource context and repository authorization

**Files:**
- Modify: `src/control_plane/rbac.rs`
- Modify: `src/control_plane/repository.rs`
- Test: `src/control_plane/rbac.rs` and repository test module

**Interfaces:**
- Produce `ResourceContext::{Global, ProxyHost(i64)}`.
- Produce `user_has_permission(pool, user_id, key, scope)` that checks global or exact host scope.
- Preserve `authorize` as the centralized handler-facing entry point.

- [ ] **Step 1: Write failing tests** for global grants, exact host grants, unassigned host denial, and unknown scope denial.
- [ ] **Step 2: Run the focused Rust tests** and verify the new cases fail.
- [ ] **Step 3: Implement the enum and SQL predicate** with `scope_type='proxy_host'` and `scope_id` matching the requested ID.
- [ ] **Step 4: Run focused tests, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`.**
- [ ] **Step 5: Commit** `feat: add per-host authorization context`.

### Task 2: Scoped role persistence and validation

**Files:**
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/repository.rs`
- Modify: `src/control_plane/mod.rs`
- Test: repository and HTTP handler tests

**Interfaces:**
- Add serializable `RolePermissionScope { permission: String, proxy_host_ids: Vec<i64> }`.
- Extend `RoleDetail`, `RoleCreate`, and `RolePatch` additively with `scopes`.
- Add repository functions to read and atomically replace scoped rows while leaving global rows unchanged.

- [ ] **Step 1: Add failing persistence/API tests** for create, replace, clear, unknown host, invalid permission, duplicate IDs, and built-in-role rejection.
- [ ] **Step 2: Run focused tests** to verify failure.
- [ ] **Step 3: Implement normalized scope validation** and a transaction that validates all host IDs before replacing only scoped rows.
- [ ] **Step 4: Include scopes in role responses** and emit `role_scopes_changed` plus `roles.changed` only after successful mutation.
- [ ] **Step 5: Run focused tests and Rust quality checks.**
- [ ] **Step 6: Commit** `feat: persist per-host role scopes`.

### Task 3: Enforce scopes in proxy-host handlers

**Files:**
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/repository.rs`
- Test: API integration tests covering proxy-host routes

**Interfaces:**
- Add `list_hosts_for_user(pool, user_id, permission)` returning globally visible or scoped hosts.
- Pass `ResourceContext::ProxyHost(id)` to detail/update/delete authorization checks.

- [ ] **Step 1: Write failing integration tests** for filtered list, scoped update/delete, denied detail/update/delete `404`, and scoped-only create `403`.
- [ ] **Step 2: Run the tests** and confirm they fail against global-only behavior.
- [ ] **Step 3: Implement filtered listing and resource-context checks**; keep existing success payloads unchanged.
- [ ] **Step 4: Remove scoped assignments when deleting a host** and preserve rollback behavior if proxy reload fails.
- [ ] **Step 5: Run the complete Rust test suite and quality checks.**
- [ ] **Step 6: Commit** `feat: enforce proxy host scopes`.

### Task 4: Admin role scope editor

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/ui.tsx` if a shared primitive is needed
- Test: `frontend/src/roles.test.tsx`

**Interfaces:**
- Consume role `scopes` and proxy-host list APIs.
- Produce role create/edit payloads containing normalized scope assignments.

- [ ] **Step 1: Write failing component tests** for rendering scope controls, selecting hosts per permission, clearing scopes, built-in-role read-only state, and narrow viewport layout.
- [ ] **Step 2: Run focused Vitest tests** and verify failure.
- [ ] **Step 3: Implement the scope editor** using existing Tailwind v4 semantic primitives and stable test IDs.
- [ ] **Step 4: Handle API validation errors** with the existing alert pattern and preserve unsaved form state.
- [ ] **Step 5: Run all frontend tests and `npm run build`.**
- [ ] **Step 6: Commit** `feat: add role scope editor`.

### Task 5: Audit, documentation, and verification gate

**Files:**
- Modify: `src/control_plane/mod.rs` or audit helper as needed
- Modify: `docs/PRD.md`
- Create: `scripts/check-legacy-classes.sh` only if a new frontend guard is required

- [ ] **Step 1: Add tests** for redacted scope audit events and realtime invalidation after scope changes.
- [ ] **Step 2: Update the PRD** with a Phase 4E status note and explicit non-goals.
- [ ] **Step 3: Run the full verification gate:** `cargo test`, `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, `npm test -- --run`, `npm run build`, `git diff --check`.
- [ ] **Step 4: Request a fresh code review** against the complete branch.
- [ ] **Step 5: Commit** `docs: complete phase 4e per-host rbac scopes` after review findings are resolved.

## Completion Criteria

- Global and scoped authorization are both covered by automated tests.
- Scoped users cannot see or mutate unassigned hosts.
- Role scope changes are atomic, audited, realtime-invalidating, and backward-compatible.
- Frontend role management exposes the capability accessibly and responsively.
- All verification commands pass on a clean feature branch.
