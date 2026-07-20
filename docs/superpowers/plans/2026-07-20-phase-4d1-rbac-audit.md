# Phase 4D.1 Persistent RBAC and Audit Coverage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add persistent custom roles and global permissions, administrative session revocation, centralized authorization, and complete safe audit coverage while preserving existing Phase 4 behavior.

**Architecture:** Keep the current SQLite control-plane repository and additive migration style. Add relational `roles`, `permissions`, and `role_permissions` tables with nullable future scope columns, preserve the existing `users.role` string during compatibility migration, and resolve authorization through a centralized permission service. Extend the existing Axum handlers and React dashboard without changing session cookie format or exposing secrets.

**Tech Stack:** Rust 1.84, Axum 0.8, SQLx 0.8 SQLite, Tokio, Serde, Argon2, Chrono, React, TypeScript, Vitest.

## Global Constraints

- Built-in role slugs `admin`, `operator`, and `viewer` are system-managed and cannot be renamed, permission-edited, or deleted through the API.
- The ten permission keys are `proxy_hosts.read`, `proxy_hosts.write`, `certificates.read`, `certificates.write`, `users.manage`, `roles.manage`, `audit_logs.read`, `audit_logs.export`, `system.settings.manage`, and `sessions.revoke`.
- Phase 4D.1 evaluates global permissions only; `scope_type` and `scope_id` remain nullable for future per-host scope.
- `audit_logs.export` and `system.settings.manage` are seeded but do not authorize an endpoint in this increment.
- Existing users, session cookie format, last-active-admin protection, and Phase 4C audit redaction behavior must remain compatible.
- Authorization failures fail closed and client responses must not expose raw SQL errors, password hashes, session tokens, private keys, request bodies, or credentials.
- Every implementation task must add focused tests before implementation and run the narrow test before the full regression suite.

---

## File map

- Modify `src/control_plane/models.rs`: role, permission, role-request, role-response, and session-revocation DTOs.
- Modify `src/control_plane/rbac.rs`: permission keys and centralized authorization abstractions.
- Modify `src/control_plane/repository.rs`: additive migration, seeds, role/permission queries, role assignment compatibility, and session revocation.
- Modify `src/control_plane/mod.rs`: application wiring, role/session routes, permission checks, and audit coverage.
- Modify `src/control_plane/auth.rs`: actor-aware logout audit and session lookup helpers where needed.
- Modify `src/control_plane/audit.rs`: structured safe details helpers if required by handler coverage.
- Modify `frontend/src/api.ts`: role and session-revocation API contracts.
- Modify `frontend/src/App.tsx`: administrator role management and session-revocation controls.
- Modify `frontend/src/users.test.tsx`: role/session UI and API contract tests.
- Create or modify `tests/control_plane_roles.rs`: role lifecycle and HTTP authorization tests.
- Modify `tests/control_plane_repository.rs`: migration, role, assignment, and session repository tests.
- Modify `tests/control_plane_users.rs`: regression tests for permission enforcement and revocation.
- Modify `tests/control_plane_audit.rs`: audit coverage and redaction regression tests.

---

### Task 1: Add failing repository tests for persistent RBAC

**Files:**
- Modify: `tests/control_plane_repository.rs`
- Create: `tests/control_plane_roles.rs`

**Interfaces:**
- Consumes: existing `repository::connect`, `repository::migrate`, `repository::insert_user`, and `SqlitePool` test helpers.
- Produces: executable expectations for `list_roles`, `insert_role`, `update_role`, `delete_role`, `set_role_permissions`, `role_permissions`, `user_has_permission`, and built-in seed behavior.

- [ ] **Step 1: Add migration/seed tests**

```rust
#[tokio::test]
async fn migration_seeds_builtin_roles_and_all_permissions_idempotently() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    repository::migrate(&pool).await.unwrap();

    let roles: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM roles WHERE system_managed=1")
        .fetch_one(&pool).await.unwrap();
    let permissions: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM permissions")
        .fetch_one(&pool).await.unwrap();
    assert_eq!(roles, 3);
    assert_eq!(permissions, 10);
    assert_eq!(repository::role_by_slug(&pool, "admin").await.unwrap().unwrap().slug, "admin");
}
```

- [ ] **Step 2: Add custom-role lifecycle tests**

```rust
#[tokio::test]
async fn custom_role_permissions_can_change_while_assigned_but_assigned_role_cannot_delete() {
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    let role = repository::insert_role(&pool, "security-auditor", "Security Auditor", "custom role")
        .await.unwrap();
    repository::set_role_permissions(&pool, role.id, &["audit_logs.read"])
        .await.unwrap();
    let user = repository::insert_user(&pool, "auditor@example.com", "hash", &role.slug)
        .await.unwrap();

    repository::set_role_permissions(&pool, role.id, &["audit_logs.read", "sessions.revoke"])
        .await.unwrap();
    assert!(repository::user_has_permission(&pool, user.id, "sessions.revoke", None)
        .await.unwrap());
    assert!(repository::delete_role(&pool, role.id).await.is_err());
}
```

- [ ] **Step 3: Run the focused tests and verify failure**

Run: `cargo test --test control_plane_repository --test control_plane_roles migration_seeds_builtin_roles_and_all_permissions_idempotently custom_role_permissions_can_change_while_assigned_but_assigned_role_cannot_delete`

Expected: FAIL because the role DTOs and repository functions do not exist yet.

- [ ] **Step 4: Commit the failing tests**

```bash
git add tests/control_plane_repository.rs tests/control_plane_roles.rs
git commit -m "test: define persistent rbac repository contracts"
```

### Task 2: Implement RBAC schema, seeds, and repository layer

**Files:**
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/repository.rs`
- Modify: `tests/control_plane_repository.rs`

**Interfaces:**
- Consumes: Task 1 tests and existing `User`/`Role` models.
- Produces: `RoleRecord`, `PermissionRecord`, `RoleDetail`, `insert_role`, `get_role`, `list_roles`, `update_role`, `delete_role`, `set_role_permissions`, `role_permissions`, `role_by_slug`, `user_has_permission`, and additive idempotent migrations.

- [ ] **Step 1: Define DTOs and repository error classification**

Add serializable read models with fields `id: i64`, `slug: String`, `name: String`, `description: String`, `system_managed: bool`, and `permissions: Vec<String>`. Add request models for role creation/patching with optional `name`, `description`, and `permissions`. Keep permission keys validated against the seeded key set before SQL writes.

- [ ] **Step 2: Add additive tables and seed data**

Extend `repository::migrate` with tables equivalent to:

```sql
CREATE TABLE IF NOT EXISTS roles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  slug TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  system_managed INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS permissions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  key TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS role_permissions (
  role_id INTEGER NOT NULL,
  permission_id INTEGER NOT NULL,
  scope_type TEXT,
  scope_id INTEGER,
  PRIMARY KEY (role_id, permission_id, scope_type, scope_id),
  FOREIGN KEY(role_id) REFERENCES roles(id) ON DELETE CASCADE,
  FOREIGN KEY(permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);
```

Use `INSERT OR IGNORE` only for stable seed identities. Seed all ten permission keys and built-in role assignments matching current behavior: admin receives all ten; operator receives proxy/certificate read/write; viewer receives proxy/certificate read and audit log read. Ensure a second migration call creates no duplicates.

- [ ] **Step 3: Implement role and permission queries**

Implement repository functions with existing `SqlitePool` style and safe error classification:

```rust
pub async fn list_roles(pool: &SqlitePool) -> Result<Vec<RoleDetail>, sqlx::Error>;
pub async fn role_by_slug(pool: &SqlitePool, slug: &str) -> Result<Option<RoleDetail>, sqlx::Error>;
pub async fn get_role(pool: &SqlitePool, id: i64) -> Result<Option<RoleDetail>, sqlx::Error>;
pub async fn insert_role(pool: &SqlitePool, slug: &str, name: &str, description: &str) -> Result<RoleDetail, sqlx::Error>;
pub async fn update_role(pool: &SqlitePool, id: i64, name: Option<&str>, description: Option<&str>) -> Result<Option<RoleDetail>, sqlx::Error>;
pub async fn set_role_permissions(pool: &SqlitePool, role_id: i64, keys: &[&str]) -> Result<RoleDetail, sqlx::Error>;
pub async fn delete_role(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error>;
pub async fn user_has_permission(pool: &SqlitePool, user_id: i64, key: &str, scope: Option<(&str, i64)>) -> Result<bool, sqlx::Error>;
```

Use a transaction for permission replacement. Reject system-managed role mutation with a protocol error that handlers map to a stable conflict/forbidden response. Reject deletion when `users.role` references the role slug. For Phase 4D.1, only rows with null scope are considered.

- [ ] **Step 4: Run repository tests**

Run: `cargo test --test control_plane_repository --test control_plane_roles`

Expected: PASS, including existing user/session tests.

- [ ] **Step 5: Run formatting and commit**

```bash
cargo fmt --check
git add src/control_plane/models.rs src/control_plane/repository.rs tests/control_plane_repository.rs tests/control_plane_roles.rs
git commit -m "feat: persist roles and permissions"
```

### Task 3: Replace hardcoded checks with centralized permission authorization

**Files:**
- Modify: `src/control_plane/rbac.rs`
- Modify: `src/control_plane/mod.rs`
- Modify: `tests/control_plane_users.rs`
- Modify: `tests/control_plane_audit.rs`

**Interfaces:**
- Consumes: Task 2 `user_has_permission` and role seed assignments.
- Produces: `PermissionKey`, `ResourceContext`, and `authorize(&SqlitePool, &User, PermissionKey, ResourceContext) -> Result<bool, sqlx::Error>` used by every control-plane handler.

- [ ] **Step 1: Add failing authorization tests**

Add tests proving a seeded operator can write hosts/certificates, a seeded viewer cannot write them, only an admin can manage users/roles, and a custom role change affects the next request without re-login.

```rust
assert_eq!(json(app.clone(), "POST", "/api/proxy-hosts", Some(&viewer_cookie), body).await.0,
           StatusCode::FORBIDDEN);
assert!(repository::user_has_permission(&state.db, custom_user.id, "sessions.revoke", None)
    .await.unwrap());
```

- [ ] **Step 2: Define stable permission keys and context**

Replace handler-facing `Permission` matching with a string-backed enum or equivalent stable key type. Preserve a conversion for existing tests, but make `authorize` query persistent assignments and return false on unknown role or database lookup failure.

- [ ] **Step 3: Update every handler authorization branch**

Change `current`-authenticated handlers for proxy hosts, certificates, users, audit logs, and roles to call `authorize`. Do not use `unwrap_or(Role::Viewer)` as the effective authorization path; unknown persisted roles must fail closed. Keep denial responses generic and retain the actor ID in denial audit events.

- [ ] **Step 4: Run focused and regression tests**

Run: `cargo test --test control_plane_users --test control_plane_audit`

Expected: PASS with existing role behavior preserved and new persistent permission checks enforced.

- [ ] **Step 5: Commit**

```bash
git add src/control_plane/rbac.rs src/control_plane/mod.rs tests/control_plane_users.rs tests/control_plane_audit.rs
git commit -m "feat: centralize persistent permission checks"
```

### Task 4: Add role management API and audit events

**Files:**
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/audit.rs`
- Create: `tests/control_plane_roles.rs`

**Interfaces:**
- Consumes: Task 3 authorization service and Task 2 role repository functions.
- Produces: `GET/POST/PATCH/DELETE /api/roles` handlers and stable JSON error envelopes.

- [ ] **Step 1: Add failing HTTP tests**

Cover:

- admin lists seeded roles and ten permissions;
- non-admin receives `403`;
- admin creates a custom role;
- admin updates custom metadata and permissions;
- built-in role update/delete returns conflict/forbidden;
- assigned custom role deletion returns conflict;
- invalid permission key returns `400`;
- each mutation writes the expected audit event.

- [ ] **Step 2: Add role routes and validation**

Register:

```rust
.route("/api/roles", get(list_roles).post(create_role))
.route("/api/roles/{id}", get(get_role).patch(update_role).delete(delete_role))
```

Normalize slug to lowercase kebab-case, require a non-empty name, reject unknown permission keys, and reject scope fields because Phase 4D.1 is global-only. Return safe `invalid_input`, `forbidden`, `conflict`, and `database_error` envelopes.

- [ ] **Step 3: Record safe role audit details**

Record `role_created`, `role_updated`, `role_deleted`, `role_mutation_denied`, and `role_permissions_changed`. Serialize only role ID/slug and sorted permission keys before/after. Never include SQL error text or request credentials.

- [ ] **Step 4: Run role HTTP tests**

Run: `cargo test --test control_plane_roles`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/control_plane/models.rs src/control_plane/mod.rs src/control_plane/audit.rs tests/control_plane_roles.rs
git commit -m "feat: add custom role management api"
```

### Task 5: Implement administrative session revocation

**Files:**
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/repository.rs`
- Modify: `src/control_plane/mod.rs`
- Modify: `tests/control_plane_users.rs`
- Modify: `tests/control_plane_repository.rs`

**Interfaces:**
- Consumes: Task 3 `sessions.revoke` permission and existing `revoke_user_sessions` repository pattern.
- Produces: `POST /api/users/{id}/sessions/revoke`, returning `{ "revoked": <number> }` with no token material.

- [ ] **Step 1: Add failing repository and HTTP tests**

Create two sessions for a target user, revoke them as admin, assert the count and assert both sessions fail `GET /api/auth/me`. Assert a caller cannot target their own user ID and a role without `sessions.revoke` receives `403`.

- [ ] **Step 2: Add route and handler**

Register `POST /api/users/{id}/sessions/revoke`. Authenticate the caller, require `sessions.revoke`, reject `caller.id == target_id`, verify target existence, revoke only active sessions, and return the count. Use generic errors for missing targets and database failures.

- [ ] **Step 3: Add audit events**

Record `sessions_revoked` with actor ID, target user ID, and count; record `session_revoke_denied` for authorization, self-target, and missing-target branches. Never record session IDs, cookie values, token hashes, or raw errors.

- [ ] **Step 4: Run focused tests**

Run: `cargo test --test control_plane_users --test control_plane_repository`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/control_plane/models.rs src/control_plane/repository.rs src/control_plane/mod.rs tests/control_plane_users.rs tests/control_plane_repository.rs
git commit -m "feat: add administrative session revocation"
```

### Task 6: Complete configuration-change audit coverage

**Files:**
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/auth.rs`
- Modify: `src/control_plane/audit.rs`
- Modify: `tests/control_plane_audit.rs`

**Interfaces:**
- Consumes: Task 3 centralized authorization and Task 4/5 audit conventions.
- Produces: consistent actor-aware audit records for all implemented control-plane mutations.

- [ ] **Step 1: Add failing audit coverage tests**

Exercise successful and denied paths for proxy-host create/update/delete, certificate upload/activate/issue/renew, user create/update/delete, role changes, session revoke, login/logout, and authorization denial. Assert event names, actor labels, and absence of sensitive values.

- [ ] **Step 2: Normalize audit helper usage**

Use a single safe detail builder for resource IDs and reasons. Capture the authenticated actor for logout before revoking the session. For unauthenticated login failures, use an explicit anonymous/system actor convention. Replace inline raw error details, such as certificate reload errors, with stable error codes.

- [ ] **Step 3: Audit every early return that represents a mutation denial**

For each control-plane mutation handler, record a denial event before returning `400`, `403`, `404`, `409`, or `502` when the event represents an attempted configuration change. Keep audit write failures non-fatal and keep client envelopes generic.

- [ ] **Step 4: Run audit tests and full Rust suite**

Run: `cargo test --test control_plane_audit`

Then run: `cargo test`

Expected: PASS with no secret strings in serialized audit responses.

- [ ] **Step 5: Commit**

```bash
git add src/control_plane/mod.rs src/control_plane/auth.rs src/control_plane/audit.rs tests/control_plane_audit.rs
git commit -m "fix: complete control plane audit coverage"
```

### Task 7: Add frontend role and session administration

**Files:**
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/users.test.tsx`

**Interfaces:**
- Consumes: Task 4 role API and Task 5 session-revocation API.
- Produces: typed `Role`/`Permission` contracts, admin-only role management UI, and a user-row session revoke action.

- [ ] **Step 1: Add failing API/component tests**

Assert `api.roles`, `api.createRole`, `api.updateRole`, `api.deleteRole`, and `api.revokeUserSessions` use the correct paths/methods. Render an admin and assert role CRUD controls and session revoke controls appear; render operator/viewer and assert they do not appear. Assert generic sanitized errors are shown.

- [ ] **Step 2: Add TypeScript API contracts**

Add:

```ts
type PermissionKey = "proxy_hosts.read" | "proxy_hosts.write" | "certificates.read" | "certificates.write" | "users.manage" | "roles.manage" | "audit_logs.read" | "audit_logs.export" | "system.settings.manage" | "sessions.revoke";
type RoleRecord = { id:number; slug:string; name:string; description:string; system_managed:boolean; permissions:PermissionKey[] };
```

Add API methods matching the backend routes and keep request errors passed through existing sanitization.

- [ ] **Step 3: Add admin-only role management**

Render a role card/table only for `user.role === "admin"`. Show system-managed roles as read-only. Allow custom role creation, metadata editing, permission checkbox selection, and deletion only when the API permits it. Refresh role data after mutations.

- [ ] **Step 4: Add session revoke control**

Add a confirmed “Revoke sessions” action to other users’ rows. Do not render it for the current user. Show the returned revoked count and use the existing generic user error sanitizer.

- [ ] **Step 5: Run frontend tests and build**

Run: `cd frontend && npm test -- --run users.test.tsx && npm run build`

Expected: PASS and a successful TypeScript/Vite build.

- [ ] **Step 6: Commit**

```bash
git add frontend/src/api.ts frontend/src/App.tsx frontend/src/users.test.tsx
git commit -m "feat: add role and session administration ui"
```

### Task 8: Final regression, security checks, and documentation

**Files:**
- Modify: `docs/PRD.md` (Phase 4D.1 status only)
- Modify: `tests/control_plane_roles.rs` if final gaps are discovered
- Modify: `tests/control_plane_audit.rs` if final gaps are discovered

**Interfaces:**
- Consumes: all previous tasks.
- Produces: verified Phase 4D.1 increment with documented status and no untracked implementation gaps.

- [ ] **Step 1: Run formatting, lint, and all backend tests**

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Expected: all commands exit 0.

- [ ] **Step 2: Run all frontend checks**

```bash
cd frontend
npm test -- --run
npm run build
```

Expected: all tests pass and the production bundle builds.

- [ ] **Step 3: Run secret-boundary searches**

```bash
grep -RInE 'password_hash|token_hash|bearust_session=|private_key|request_body' src/control_plane frontend/src tests/control_plane_roles.rs tests/control_plane_audit.rs
```

Review every match and confirm it is persistence/test setup or a redaction assertion, never a serialized API response or UI rendering path.

- [ ] **Step 4: Update PRD status**

Add a concise Phase 4D.1 status subsection documenting persistent custom roles/global permissions, built-in role immutability, administrative session revocation, and audit coverage. Explicitly leave per-host scope, SSE, and frontend design-system work assigned to later increments.

- [ ] **Step 5: Inspect diff and commit verification**

```bash
git diff --check
git status --short
git log --oneline -10
```

Commit the status documentation and any final test-only changes:

```bash
git add docs/PRD.md tests
git commit -m "docs: record phase 4d1 completion status"
```

## Verification checklist

- [ ] Additive migration runs twice without duplicate roles or permissions.
- [ ] Existing users and sessions remain compatible.
- [ ] Built-in roles remain immutable.
- [ ] Custom role CRUD and permission replacement work while assigned.
- [ ] Assigned custom roles cannot be deleted.
- [ ] All ten permission keys are seeded; only implemented permissions authorize routes.
- [ ] Session revocation affects target sessions and cannot target the caller.
- [ ] Every implemented configuration mutation and denial path has safe audit coverage.
- [ ] Audit output remains redacted at the read boundary.
- [ ] Backend and frontend tests, formatting, clippy, and build pass.
