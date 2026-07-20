# Phase 4D.1 — Persistent RBAC and Audit Coverage

## Status

Approved design for implementation planning.

## Goal

Complete the first incremental RBAC layer after Phase 4C by adding persistent custom roles and permissions, preserving compatibility with the existing global role model, implementing administrative session revocation, and making configuration-change auditing consistent.

This increment intentionally does **not** implement per-host authorization, audit-log export, or system-settings management. The schema will reserve a scope representation so those capabilities can be added without replacing the RBAC model.

## Scope

### Included

- Persistent roles, permissions, and role-permission assignments.
- Ten global permission keys:
  - `proxy_hosts.read`
  - `proxy_hosts.write`
  - `certificates.read`
  - `certificates.write`
  - `users.manage`
  - `roles.manage`
  - `audit_logs.read`
  - `audit_logs.export`
  - `system.settings.manage`
  - `sessions.revoke`
- System-managed built-in roles: `admin`, `operator`, and `viewer`.
- Custom role CRUD for administrators.
- Direct permission changes on custom roles, including roles currently assigned to users.
- Compatibility with existing users whose role is stored as a role string.
- Administrative revocation of another user’s active sessions.
- Centralized permission evaluation for control-plane handlers.
- Consistent audit events for role, user, session, proxy-host, and certificate mutations and authorization denials.
- Migration/seed behavior that guarantees built-in roles and permission definitions exist.
- Nullable scope metadata on role-permission assignments; Phase 4D.1 uses global scope only.

### Excluded

- Per-host or per-resource authorization enforcement.
- Audit-log export endpoint, despite seeding `audit_logs.export`.
- System-settings endpoint, despite seeding `system.settings.manage`.
- External authentication/SSO.
- Database engine portability; Phase 5 remains responsible for PostgreSQL/MySQL support.
- SSE/WebSocket realtime updates; those belong to Phase 4D.2.
- Tailwind/theme redesign; that belongs to Phase 4D.3.

## Design

### Persistence model

Add the following tables through the existing automatic migration mechanism:

- `roles`: stable `slug`, display name, description, `system_managed` flag, and timestamps.
- `permissions`: stable unique permission `key` and description.
- `role_permissions`: role/permission relation with nullable `scope_type` and `scope_id`, plus a uniqueness constraint. A null scope represents a global permission in this increment.

Keep the existing user role representation during the compatibility transition. Built-in role slugs continue to resolve existing users, while new authorization code resolves role permissions through the persistent role model. Existing data must remain usable after migration without requiring a manual conversion step.

Built-in roles are seeded idempotently and are immutable through the public API. Their slug, identity, and permission assignments cannot be edited or deleted by administrators. Custom roles may be created, renamed, permission-edited, and deleted. A custom role that is assigned to one or more users cannot be deleted until those assignments are moved or removed.

### Permission service

Introduce one control-plane authorization service as the only handler-facing permission check. Its conceptual interface is:

```text
authorize(user, permission_key, resource_context) -> allowed/denied
```

`resource_context` is present for forward compatibility with per-host scope. Phase 4D.1 evaluates only global assignments. Existing handlers should transition away from direct hardcoded enum checks so future permission changes are centralized.

The existing built-in role behavior must remain equivalent unless an explicit persistent permission assignment says otherwise. Unknown or invalid persisted roles fail closed.

### API

Add administrator-protected role endpoints:

- `GET /api/roles`
- `POST /api/roles`
- `GET /api/roles/{id}`
- `PATCH /api/roles/{id}`
- `DELETE /api/roles/{id}`

Role responses expose identity, display metadata, system-managed status, and permission keys. They never expose passwords, session tokens, hashes, or other secrets.

Add an administrator-protected user-session endpoint:

- `POST /api/users/{id}/sessions/revoke`

It revokes all active sessions for the target user and returns a safe result. It cannot be used to revoke the caller’s own sessions through this administrative endpoint. A missing user is reported without leaking database details.

`audit_logs.export` and `system.settings.manage` are seeded but do not authorize any new endpoint in this increment.

### Audit events

Add or normalize events for:

- `role_created`
- `role_updated`
- `role_deleted`
- `role_mutation_denied`
- `role_permissions_changed`
- `sessions_revoked`
- `session_revoke_denied`
- proxy-host create/update/delete success and denial paths;
- certificate upload/activation/renewal/issuance success and denial paths;
- user create/update/delete success and denial paths;
- authorization denials generally.

Role-permission changes record permission keys before and after. Details must remain safe for the existing audit read-boundary sanitizer and must never include credentials, session tokens, password hashes, private keys, request bodies, or raw database errors. Logout should retain the authenticated actor where a valid session is available; unauthenticated failures remain anonymous/system events as appropriate.

### Error handling and invariants

- Built-in role mutation returns a stable conflict/forbidden error and creates a denial audit event.
- Deleting an assigned custom role returns a conflict and leaves all assignments intact.
- Invalid permission keys are rejected before persistence.
- Duplicate role slugs/names follow the existing safe conflict envelope without exposing SQL details.
- Permission changes take effect for subsequent requests without requiring user reassignment or process restart.
- Existing last-active-admin protections remain unchanged.
- Authorization failures fail closed.
- Audit-recording failures must not expose sensitive database errors to clients.

## Acceptance criteria

1. A migration on an existing database creates and seeds all roles and permissions idempotently.
2. Existing users can still authenticate and authorize after migration.
3. Administrators can list, create, inspect, update, and delete custom roles.
4. Built-in `admin`, `operator`, and `viewer` roles cannot be renamed, permission-edited, or deleted.
5. A custom role assigned to users can have its permissions changed directly; the next request observes the new permissions.
6. An assigned custom role cannot be deleted until no user references it.
7. Global permissions govern the existing proxy-host, certificate, user, role, audit-log, and session-revocation operations.
8. `POST /api/users/{id}/sessions/revoke` revokes all active sessions for another user and prevents those sessions from authenticating afterward.
9. The caller cannot revoke their own sessions through the administrative endpoint.
10. Permission and role mutations, session revocations, configuration changes, and authorization denials generate safe audit events.
11. Audit responses continue to redact secrets and never expose raw database errors.
12. Permission keys `audit_logs.export` and `system.settings.manage` exist in persistence but do not expose unimplemented operations.
13. Automated tests cover migration idempotency, built-in immutability, custom-role lifecycle, active assignment behavior, permission enforcement, session revocation, audit coverage, and fail-closed behavior.

## Testing strategy

- Repository tests for migration/seed idempotency, role/permission CRUD, assignments, and session revocation.
- Control-plane HTTP tests for authorization, stable error envelopes, built-in immutability, assigned-role deletion protection, and caller self-revocation protection.
- Regression tests for existing login, user management, proxy-host, certificate, and audit-viewer behavior.
- Security-focused assertions that responses and audit rows do not contain passwords, hashes, tokens, private keys, request bodies, or raw database errors.
- Frontend API/component tests for role administration and session-revocation controls if those controls are included in the existing management UI during implementation.

## Rollout and compatibility

The migration must be additive and idempotent. Existing role strings remain readable while the persistent role model is introduced. The implementation should avoid changing session cookie format or invalidating all existing sessions. A later increment may replace the compatibility role string with a foreign-key assignment after a dedicated migration and rollout plan.
