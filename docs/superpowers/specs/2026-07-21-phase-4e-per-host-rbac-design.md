# Phase 4E — Per-host RBAC Scope Design

## Goal

Allow custom roles to read and manage only explicitly assigned proxy hosts while preserving backward compatibility with the existing global RBAC model.

## Scope

This increment implements per-host scopes for `proxy_hosts.read` and `proxy_hosts.write`. Certificate permissions remain global because certificates are shared resources and may be referenced by multiple hosts. System settings, audit export, and account-level theme synchronization remain separate increments.

## Existing context

- `role_permissions` already contains nullable `scope_type` and `scope_id` columns reserved for scoped authorization.
- `authorize` currently accepts a `ResourceContext` but only evaluates global permissions.
- Proxy-host list/detail/create/update/delete handlers currently authorize globally and list every host.
- Built-in roles remain system-managed and immutable.

## Design

### Resource context and authorization

Replace the empty resource context with an explicit enum:

```rust
pub enum ResourceContext {
    Global,
    ProxyHost(i64),
}
```

`user_has_permission` evaluates a permission as allowed when either:

1. the user has a global assignment (`scope_type IS NULL` and `scope_id IS NULL`), or
2. the requested context is `ProxyHost(id)` and the user has an exact `scope_type = 'proxy_host'`, `scope_id = id` assignment.

Unknown scope types fail closed. Built-in roles continue to receive global assignments during idempotent initialization.

### Proxy-host behavior

- `GET /api/proxy-hosts` returns all hosts for a user with global `proxy_hosts.read`; otherwise it returns only hosts for which the user has a scoped read assignment.
- `GET /api/proxy-hosts/{id}`, `PUT /api/proxy-hosts/{id}`, and `DELETE /api/proxy-hosts/{id}` authorize against that host ID.
- A scoped-only user cannot create a host because creation has no existing resource ID; creation requires global `proxy_hosts.write`.
- Unauthorized host detail/update/delete responses use `404` to avoid revealing the existence of an inaccessible host, while recording a redacted authorization-denied audit event.
- Existing global permission behavior and response formats remain unchanged.
- Deleting a host removes its scoped role assignments so no dangling access records remain.

### Scope management API

Extend role representations without breaking existing clients:

```json
{
  "permissions": ["proxy_hosts.read"],
  "scopes": [
    {"permission": "proxy_hosts.read", "proxy_host_ids": [3, 5]}
  ]
}
```

- `GET /api/roles` and `GET /api/roles/{id}` include `scopes`.
- `POST /api/roles` and `PATCH /api/roles/{id}` accept optional `scopes`; omission preserves current scopes.
- Only `proxy_hosts.read` and `proxy_hosts.write` may be scoped in this increment.
- Scope IDs must reference existing proxy hosts; duplicate IDs are normalized away; an empty host list removes that permission's scoped assignments.
- Built-in roles reject scoped mutations with the existing immutable-role conflict response.
- Role mutation remains restricted to `roles.manage` (global admin capability).
- Invalid permission/scope combinations, unknown hosts, negative IDs, and malformed payloads return the existing `invalid_input` envelope without leaking database errors.

### Data integrity

- Keep the existing composite primary key on `role_permissions`.
- Add an index supporting `(scope_type, scope_id, permission_id)` lookups.
- Clean scoped rows when a proxy host is deleted.
- Existing global rows must remain untouched by scoped updates.

### Frontend

Add an admin-only scope editor to the existing role management UI. It lists current proxy hosts, groups them by permission, and clearly distinguishes global permissions from host-scoped permissions. The UI must preserve the current Tailwind v4 primitives and remain usable on narrow screens. API denial remains authoritative; hiding controls is not a security boundary.

## Error handling and audit

- Authorization remains fail-closed on repository errors.
- Scope changes emit `role_scopes_changed` with role ID and counts only; no secrets or request bodies are logged.
- Denied scoped access emits the existing `authorization_denied` event with a resource type and ID, never host credentials or private configuration.
- Realtime invalidation publishes `roles.changed` and `proxy_hosts.changed` after successful mutations.

## Testing strategy

Backend tests must cover:

1. global permission grants access to every host;
2. scoped read returns only assigned hosts;
3. scoped write permits update/delete on assigned hosts;
4. scoped-only users cannot create hosts;
5. access to an unassigned host returns `404` for detail/update/delete;
6. role scope create/update/remove persists and leaves global permissions intact;
7. built-in roles reject scoped mutation;
8. unknown host IDs and invalid scope permissions are rejected;
9. deleting a host removes its scope rows;
10. authorization failures remain fail-closed on database errors.

Frontend tests must cover rendering, editing, clearing, and responsive behavior of the scope editor. Run the existing full backend and frontend suites, formatting/lint checks, and the production frontend build.

## Non-goals

- Per-host certificate permissions
- Audit-log export
- System settings or account-level preference synchronization
- External database support (Phase 5)
- Cross-node scope synchronization (Phase 10)
