# Phase 4B — User Management & RBAC Design

## Goal

Melengkapi control plane Bearust dengan manajemen user dan penegakan role-based access control yang konsisten untuk role `admin`, `operator`, dan `viewer`.

## Scope

### In scope

- Admin dapat melihat daftar user.
- Admin dapat membuat user dengan role yang valid.
- Admin dapat mengubah role user.
- Admin dapat menonaktifkan atau menghapus user.
- Admin terakhir tidak boleh dihapus atau diturunkan rolenya.
- Semua endpoint control plane memeriksa permission sesuai role.
- GUI menyediakan halaman manajemen user untuk admin.
- API dan GUI menampilkan error authorization secara konsisten.
- Audit event untuk pembuatan, perubahan role, penonaktifan, dan penghapusan user.

### Out of scope

- Permission custom di luar tiga role bawaan.
- Scope permission per proxy host.
- SSO, LDAP, OAuth, dan external identity provider.
- Audit-log viewer dan filter lanjutan; dikerjakan pada Phase 4C.

## Role matrix

| Capability | Admin | Operator | Viewer |
|---|---:|---:|---:|
| Read proxy hosts | Yes | Yes | Yes |
| Write proxy hosts | Yes | Yes | No |
| Read certificates | Yes | Yes | Yes |
| Write certificates / ACME | Yes | Yes | No |
| Manage users | Yes | No | No |
| Manage roles | Yes | No | No |
| View audit events through existing operational responses | Yes | Yes | Yes |

Role names are persisted as lowercase strings and parsed through the existing `Role` enum. Unknown role values are rejected at input boundaries.

## Backend design

### Repository layer

Extend the repository with focused operations for:

- list users without password hashes;
- create a user after email/password/role validation;
- update a user role;
- disable a user or delete a user;
- count active administrators;
- reject mutations that would leave zero active administrators.

User responses must contain only `id`, `email`, `role`, `disabled` (or equivalent status), and `created_at`. Password hashes, session hashes, setup tokens, and provider secrets never leave the repository/API response.

If the existing schema does not contain an account status field, add a backward-compatible migration/default so existing accounts remain enabled.

### HTTP API

Add authenticated, admin-only endpoints:

- `GET /api/users`
- `POST /api/users`
- `PATCH /api/users/{id}`
- `DELETE /api/users/{id}`

The current user cannot remove or disable their own account through these endpoints. The last active admin cannot be removed or lose the admin role. Invalid input returns the existing structured `invalid_input` response; insufficient permission returns `403` with the existing authorization error contract; missing users return `404`.

Every successful mutation and every denied mutation records a redacted audit event. Audit details include the target user id and action outcome, never passwords or session material.

### Authorization boundary

Keep permission decisions centralized in `control_plane::rbac::allowed`. Route handlers obtain the current session user once, parse the role, and check the specific permission before repository calls. Operator/viewer behavior for existing proxy-host and certificate routes remains unchanged but gains regression coverage.

## Frontend design

Add an admin-only Users section to the existing dashboard:

- responsive table/cards showing email, role, status, and creation date;
- create-user form with email, password, and role;
- role update control;
- disable/delete action with confirmation;
- clear loading, empty, validation, and authorization-error states.

The section is not rendered for non-admin users. The backend remains authoritative; hiding controls is only a usability feature, not a security boundary.

## Error handling and security

- Enforce minimum password length already used by setup/login flows.
- Normalize email consistently with existing authentication behavior.
- Do not reveal whether a non-admin target user exists when the caller lacks permission.
- Invalidate active sessions when a user is disabled or deleted.
- Preserve the initial setup invariant: initialization is allowed only when no users exist.

## Testing strategy

### Backend

- repository tests for list/create/update/disable/delete;
- API tests for admin success and operator/viewer `403` responses;
- tests for invalid roles, duplicate emails, self-delete, and last-admin protection;
- tests proving response JSON excludes password/session fields;
- audit assertions for successful and denied mutations.

### Frontend

- API client tests for user endpoints;
- rendering test proving the Users section is admin-only;
- interaction tests for create, role update, and disable/delete error states;
- production build verification.

## Completion criteria

Phase 4B is complete when:

1. All user-management endpoints and UI flows are implemented.
2. Existing proxy/certificate routes pass role regression tests.
3. Security invariants (last admin, self-mutation, secret redaction, session invalidation) are covered by tests.
4. Rust tests, frontend tests, and frontend build pass.
5. API and role behavior are documented.

