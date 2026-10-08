# Phase 3 Control Plane and GUI Design

## Goal

Deliver the first end-to-end management slice of Bearust: first-run admin setup, RBAC-protected sessions, Proxy Host CRUD, and custom certificate upload/activation through a React/Vite/Tailwind GUI.

## Scope

### In scope

- SQLite persistence for users, sessions, proxy hosts, certificates, and audit events.
- Three built-in roles: `admin`, `operator`, and `viewer`.
- Argon2id password hashing and secure HTTP-only session cookies.
- One-time first-run admin creation protected by `BEARUST_SETUP_TOKEN` (or an equivalent startup-generated token documented by the runtime).
- Proxy Host CRUD with domain, target host/port, TLS mode, certificate selection, and enabled state.
- Custom PEM certificate/key upload through the existing secure `CertificateStore`.
- Atomic persistence and data-plane reload; failed reload preserves the previous active configuration.
- React/Vite/Tailwind pages for setup, login, dashboard, Proxy Hosts, and Certificates.
- Backend/API, security, persistence, and GUI smoke tests.

### Out of scope for this slice

- Custom roles and arbitrary permission authoring.
- User invitation flows and password reset email.
- Realtime WebSocket/SSE updates.
- Let’s Encrypt issuance UI and concrete `AcmeManager` control-plane wiring (the API model may reserve `letsencrypt` as a TLS mode for the next slice).
- Multi-node synchronization and WAF management.

## Roles and permissions

| Permission | Admin | Operator | Viewer |
|---|---:|---:|---:|
| `proxy_hosts:read` | yes | yes | yes |
| `proxy_hosts:write` | yes | yes | no |
| `certificates:read` | yes | yes | yes |
| `certificates:write` | yes | yes | no |
| `users:manage` | yes | no | no |
| `roles:manage` | yes | no | no |

The API is the security boundary. GUI controls are only a convenience and must never replace backend permission checks. Certificate private keys are never returned by an API response.

## First-run setup and authentication

When `users` is empty, `GET /api/setup/status` reports an uninitialized installation and the GUI redirects to `Create Admin Account`. `POST /api/setup/initialize` accepts the setup token, username, and password, and creates exactly one `admin` in a database transaction. A uniqueness/empty-table guard makes concurrent initialization requests safe. Once successful, setup endpoints are permanently closed and normal login is required.

`POST /api/auth/login` creates a server-side session whose random token is stored only as a hash in `sessions`; the raw token is sent in an `HttpOnly`, `Secure`, `SameSite=Lax` cookie. Logout revokes the session. Session expiry and invalid credentials return generic errors without revealing account existence.

## Persistence model

- `users`: id, username, password hash, role, must-change-password flag, timestamps.
- `sessions`: id, user id, token hash, expiry, created timestamp, revoked timestamp.
- `proxy_hosts`: id, name, domains, forward host/port, TLS mode (`disabled`, `custom`, `letsencrypt`), certificate id, enabled, timestamps.
- `certificates`: id, name, source (`custom` or `letsencrypt`), store paths, expiry metadata, active flag, timestamps.
- `audit_logs`: actor, action, resource type/id, success/failure, timestamp, redacted detail.

Certificate files and keys remain under `CertificateStore`; SQLite stores metadata and references only.

## API surface

- `GET /api/setup/status`
- `POST /api/setup/initialize`
- `POST /api/auth/login`
- `POST /api/auth/logout`
- `GET /api/auth/me`
- `GET /api/proxy-hosts`
- `POST /api/proxy-hosts`
- `GET /api/proxy-hosts/:id`
- `PATCH /api/proxy-hosts/:id`
- `DELETE /api/proxy-hosts/:id`
- `GET /api/certificates`
- `POST /api/certificates` (multipart PEM/key upload)
- `GET /api/certificates/:id`
- `POST /api/certificates/:id/activate`
- Admin-only user/role endpoints for the built-in roles.

Handlers validate domains, ports, target values, TLS/certificate compatibility, ownership of referenced records, and upload size/type before mutation. Every sensitive mutation produces an audit event.

## Configuration application

The control plane writes the validated desired state, then requests a data-plane reload using the existing reload channel. A reload failure returns an error and leaves the previous active snapshot in service. Certificate activation uses the existing atomic store semantics; private key permissions and path-containment checks remain enforced by `CertificateStore`.

## GUI flow

1. Setup page when installation is uninitialized.
2. Login page after setup.
3. Dashboard with active proxy count, expiring certificates, and proxy status.
4. Proxy Hosts table and create/edit form.
5. Certificates table and custom certificate upload form with expiry/source/active status.

The GUI hides actions not allowed by the current permission set, while API responses remain authoritative. Initial status refreshes after mutations; realtime transport is deferred.

## Testing and acceptance

- Unit tests for permission matrix, password/session behavior, setup-token validation, and setup race safety.
- API tests for auth, all Proxy Host CRUD paths, certificate upload validation, activation, authorization failures, and audit events.
- Persistence tests covering SQLite migrations and restart/reload behavior.
- Integration test proving a failed data-plane reload does not replace the active configuration.
- GUI smoke test covering setup → login → create Proxy Host → upload/activate certificate.
- Compose configuration and documented local smoke commands must pass.

## Success criteria

An empty installation can be opened in a browser, initialized exactly once into an admin account, logged into, and used to create a Proxy Host and activate a valid custom certificate. Operators can manage proxy/certificate resources but not users; viewers can inspect them but cannot mutate them. Invalid certificates and failed reloads are rejected without disrupting the currently active proxy configuration.

