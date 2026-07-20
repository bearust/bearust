# BeaRust

![BeaRust](docs/logo.png)

BeaRust is a configuration-driven reverse proxy and load balancer. It supports HTTP/1.1, host/path routing, round-robin and least-connections balancing, TCP/HTTP backend health checks, WebSocket passthrough, JSON logs, graceful shutdown, atomic `SIGHUP` reloads, native TLS, custom certificates, and authenticated ACME certificate automation (HTTP-01 and Cloudflare DNS-01).

## Five-minute start

```sh
cp .env.example .env
docker compose up -d --build
curl -H 'Host: api.example.com' http://127.0.0.1:8080/v1/health
```

For the development compose file, build the UI once before opening the management page:

```sh
npm ci --prefix frontend && npm run build --prefix frontend
docker compose -f docker-compose.dev.yml up -d --build
```

Edit `config/bearust.example.toml` (or set `BEARUST_CONFIG`) for backends. Mount persistent `./data` and a read-only `./tls` directory (override with `BEARUST_DATA`/`BEARUST_TLS`). Reload with `docker compose kill -s HUP bearust` or `bearust reload --pid-file ./bearust.pid`. Configuration is TOML with `[server]`, `[health]`, `[[upstream_pools]]`, and `[[routes]]` tables.

The management API is available at host `127.0.0.1:8081` in Docker Compose (the container binds `0.0.0.0:8081`, while the host port remains localhost-only). Set `BEARUST_SETUP_TOKEN` before startup, or read the generated one-time token from `./data/setup-token` and expose the management UI only through an HTTPS reverse proxy. Keep `./data` private because it contains the SQLite database and certificate material.

Run `cargo test --locked`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings`. See [DEVELOPMENT.md](DEVELOPMENT.md), [DEPLOY.md](DEPLOY.md), and the [roadmap](docs/PRD.md). Licensed under MIT OR Apache-2.0.

Certificate automation is documented in [docs/acme.md](docs/acme.md). Start with Let's Encrypt staging, verify the challenge and reload path, then switch to production.

## Management users and RBAC

The control plane listens on `http://127.0.0.1:8081` in the development compose setup. On a fresh data directory, `GET /api/setup/status` reports that initialization is required. Create the first administrator exactly once with the one-time setup token:

```sh
curl -c cookies.txt -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"correct horse battery","setup_token":"<setup-token>"}' \
  http://127.0.0.1:8081/api/setup/initialize
```

Initialization is rejected after the first user exists. The account created by setup is an enabled `admin`; subsequent accounts must be created by an administrator through the authenticated API or the Users section in the dashboard. Passwords and session material are never included in user responses.

### User API

Send the session cookie returned by login (`curl -b cookies.txt ...`) to these administrator-only endpoints:

| Method and path | Purpose | Success response |
| --- | --- | --- |
| `GET /api/users` | List users | JSON array of `{id,email,role,created_at,disabled}` |
| `POST /api/users` | Create a user | `201` and the created user summary |
| `PATCH /api/users/{id}` | Change `role` and/or `disabled` | `200` and the updated user summary |
| `DELETE /api/users/{id}` | Delete a user | `204 No Content` |

Example user creation:

```sh
curl -b cookies.txt -H 'Content-Type: application/json' \
  -d '{"email":"operator@example.com","password":"operator password 123","role":"operator"}' \
  http://127.0.0.1:8081/api/users
```

Only `admin`, `operator`, and `viewer` are valid roles. Invalid input returns `400` (`invalid_input`), missing users return `404`, duplicate email returns `409`, and insufficient permission returns `403` (`forbidden`). An administrator cannot disable or delete their own account, and the last enabled administrator cannot be disabled, deleted, or changed to another role. Disabling or deleting an account invalidates its active sessions; a disabled account cannot log in.

The role matrix is:

| Capability | Admin | Operator | Viewer |
| --- | ---: | ---: | ---: |
| Read proxy hosts | Yes | Yes | Yes |
| Create/update/delete proxy hosts | Yes | Yes | No |
| Read certificates | Yes | Yes | Yes |
| Upload, activate, renew, or issue ACME certificates | Yes | Yes | No |
| Manage users and roles | Yes | No | No |

The backend remains authoritative even when the UI hides write controls or the admin-only Users section for non-admin users. Successful and denied user mutations are recorded as redacted audit events. Per-host permissions, custom permissions, and SSO/external identity providers remain future work.

### Audit log API and viewer

Authenticated `admin`, `operator`, and `viewer` sessions can read the audit history through `GET /api/audit-logs`; unauthenticated requests are rejected. The dashboard exposes the same read-only view for every role. Results are newest first (`created_at DESC, id DESC`) and are returned as `{items, page, page_size, total}`.

The endpoint accepts these optional query parameters:

- `event` — exact event name.
- `actor_id` — numeric user ID (including actors whose account was later deleted).
- `from` and `to` — RFC3339 timestamp bounds, inclusive.
- `q` — text search across the event name and details.
- `page` — 1-based page number (default `1`).
- `page_size` — rows per page (default `25`, limited to `1`–`100`).

Each row contains only `id`, `actor`, `event`, redacted `details`, and `created_at`. Actor labels are the current user email, `system` for system-generated events, or `deleted-user` when the original account no longer exists. Passwords, session/token hashes, setup tokens, private keys, provider credentials, request bodies, and raw SQL/database errors are sanitized at the read boundary and never serialized, rendered, or otherwise exposed. Audit history is strictly read-only: there are no delete, mutation, or export endpoints.
