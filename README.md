# BeaRust

![BeaRust](docs/logo.png)

BeaRust is a configuration-driven reverse proxy and load balancer. It supports HTTP/1.1, host/path routing, round-robin and least-connections balancing, TCP/HTTP backend health checks, WebSocket passthrough, JSON logs, graceful shutdown, atomic `SIGHUP` reloads, native TLS, custom certificates, and authenticated ACME certificate automation (HTTP-01 and Cloudflare DNS-01).

## Five-minute start

```sh
cp .env.example .env
docker compose up -d --build
curl -H 'Host: api.example.com' http://127.0.0.1:8080/v1/health
```

SQLite is the default and is persisted under `./data`. External database
profiles are opt-in; copy `.env.example`, uncomment the matching `DATABASE_URL`
and credential lines, replace the development passwords, and start exactly one
profile:

```sh
docker compose --profile postgres up -d --build
# or
docker compose --profile mysql up -d --build
```

PostgreSQL data is stored in the `postgres-data` named volume and MySQL data in
`mysql-data`. Migrations run automatically on application startup. Changing
database backends requires a deliberate export/import procedure; do not delete
the old volume until the new deployment has been verified. Redact passwords in
`DATABASE_URL`, `.env`, Compose diagnostics, logs, and support bundles.

The application waits for the selected database health check. Enabling both
profiles makes it wait for both services; `DATABASE_URL` still selects the
backend it uses. For a non-default env file, pass it explicitly with
`docker compose --env-file .env.production --profile postgres up -d`.

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

### Phase 4D.2 realtime updates

The dashboard subscribes to `GET /api/events` using an authenticated session cookie. The endpoint uses Server-Sent Events (SSE) to deliver safe invalidation notifications for proxy hosts, certificates, users, roles, sessions, and audit activity; the dashboard reloads the corresponding proxy-host, certificate, user, role, and audit data, while session events are notified through the stream for future session-view consumers. Payloads never contain credentials, tokens, hashes, private keys, or request bodies. Delivery is process-local and bounded, so clients automatically reconnect after transient disconnects and receive a heartbeat roughly every 15 seconds. Cross-node fan-out and replay of events missed while disconnected are intentionally deferred until the multi-node phase.

### Analytics dashboard

The authenticated dashboard includes a read-only Analytics panel for proxy
traffic and security aggregates. `admin`, `operator`, and `viewer` sessions
may query `GET /api/analytics/summary` and
`GET /api/analytics/timeseries`; unauthenticated requests are rejected and
malformed or oversized filters return `400`. The panel provides proxy-host and
time-range filters, request/status cards, p50/p95/p99 latency and error-rate
views, security-event panels, loading/error/empty states, and refreshes after
the redacted `analytics.changed` SSE invalidation event.

Analytics is process-local and resets on restart. It retains one-minute
buckets for 24 hours (up to 1,440 buckets per host), returns at most 100 hosts
and 1,440 timeseries buckets, and records bounded histograms rather than raw
samples. Events contain aggregate status, latency, WAF, bot, and rate-limit
counters only: raw IP addresses, complete URLs, headers, bodies, credentials,
tokens, and secrets are never stored or returned. Collection is fail-open and
cannot reject proxy traffic.

Prometheus is disabled by default. To enable it, add a `[prometheus]` table to
the TOML configuration. The default safe bind is `127.0.0.1:9090`, with
`internal_only = true` and `require_auth = true`; internal-only mode must bind
loopback, while any external bind must retain authentication. `/metrics`
exposes stable bounded labels (`proxy_host_id` and status class) and is capped
at 256 KiB by default. Do not expose it publicly without an authenticated
network boundary.

Durable history, Redis/cross-node aggregation and fan-out, per-route
dimensions, anomaly detection, adaptive tuning, custom retention, and alerting
remain deferred to later phases.
### Basic WAF

Phase 6 adds a bounded in-process WAF for SQL injection, XSS, path traversal,
and command injection. Fresh installations start in `monitor-only` mode; use
the admin dashboard or `/api/waf/*` endpoints to review rules and switch to
`block`. Custom rules support `inherit`, `allow`, `log`, and `block` actions.
Request-body inspection is capped at 8 KiB, and audit records never contain
credentials, tokens, or request bodies.

TOML imports use a versioned schema:

```toml
version = 1
mode = "monitor-only"

[[rules]]
name = "block suspicious query"
category = "custom"
severity = "medium"
action = "block"
field = "query"
pattern = "evil"
```

Rate limiting is disabled and monitor-only by default. Administrators may
configure the bounded token bucket in the main TOML file or dashboard:

```toml
[rate_limit]
enabled = false
action = "monitor"
capacity = 100
refill_per_second = 10.0
key_scope = "proxy_host_ip"
```
