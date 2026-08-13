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

Run `cargo test --locked`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings`. Frontend localization contributions must also run `npm run validate-locales --prefix frontend`; the supported UI locale codes are `en` (English), `id` (Indonesian), and `ja` (Japanese). See [DEVELOPMENT.md](DEVELOPMENT.md), [localization contribution guidance](docs/localization.md), [DEPLOY.md](DEPLOY.md), and the [roadmap](docs/PRD.md). Licensed under MIT OR Apache-2.0.

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

### Phase 13A WASM plugins (optional and disabled by default)

Phase 13A provides a local, health-check-only WASM runtime foundation. Plugins
are not loaded unless `[plugins].enabled = true`; the default directory is
`./plugins`. With plugins disabled, a missing directory, an invalid manifest, or
a failed invocation, BeaRust starts normally and proxy traffic is unaffected.

Configuration limits are bounded by the server and can be lowered per
deployment:

```toml
[plugins]
enabled = false
directory = "./plugins"
max_plugins = 64
max_module_bytes = 16777216       # 16 MiB
max_memory_pages = 256            # 64 KiB per page
max_fuel = 10000000
invocation_timeout_ms = 1000
max_output_bytes = 65536
```

Each immediate child directory is one plugin and contains only a manifest and
its module. See [`docs/PLUGIN_AUTHORING.md`](docs/PLUGIN_AUTHORING.md) for a
full guide to writing a plugin in Rust, covering every hook capability with
worked examples.

```text
plugins/
└── health-ok/
    ├── plugin.toml
    └── health_ok.wasm
```

The versioned manifest requires `id` (lowercase letters, digits, and hyphens),
`display_name`, `abi_version = 1`, and a module filename. The only accepted
capability is `health_check`; `[limits]` may set `memory_pages`, `fuel`,
`invocation_timeout_ms`, and `max_output_bytes` within the configured maxima.
The module exports `bearust_abi_version() -> i32` and may export
`bearust_health_check() -> i32`. No WASI imports or host functions are
available.

Administrators use the authenticated control-plane API (permissions are
`plugins.read` and `plugins.manage`):

| Method and path | Permission | Purpose |
| --- | --- | --- |
| `GET /api/plugins` | `plugins.read` | List bounded, redacted status |
| `POST /api/plugins/reload` | `plugins.manage` | Atomically reload local plugins |
| `POST /api/plugins/{id}/enable` | `plugins.manage` | Enable a loaded plugin |
| `POST /api/plugins/{id}/disable` | `plugins.manage` | Disable invocation |
| `DELETE /api/plugins/{id}` | `plugins.manage` | Unload a plugin |
| `POST /api/plugins/{id}/health-check` | `plugins.read` | Run the bounded health ABI |

For example, `curl -b cookies.txt -X POST
http://127.0.0.1:8081/api/plugins/reload` returns `{ "loaded": 1, "failed": 0 }`.
Status responses contain only the plugin ID/display name, ABI, SHA-256 digest,
enabled/loaded flags, and a safe error code. Invalid manifests, ABI mismatches,
compilation failures, disabled plugins, timeouts, fuel exhaustion, memory
limits, traps, and missing IDs map to stable codes such as
`invalid_manifest`, `abi_mismatch`, `compile_failed`, `disabled`, `timeout`,
`fuel_exhausted`, `memory_limit`, `trap`, `not_found`, and `io_error`.
Unauthorized callers receive the standard `401`/`403` envelope.

Security boundary: paths are canonicalized beneath the configured plugin
directory; traversal, absolute paths, symlink escapes, unknown capabilities,
WASI imports, and unbounded limits are rejected. Audit/realtime/metrics output
is redacted and never contains module bytes, manifest contents, filesystem
paths, runtime backtraces, request data, or secrets. The public SDK and
traffic hooks were delivered in Phase 13B–13G; manifest signing and
trust-on-first-use pinning were added in Phase 14 (below). Registry
distribution remains future work.

### Phase 14 plugin manifest signing and trust-on-first-use

Plugin signing is optional and off by default. Set `plugins.require_signature
= true` to reject any plugin directory that lacks a valid `plugin.sig`; left
`false` (the default), unsigned plugins still load but signed ones are still
verified and pinned:

```toml
[plugins]
enabled = true
directory = "./plugins"
require_signature = false
max_plugins = 64
max_module_bytes = 16777216       # 16 MiB
max_memory_pages = 256            # 64 KiB per page
max_fuel = 10000000
invocation_timeout_ms = 1000
max_output_bytes = 65536
```

A signed plugin directory adds one file next to `plugin.toml` and the
module:

```text
plugins/
└── health-ok/
    ├── plugin.toml
    ├── health_ok.wasm
    └── plugin.sig
```

Generate a signing keypair and sign a plugin directory with the `bearust`
CLI:

```console
$ bearust plugin keygen --out ./keys
<base64 public key printed to stdout>
$ bearust plugin sign ./plugins/health-ok --key ./keys/signing.key
wrote ./plugins/health-ok/plugin.sig
```

`plugin keygen` writes `signing.key` with mode `0600` on Unix and refuses to
overwrite an existing key at that path (on any platform) — remove the old
key first if you intend to replace it. `plugin sign` reads the manifest and
module, computes an Ed25519 signature over both, and writes `plugin.sig`.

On load, a signature is checked cryptographically and then checked against
`<plugins-directory>/trusted-keys.json`, a trust-on-first-use pin store: the
first key seen for a given plugin ID is pinned automatically, and every
later load must match that pinned key or the plugin fails closed with
`key_mismatch`. If you legitimately rotate a plugin's signing key, remove
(or edit) that plugin's entry in `trusted-keys.json` and reload — the next
load re-pins whatever key is present. There is no API to rotate a pin
remotely; it is a deliberate, manual operator action.

Threat-model boundary: `trusted-keys.json` lives inside the same directory
as the plugin bundles it protects, so this mechanism protects against a
tampered *distribution channel* (a corrupted download, a compromised
mirror) — it does **not** protect against an attacker who already has write
access to the plugins directory, since they could edit or delete the pin
file too. Ensure the plugins directory is owned and writable only by the
account running BeaRust.

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

### Multi-Node Cluster and HA operations (Phases 10A–10C)

BeaRust includes an explicit node identity and cluster peer foundation for multi-node deployments. Setting `CLUSTER_PEERS` (or configuring `[cluster]` in TOML) together with a shared `CLUSTER_AUTH_TOKEN` (at least 32 bytes) enables authenticated, out-of-band peer connectivity checks without affecting proxy request handling or single-node operations.

- `NODE_ID`: Unique node identifier (defaults to `node1`).
- `CLUSTER_PEERS`: Comma-separated `node_id=host:port` peer list (defaults to empty, preserving single-node behavior).
- `GET /api/cluster/status`: Authenticated control-plane status endpoint returning local node identity, redacted peer connectivity health snapshots, and additive Raft leader/quorum readiness fields.

Phase 10B adds durable Raft-backed configuration replication. Phase 10C adds
leader-aware write forwarding, committed cross-node invalidations, bounded
failover/quorum coverage, and the host-level keepalived/VIP procedure. BeaRust
never changes host interfaces or runs keepalived inside a container; follow
[the keepalived operations guide](docs/keepalived.md) for the readiness check,
fencing procedure, and three-node VRRP example.

Phase 11 localization is complete across its three increments: 11A adds the
English-default i18n foundation and locale selector; 11B supplies complete
Indonesian and Japanese catalogs; and 11C persists validated account
preferences, applies locale-aware dashboard formatting, and documents the
translation contribution workflow. Phase 12 (AI Advisor) is the next planned
product phase.

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

Analytics history remains process-local and resets on restart. Durable history,
Redis/cross-node aggregation and fan-out, per-route dimensions, custom
retention, and alerting remain deferred to later phases. Phase 9 now adds the
bounded self-learning layer: per-host traffic baselines, deterministic anomaly
detection, and opt-in adaptive tuning. These controls are monitor-only by
default, preserve bounded storage and sensitive-data redaction, and expose
authenticated baseline, anomaly, recommendation, and policy APIs plus redacted
realtime invalidation events.

### Self-learning (Phase 9)

Phase 9 is complete across three increments:

- **9A — Traffic baseline:** bounded per-host rolling metrics with warming-up
  handling and `GET /api/analytics/baseline`.
- **9B — Anomaly detection:** deterministic rate, error, latency, and security
  deviation detection with severity, deduplication, acknowledgement, and
  `GET /api/analytics/anomalies`.
- **9C — Adaptive tuning:** opt-in per-host recommendations and guarded runtime
  tuning. The default mode is `monitor`; automatic enforcement requires an
  explicit host policy, confidence threshold, and a non-emergency-disabled
  control-plane state.

Cross-node self-learning aggregation and event replay remain deferred to
Phase 10 and later.
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
