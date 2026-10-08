# Bearust operator manual

Detailed operator reference for Bearust: accounts and RBAC, audit logs, realtime events, analytics, WAF and rate limiting, WASM plugins, HTTP/3, and multi-node clustering. For installation and first run, start with the [README](../README.md); for deployment hardening see [DEPLOY.md](../DEPLOY.md).

## Contents

- [Control-plane accounts and RBAC](#control-plane-accounts-and-rbac)
- [Audit log API and viewer](#audit-log-api-and-viewer)
- [Realtime updates](#realtime-updates)
- [Analytics dashboard](#analytics-dashboard)
- [Self-learning](#self-learning-phase-9)
- [WAF and rate limiting](#waf-and-rate-limiting)
- [WASM plugin runtime](#wasm-plugin-runtime)
- [Plugin manifest signing and trust-on-first-use](#plugin-manifest-signing-and-trust-on-first-use)
- [Community plugin registry](#community-plugin-registry)
- [HTTP/3 listener](#http3-listener)
- [Multi-node cluster and HA operations](#multi-node-cluster-and-ha-operations)

## Control-plane accounts and RBAC

The control plane and bundled management UI listen on `http://127.0.0.1:8081` by
default (loopback-only in both Compose files). On a fresh data directory,
`GET /api/setup/status` reports that initialization is required. Create the
first administrator exactly once with the one-time setup token:

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

The backend remains authoritative even when the UI hides write controls or the admin-only Users section for non-admin users. Successful and denied user mutations are recorded as redacted audit events. Per-host proxy-host scopes and custom roles are supported; custom permission vocabularies and SSO/external identity providers remain future work.

## Audit log API and viewer

Authenticated `admin`, `operator`, and `viewer` sessions can read the audit history through `GET /api/audit-logs`; unauthenticated requests are rejected. The dashboard exposes the same read-only view for every role. Results are newest first (`created_at DESC, id DESC`) and are returned as `{items, page, page_size, total}`.

The endpoint accepts these optional query parameters:

- `event` — exact event name.
- `actor_id` — numeric user ID (including actors whose account was later deleted).
- `from` and `to` — RFC3339 timestamp bounds, inclusive.
- `q` — text search across the actor label, event name, and details.
- `page` — 1-based page number (default `1`).
- `page_size` — rows per page (default `25`, limited to `1`–`100`).

Each row contains only `id`, `actor`, `event`, redacted `details`, and `created_at`. Actor labels are the current user email, `system` for system-generated events, or `deleted-user` when the original account no longer exists. Passwords, session/token hashes, setup tokens, private keys, provider credentials, request bodies, and raw SQL/database errors are sanitized at the read boundary and never serialized, rendered, or otherwise exposed. Audit history is strictly read-only: there are no delete, mutation, or export endpoints.

## Realtime updates

The dashboard subscribes to `GET /api/events` using an authenticated session cookie. The endpoint uses Server-Sent Events (SSE) to deliver safe invalidation notifications for proxy hosts, certificates, users, roles, sessions, and audit activity; the dashboard reloads the corresponding proxy-host, certificate, user, role, and audit data, while session events are notified through the stream for future session-view consumers. Payloads never contain credentials, tokens, hashes, private keys, or request bodies. Delivery to each process is bounded and process-local, while committed cluster events fan out across configured nodes and trigger bounded local catch-up. Clients automatically reconnect after transient disconnects and receive a heartbeat roughly every 15 seconds; replay of every event missed while disconnected remains intentionally deferred.

## Analytics dashboard

`GET /api/analytics/timeseries` accepts `interval=minute|hour|day` (default
`minute`). Buckets align to UTC boundaries and remain separated by proxy host.
The `from`/`to` filters select source minute buckets before aggregation; `limit`
selects the newest output buckets after aggregation. Counters and latency
histograms are summed, then percentiles are recalculated from the combined
histogram. The dashboard exposes an interval selector and UTC date labels.
This is a query-time rollup of retained minute history, not additional long-term
storage or cross-node aggregation; retention remains unchanged.

The authenticated dashboard includes a read-only Analytics panel for proxy
traffic and security aggregates. `admin`, `operator`, and `viewer` sessions
may query `GET /api/analytics/summary` and
`GET /api/analytics/timeseries`; unauthenticated requests are rejected and
malformed or oversized filters return `400`. The panel provides proxy-host and
time-range filters, request/status cards, p50/p95/p99 latency and error-rate
views, security-event panels, loading/error/empty states, and refreshes after
the redacted `analytics.changed` SSE invalidation event.

Analytics uses a bounded in-memory ring for live collection and persists
one-minute aggregate buckets in the control-plane database. It restores the
configured window after restart, retains one-minute buckets for 1 hour to 7
days (up to 10,080 buckets per host), returns at most 100 hosts and 10,080
timeseries buckets, and records bounded histograms rather than raw samples.
Events contain aggregate status, latency, WAF, bot, and rate-limit counters
only: raw IP addresses, complete URLs, headers, bodies, credentials, tokens,
and secrets are never stored or returned. Collection is fail-open and cannot
reject proxy traffic.

Prometheus is disabled by default. To enable it, add a `[prometheus]` table to
the TOML configuration. The default safe bind is `127.0.0.1:9090`, with
`internal_only = true` and `require_auth = true`; internal-only mode must bind
loopback, while any external bind must retain authentication. `/metrics`
exposes stable bounded labels (`proxy_host_id` and status class) and is capped
at 256 KiB by default. Do not expose it publicly without an authenticated
network boundary.

Durable minute-level history, administrator-configurable retention, and
cross-node policy/invalidation synchronization are implemented. Long-term
hourly/day rollups, Redis or cross-node metric aggregation, per-route
dimensions, and alerting remain deferred to later phases. Phase 9 now adds the
bounded self-learning layer: per-host traffic baselines, deterministic anomaly
detection, and opt-in adaptive tuning. These controls are monitor-only by
default, preserve bounded storage and sensitive-data redaction, and expose
authenticated baseline, anomaly, recommendation, and policy APIs plus redacted
realtime invalidation events.

## Self-learning (Phase 9)

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

## WAF and rate limiting

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

## WASM plugin runtime

Phase 13A provides a local, health-check-only WASM runtime foundation. Plugins
are not loaded unless `[plugins].enabled = true`; the default directory is
`./plugins`. With plugins disabled, a missing directory, an invalid manifest, or
a failed invocation, Bearust starts normally and proxy traffic is unaffected.

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
its module. See [`PLUGIN_AUTHORING.md`](PLUGIN_AUTHORING.md) for a
full guide to writing a plugin in Rust, covering every hook capability with
worked examples.

```text
plugins/
└── health-ok/
    ├── plugin.toml
    └── health_ok.wasm
```

The versioned manifest requires `id` (lowercase letters, digits, and hyphens),
`display_name`, `abi_version = 1`, and a module filename. Accepted
capabilities are `health_check`, `notify.waf_block`, `waf.detect`,
`transform.request`, `transform.response`, and `balance.select` (each hook is
documented with worked examples in `PLUGIN_AUTHORING.md`); `[limits]` may set
`memory_pages`, `fuel`, `invocation_timeout_ms`, and `max_output_bytes` within
the configured maxima. Every module exports `bearust_abi_version() -> i32`
plus its capability entry point(s). No WASI imports or host functions are
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
traffic hooks were delivered in Phase 13B–13G; manifest signing,
trust-on-first-use pinning, and registry distribution were added in
Phase 14 (see below).

## Plugin manifest signing and trust-on-first-use

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
account running Bearust.

## Community plugin registry

`bearust plugin search <query>` and `bearust plugin install <id>` fetch a
static, HTTPS-hosted JSON index of published plugins and let an operator
install one without manually downloading and extracting an archive. The
default index URL points at Bearust's own community index; override it
with `--registry-url <url>` or the `BEARUST_PLUGIN_REGISTRY_URL`
environment variable to use a private or self-hosted index instead —
there is no requirement to use the default.

```console
$ bearust plugin search waf
waf-guard  v1.0.0  Blocks common admin-path scanning patterns.

$ bearust plugin install waf-guard --out ./plugins
waf-guard  v1.0.0
capabilities: waf.detect
signer: MCowBQYDK2VwAyEA...
Install this plugin? [y/N]: y
installed waf-guard to ./plugins/waf-guard -- run `POST /api/plugins/reload` to load it
```

`install` downloads the plugin's archive, verifies its SHA-256 checksum
against the index entry, extracts it (rejecting any path-traversal
attempt or unexpected file in the archive), and — if the index declares a
`signer_public_key` for that entry — cross-checks it against the
signature actually embedded in the archive before writing anything to
disk. Pass `--yes` to skip the confirmation prompt (for scripted use) and
`--force` to overwrite an already-installed plugin directory with the
same ID.

The index is a catalog and a transport-integrity check, not a new source
of trust: `install` never pins a key or loads a module. Trust is decided
exactly the way it already is for a manually-placed plugin — the first
time Bearust reloads plugins from disk, the installed plugin's signature
(if any) goes through the same trust-on-first-use pinning described
above. There is no `bearust plugin publish` command; contributing an
entry to the community index is a pull request to that index's own
repository, reviewed by its maintainers.

## HTTP/3 listener

Bearust can optionally accept client-facing HTTP/3 (QUIC) connections
alongside the existing Pingora-based HTTP/1.1/HTTP/2 listener. It is
off by default and requires TLS to already be configured:

```toml
[server.tls]
cert_path = "/etc/bearust/cert.pem"
key_path = "/etc/bearust/key.pem"

[server.http3]
enabled = true
bind = "0.0.0.0:443"   # UDP port; default is 127.0.0.1:8443
```

Config validation rejects `server.http3.enabled = true` without
`server.tls` configured — HTTP/3 always runs over QUIC's built-in TLS,
so there is no way to serve it in plaintext. The H3 listener reuses the
same certificate/key PEM files as the TCP/TLS listener, and (independent
of that listener) evaluates every request against the same WAF rule
engine and proxy host routing/load-balancing that the HTTP/1.1/HTTP/2
path uses, producing byte-identical WAF block responses when a request
is blocked.

When `server.http3.enabled` is `true`, the existing HTTP/1.1/HTTP/2
listener advertises the H3 endpoint on every response via an `Alt-Svc:
h3=":<port>"; ma=86400` header (`<port>` is `server.http3.bind`'s UDP
port), so compliant clients can discover and upgrade to H3 for
subsequent requests. The header is omitted entirely when HTTP/3 is
disabled.

H3 requests are recorded into the same analytics collector the
HTTP/1.1/HTTP/2 path feeds (status code, latency, proxy host, and WAF
block counts), so they appear in the existing analytics dashboard and
`GET /api/analytics` surfaces alongside HTTP/1.1/HTTP/2 traffic.

The same rate limiter and live policy the HTTP/1.1/HTTP/2 path uses
also applies to H3 requests: once a request's route resolves, its
client IP (respecting `server.trusted_proxy_cidrs`) and the route's
policy are evaluated, and an over-limit request in `block` mode gets a
byte-identical `429 Rate limit exceeded` response (with `Retry-After`
and `Cache-Control: no-store`) without ever reaching the backend;
`monitor` mode records the event but never blocks.

The same bot-protection evaluator and challenge/clearance flow the
HTTP/1.1/HTTP/2 path uses also applies to H3 requests, evaluated after
the WAF (which still wins if it blocks) and before routing: a detected
request in `block` mode gets a byte-identical `403 Request blocked`
response without ever reaching the backend, and in `challenge` mode
gets the same `403` JSON challenge body (`challenge_url`,
`fingerprint_prefix`) as the existing listener; a request presenting a
valid clearance cookie for its fingerprint passes straight through.

All five of the plugin system's hooks now run on the H3 path:
`waf.detect` (can escalate — never downgrade — the WAF's decision),
`notify.waf_block` (fires on every H3 WAF block, same as the existing
listener), `transform.request` (can rewrite outbound request headers;
`Host`/`X-Forwarded-For`/`X-Request-Id` are still reasserted
unconditionally afterward, so a transform plugin can never drop or
spoof them), `balance.select` (can pick which backend serves the
request, validated against the pool's healthy candidates, falling
back to the normal selection algorithm on any failure), and
`transform.response` (an eligible response is fully buffered — up to
the same 1 MiB cap the existing listener uses — before anything is
sent to the client; an oversized body fails open and streams
unmodified rather than being truncated or dropped).

This gives the H3 listener full WAF/analytics/rate-limiting/bot-
protection/plugin-hook parity with the existing HTTP/1.1/HTTP/2
listener. Forwarded requests to upstream backends still always use
HTTP/1.1 or HTTP/2 — only the client-facing edge speaks H3. Upstream
HTTP/3 was investigated and deliberately not implemented: `reqwest`'s
`http3` feature is unstable (excluded from semver guarantees) and
essentially no real backend origin servers speak HTTP/3 in the first
place, so the risk isn't worth the near-zero real-world value; see
`docs/PRD.md`'s Phase 15 status for the full rationale.

## Multi-node cluster and HA operations

Bearust includes an explicit node identity and cluster peer foundation for multi-node deployments. Setting `CLUSTER_PEERS` (or configuring `[cluster]` in TOML) together with a shared `CLUSTER_AUTH_TOKEN` (at least 32 bytes) enables authenticated, out-of-band peer connectivity checks without affecting proxy request handling or single-node operations.

- `NODE_ID`: Unique node identifier (defaults to `node1`).
- `CLUSTER_PEERS`: Comma-separated `node_id=host:port` peer list (defaults to empty, preserving single-node behavior).
- `GET /api/cluster/status`: Authenticated control-plane status endpoint returning local node identity, redacted peer connectivity health snapshots, and additive Raft leader/quorum readiness fields.

Phase 10B adds durable Raft-backed configuration replication. Phase 10C adds
leader-aware write forwarding, committed cross-node invalidations, bounded
failover/quorum coverage, and the host-level keepalived/VIP procedure. Bearust
never changes host interfaces or runs keepalived inside a container; follow
[the keepalived operations guide](keepalived.md) for the readiness check,
fencing procedure, and three-node VRRP example.

