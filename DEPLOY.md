# Deployment and operations

The production image runs as UID/GID 10001, drops all capabilities, enables
`no-new-privileges`, and uses a read-only root filesystem. The TOML config is
mounted read-only; `/data` and `/etc/bearust/tls` are persistent named Docker
volumes initialized with the correct ownership for UID 10001. `/tmp` and
`/run/bearust` are tmpfs. `${BEARUST_PORT:-8080}` maps to the data-plane proxy
port 8080, while the bundled management UI and control API are exposed
loopback-only at `http://127.0.0.1:${BEARUST_CONTROL_PORT:-8081}`.

The default production deployment is intentionally one command:

```bash
docker compose up -d --build
```

It uses the local image tag `bearust:local`. To build the same image for a
public registry, provide a tag explicitly and push it yourself:

```bash
BEARUST_IMAGE=ghcr.io/your-account/bearust:latest docker compose build
docker push ghcr.io/your-account/bearust:latest
```

For a custom certificate, copy the PEM chain and private key into the
`bearust-tls` volume and reference them from `[server.tls]`. Keep private keys
mode `0600`; never put key contents or ACME tokens in configuration, logs, or
issue reports. The certificate store persists active metadata below `/data`
and activates new material atomically, preserving the previous active
certificate when validation or issuance fails.

Let's Encrypt HTTP-01 requires public port 80 and every requested hostname resolving to the proxy. DNS-01 is required for wildcard names or deployments without port 80; the Cloudflare API token should be scoped to the target zone with only `Zone:DNS:Edit` and `Zone:Zone:Read`. Renewal runs asynchronously outside request handling once a certificate enters its renewal window, with bounded retries and last-known-good fallback. See [docs/acme.md](docs/acme.md) for the staging-first rollout and recovery procedure.

ACME credentials are accepted only by the authenticated certificate API and are stored in `/data/secrets` with mode `0700` (individual files `0600`). They are never returned by API responses or written to JSON logs. Keep `/data` private and back it up using filesystem permissions that preserve these modes.

The command is `bearust serve --config /etc/bearust/bearust.toml --json-logs`. The PID file defaults to `./bearust.pid` relative to `/run/bearust`; send `SIGHUP` (`docker compose kill -s HUP bearust`) after atomically replacing the mounted config. Shutdown is graceful: listeners stop accepting new work and in-flight requests drain.

## Optional AI Advisor

The advisor remains disabled unless both `LLM_API_URL` and `LLM_API_KEY` are
set. Use an OpenAI-compatible `/v1/chat/completions` endpoint; optional bounded
settings include `LLM_MODEL`, `LLM_REQUEST_TIMEOUT_SECONDS`,
`LLM_RESPONSE_LIMIT_BYTES`, `LLM_QUEUE_CAPACITY`, `LLM_WORKER_COUNT`, and
`LLM_CIRCUIT_FAILURE_THRESHOLD`. Empty values use safe defaults. Prompts contain
redacted aggregate snapshots only; raw URLs, headers, bodies, IPs, credentials,
tokens, and provider responses are not retained. Unset both required variables
and restart to disable safely. Self-hosted HTTPS endpoints are supported. Never
commit API keys or include them in support bundles.

## Database profiles

The default `docker compose up -d` keeps the control plane on SQLite at
`/data/bearust.sqlite`, persisted by the `bearust-data` named volume.
PostgreSQL and MySQL are opt-in profiles with health checks and named volumes:

Uncomment and set the matching `DATABASE_URL` and `POSTGRES_*` or `MYSQL_*`
credentials in `.env` (use a long random password in production), then run
exactly one profile:

```sh
docker compose --profile postgres up -d
# or, for MySQL:
docker compose --profile mysql up -d
```

For a non-default env file, use `--env-file`, for example
`docker compose --env-file .env.production --profile postgres up -d`.
Enabling both profiles makes Bearust wait for both health checks while
`DATABASE_URL` selects the backend it uses. Migrations run automatically at startup;
the database volume is retained across restarts and image upgrades. Switching
between SQLite, PostgreSQL, and MySQL is not an in-place operation: perform an
explicit, tested export/import outside this phase and keep the original volume
as a rollback copy. Never paste `DATABASE_URL` values containing passwords into
logs, issue reports, or support bundles; redact credentials before sharing
Compose output or diagnostic archives.

## Optional WASM plugins (Phase 13A)

Production deployments keep plugins disabled unless a reviewed local module is
required. The default is `[plugins].enabled = false` with `directory =
"./plugins"`; when enabled, mount a dedicated read-only plugin directory below
the container and set an explicit absolute path in the TOML configuration:

```toml
[plugins]
enabled = true
directory = "/etc/bearust/plugins"
max_plugins = 64
max_module_bytes = 16777216
max_memory_pages = 256
max_fuel = 10000000
invocation_timeout_ms = 1000
max_output_bytes = 65536
```

The directory layout is one child per plugin (`plugin.toml` and one `.wasm`
module). Manifests use ABI version `1`, allow only `health_check`, and declare
bounded memory pages, fuel, timeout, and output limits. The runtime provides no
WASI, filesystem, network, environment, clock, random, database, or proxy
request access. It canonicalizes module paths beneath the configured root and
rejects traversal and symlink escapes.

After startup, administrators can use the authenticated control-plane API:
`GET /api/plugins` and `POST /api/plugins/reload` for status/reload,
`POST /api/plugins/{id}/enable` or `/disable`, `DELETE /api/plugins/{id}`, and
`POST /api/plugins/{id}/health-check`. `plugins.read` permits listing and health
checks; `plugins.manage` permits lifecycle changes. The API exposes only
bounded metadata (including SHA-256 digest and safe error code), never paths,
manifest text, module bytes, runtime errors, request data, or secrets.

Invalid configuration, compilation errors, traps, timeouts, fuel exhaustion,
and memory limits disable/isolate the affected plugin. The proxy remains
available and startup continues. Deploy only reviewed local modules; there is
still no remote download or registry.

### Plugin manifest signing and trust-on-first-use (Phase 14)

Set `plugins.require_signature = true` to require every plugin directory to
carry a valid `plugin.sig` (rejecting anything unsigned); leave it `false`
(the default) to allow unsigned modules alongside signed ones:

```toml
[plugins]
enabled = true
directory = "/etc/bearust/plugins"
require_signature = true
max_plugins = 64
max_module_bytes = 16777216
max_memory_pages = 256
max_fuel = 10000000
invocation_timeout_ms = 1000
max_output_bytes = 65536
```

Sign a reviewed plugin before shipping it to the plugin directory:

```console
$ bearust plugin keygen --out ./keys        # writes ./keys/signing.key (0600), prints the public key
$ bearust plugin sign ./plugins/health-ok --key ./keys/signing.key
```

`plugin sign` writes `plugin.sig` alongside `plugin.toml` and the `.wasm`
module. Keep `signing.key` off the deployed host entirely — sign in CI or on
a workstation and ship only `plugin.toml`, the module, and `plugin.sig`.

The first time BeaRust loads a signed plugin ID, it pins that plugin's
public key into `<directory>/trusted-keys.json`. Every subsequent load must
match the pinned key; a mismatch fails closed with `key_mismatch` in the
plugin's `last_error_code` and in `plugin_startup_failed`/reload audit logs.
Because the trust store is written at runtime, **the plugin directory cannot
be fully read-only** if signing is in use — mount it read-write and owned
only by the account running BeaRust, or pre-seed `trusted-keys.json`
read-only with the expected pins and mount only that file read-only if you
want to lock pinning down entirely.

If you rotate a plugin's signing key on purpose, the next reload after the
rotation logs `key_mismatch` — this is expected, not a compromise signal by
itself. Recover by removing (or updating) that plugin's entry in
`trusted-keys.json` on the host, then reload; the next load re-pins whatever
key is now present. There is no API for this — it is a deliberate manual
step so a rotation always leaves an operator-visible trace.

Threat-model note: `trusted-keys.json` lives next to the plugin bundles it
protects, so signing plus pinning defends against a tampered *distribution
channel* (a corrupted artifact, a compromised mirror) — it does not defend
against an attacker who already has write access to the plugins directory,
since they could edit the pin file too. Directory ownership/permissions are
still the primary control.

JSON logs include event, level, timestamp, request identifiers, route/upstream context, and error category. Unhealthy TCP/HTTP backends are removed from selection; no healthy backend returns `503`, while a route/host miss returns `404`. For `404`, verify `Host`, path prefix, and pool. For `503`, inspect health addresses/paths and reachability from the container. Roll back by restoring the prior image tag and config, then restart or issue `SIGHUP`.
