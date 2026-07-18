# Deployment and operations

The production image runs as UID/GID 10001, drops all capabilities, enables `no-new-privileges`, and uses a read-only root filesystem. The TOML config and `/etc/bearust/tls` are mounted read-only; `/data` stores certificate metadata/material and must be writable by UID 10001. `/tmp` and `/run/bearust` are tmpfs. `${BEARUST_PORT:-8080}` maps to proxy port 8080.

For a custom certificate, place the PEM chain and private key below `/etc/bearust/tls` and reference them from `[server.tls]`. Keep private keys mode `0600`; never put key contents or ACME tokens in configuration, logs, or issue reports. The certificate store persists active metadata below `/data` and activates new material atomically, preserving the previous active certificate when validation or issuance fails.

Let's Encrypt HTTP-01 requires public port 80 and every requested hostname resolving to the proxy. DNS-01 is required for wildcard names or deployments without port 80; the Cloudflare API token should be scoped to the target zone with only `Zone:DNS:Edit` and `Zone:Zone:Read`. Renewal runs asynchronously outside request handling once a certificate enters its renewal window, with bounded retries and last-known-good fallback. See [docs/acme.md](docs/acme.md) for the staging-first rollout and recovery procedure.

ACME credentials are accepted only by the authenticated certificate API and are stored in `/data/secrets` with mode `0700` (individual files `0600`). They are never returned by API responses or written to JSON logs. Keep `/data` private and back it up using filesystem permissions that preserve these modes.

The command is `bearust serve --config /etc/bearust/bearust.toml --json-logs`. The PID file defaults to `./bearust.pid` relative to `/run/bearust`; send `SIGHUP` (`docker compose kill -s HUP bearust`) after atomically replacing the mounted config. Shutdown is graceful: listeners stop accepting new work and in-flight requests drain.

JSON logs include event, level, timestamp, request identifiers, route/upstream context, and error category. Unhealthy TCP/HTTP backends are removed from selection; no healthy backend returns `503`, while a route/host miss returns `404`. For `404`, verify `Host`, path prefix, and pool. For `503`, inspect health addresses/paths and reachability from the container. Roll back by restoring the prior image tag and config, then restart or issue `SIGHUP`.
