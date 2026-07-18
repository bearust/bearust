# Deployment and operations

The production image runs as UID/GID 10001, drops all capabilities, enables `no-new-privileges`, and uses a read-only root filesystem. Only the TOML config is mounted read-only; `/tmp` and `/run/bearust` are tmpfs. `${BEARUST_PORT:-8080}` maps to proxy port 8080.

The command is `bearust serve --config /etc/bearust/bearust.toml --json-logs`. The PID file defaults to `./bearust.pid` relative to `/run/bearust`; send `SIGHUP` (`docker compose kill -s HUP bearust`) after atomically replacing the mounted config. Shutdown is graceful: listeners stop accepting new work and in-flight requests drain.

JSON logs include event, level, timestamp, request identifiers, route/upstream context, and error category. Unhealthy TCP/HTTP backends are removed from selection; no healthy backend returns `503`, while a route/host miss returns `404`. For `404`, verify `Host`, path prefix, and pool. For `503`, inspect health addresses/paths and reachability from the container. Roll back by restoring the prior image tag and config, then restart or issue `SIGHUP`.
