# BeaRust

![BeaRust](docs/logo.png)

BeaRust is a configuration-driven reverse proxy and load balancer. It supports HTTP/1.1, host/path routing, round-robin and least-connections balancing, TCP/HTTP backend health checks, WebSocket passthrough, JSON logs, graceful shutdown, atomic `SIGHUP` reloads, native TLS, custom certificates, and authenticated ACME certificate automation (HTTP-01 and Cloudflare DNS-01).

## Five-minute start

```sh
cp .env.example .env
docker compose up -d --build
curl -H 'Host: api.example.com' http://127.0.0.1:8080/v1/health
```

Edit `config/bearust.example.toml` (or set `BEARUST_CONFIG`) for backends. Mount persistent `./data` and a read-only `./tls` directory (override with `BEARUST_DATA`/`BEARUST_TLS`). Reload with `docker compose kill -s HUP bearust` or `bearust reload --pid-file ./bearust.pid`. Configuration is TOML with `[server]`, `[health]`, `[[upstream_pools]]`, and `[[routes]]` tables.

The management API is available at host `127.0.0.1:8081` in Docker Compose (the container binds `0.0.0.0:8081`, while the host port remains localhost-only). Set `BEARUST_SETUP_TOKEN` before startup, or read the generated one-time token from `./data/setup-token` and expose the management UI only through an HTTPS reverse proxy. Keep `./data` private because it contains the SQLite database and certificate material.

Run `cargo test --locked`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings`. See [DEVELOPMENT.md](DEVELOPMENT.md), [DEPLOY.md](DEPLOY.md), and the [roadmap](docs/PRD.md). Licensed under MIT OR Apache-2.0.

Certificate automation is documented in [docs/acme.md](docs/acme.md). Start with Let's Encrypt staging, verify the challenge and reload path, then switch to production.
