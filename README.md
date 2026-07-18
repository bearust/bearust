# BeaRust

![BeaRust](docs/logo.png)

BeaRust is a configuration-driven reverse proxy and load balancer. Phase 1 supports HTTP/1.1, host/path routing, round-robin and least-connections balancing, TCP/HTTP backend health checks, WebSocket passthrough, JSON logs, graceful shutdown, and atomic `SIGHUP` reloads. TLS, HTTP/2/3, ACME, and raw TCP proxying are Phase 2 or later.

## Five-minute start

```sh
cp .env.example .env
docker compose up -d --build
curl -H 'Host: api.example.com' http://127.0.0.1:8080/v1/health
```

Edit `config/bearust.example.toml` (or set `BEARUST_CONFIG`) for backends. Reload with `docker compose kill -s HUP bearust` or `bearust reload --pid-file ./bearust.pid`. Configuration is TOML with `[server]`, `[health]`, `[[upstream_pools]]`, and `[[routes]]` tables.

Run `cargo test --locked`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings`. See [DEVELOPMENT.md](DEVELOPMENT.md), [DEPLOY.md](DEPLOY.md), and the [roadmap](docs/PRD.md). Licensed under MIT OR Apache-2.0.
