# BeaRust

![BeaRust](docs/logo.png)

[![CI](https://github.com/rizalord/bearust/actions/workflows/ci.yml/badge.svg)](https://github.com/rizalord/bearust/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.97.1-orange.svg)](rust-toolchain.toml)

BeaRust is an open-source, configuration-driven **reverse proxy and load balancer** with a built-in web dashboard. Point it at your backends with a small TOML file and you get host/path routing, health-checked load balancing, TLS, a WAF, and live analytics — without learning a new DSL.

```text
                    ┌─────────────┐
  clients ──────────▶ │   BeaRust   │ ──▶ backend pool (health-checked)
  :8080 (proxy)     │  ─────────  │     round-robin / least-connections
  :8081 (dashboard) │  WAF · TLS  │
                    └─────────────┘
```

## Features

**Proxy core**

- HTTP/1.1 reverse proxy with host + path-prefix routing
- Round-robin and least-connections balancing with TCP/HTTP backend health checks
- WebSocket passthrough, graceful shutdown, and atomic `SIGHUP` reloads
- Native TLS, custom certificates, and ACME automation (HTTP-01 and Cloudflare DNS-01)
- Optional client-facing HTTP/3 (QUIC) listener with full WAF/analytics/rate-limit parity

**Security**

- Built-in WAF (SQLi, XSS, path traversal, command injection) — monitor-only by default
- Bot protection with signed challenges, adaptive rate limiting, IP security policies
- Authenticated control plane with RBAC (`admin` / `operator` / `viewer`), custom roles, and per-host scopes
- Redacted audit log, JSON logs, and secrets that never leave `/data/secrets`

**Operations**

- Web dashboard: proxy hosts, certificates, WAF, analytics, clustering, users, audit log
- Live analytics with per-host timeseries, optional Prometheus endpoint
- Self-learning layer: traffic baselines, anomaly detection, opt-in adaptive tuning
- Multi-node clustering with Raft config sync, plus a keepalived/VIP runbook
- SQLite by default; PostgreSQL or MySQL via opt-in Compose profiles
- Sandboxed WASM plugins (6 hook capabilities) with manifest signing and a community registry

## Quick start

Prerequisite: Docker. One command starts the proxy and the dashboard:

```sh
docker compose up -d --build
```

| What | Where |
| --- | --- |
| Proxy (your app traffic) | `http://localhost:8080` |
| Dashboard + control API (loopback-only) | `http://127.0.0.1:8081` |

On first startup BeaRust generates a one-time setup token. For a deterministic token, set it before starting:

```sh
echo 'BEARUST_SETUP_TOKEN=replace-with-a-long-random-value' > .env
docker compose up -d --build
```

Open `http://127.0.0.1:8081`, create the first administrator account with the setup token, then add a proxy host pointing at your backend. That is the whole setup — no database to provision (SQLite lives in a Docker volume), and proxy hosts can be managed entirely from the dashboard.

To use a TOML config file instead, edit `config/bearust.example.toml` (or point `BEARUST_CONFIG` at your own file) and reload without downtime:

```sh
bearust validate --config ./config/bearust.example.toml
docker compose kill -s HUP bearust
```

See [DEPLOY.md](DEPLOY.md) for production hardening, external databases, and TLS/ACME rollout.

## How it works

- **Data plane** (`:8080`): Pingora-based proxy. Every request flows through IP policy → bot check → WAF → routing → rate limit → load-balanced backend. Failures fail open where safe (analytics, plugins) and fail closed where it matters (auth, WAF blocks).
- **Control plane** (`:8081`, loopback-only): authenticated REST API + bundled dashboard for hosts, certificates, WAF, users, analytics, and cluster status. Serves realtime updates over SSE.
- **State**: proxy hosts, users, certificates, and analytics buckets live in the control-plane database (SQLite/PostgreSQL/MySQL); TOML remains supported for file-driven deployments.

## Configuration essentials

Minimal TOML — one pool, one route:

```toml
[server]
bind = "0.0.0.0:8080"
control_bind = "127.0.0.1:8081"

[[upstream_pools]]
name = "api"
algorithm = "round_robin"

[[upstream_pools.backends]]
address = "127.0.0.1:9001"
health_check = "http"
health_path = "/health"

[[routes]]
name = "api"
host = "api.example.com"
path_prefix = "/"
upstream_pool = "api"
```

Useful commands:

```sh
bearust validate --config ./bearust.toml   # check a file without binding ports
bearust serve --config ./bearust.toml      # run in the foreground
bearust reload --pid-file ./bearust.pid    # graceful reload of a running server
bearust plugin search waf                  # browse the community plugin index
```

Common environment variables: `BEARUST_CONFIG`, `BEARUST_PORT`, `BEARUST_CONTROL_PORT`, `BEARUST_SETUP_TOKEN`, `DATABASE_URL`, `RUST_LOG`. See [`.env.example`](.env.example) for the full list.

## Dashboard and access control

The dashboard covers proxy hosts, TLS certificates, WAF, bot protection, rate limits, analytics, cluster status, users, roles, and the audit log. The UI is localized in English, Indonesian, and Japanese.

| Capability | Admin | Operator | Viewer |
| --- | :---: | :---: | :---: |
| Read proxy hosts, certificates, analytics | Yes | Yes | Yes |
| Create/update proxy hosts and certificates | Yes | Yes | No |
| Manage users and roles | Yes | No | No |

Custom roles and per-host scopes are supported; every mutation is audit-logged. Full API reference: [docs/manual.md](docs/manual.md).

## Documentation

| Document | Contents |
| --- | --- |
| [docs/manual.md](docs/manual.md) | Operator reference: RBAC API, audit log, realtime, analytics, WAF, plugins, HTTP/3, clustering |
| [DEPLOY.md](DEPLOY.md) | Production deployment, TLS/ACME, database profiles, plugin trust |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Dev workflow, test gates, plugin and analytics development |
| [docs/acme.md](docs/acme.md) | Certificate automation rollout and recovery |
| [docs/PLUGIN_AUTHORING.md](docs/PLUGIN_AUTHORING.md) | Write a WASM plugin in Rust (all 6 hooks) |
| [docs/keepalived.md](docs/keepalived.md) | Multi-node VIP failover runbook |
| [docs/localization.md](docs/localization.md) | Translation contribution workflow |
| [docs/PRD.md](docs/PRD.md) | Product requirements and phase roadmap |
| [PRODUCT.md](PRODUCT.md) / [DESIGN.md](DESIGN.md) | Product overview and architecture notes |

## Development

The one-command dev stack runs the Rust backend with cargo-watch and the API-backed frontend with hot reload:

```sh
docker compose -f docker-compose.dev.yml up --build
# dashboard (dev): http://localhost:5183  — setup token: bearust-dev-setup
```

Native development needs Rust 1.97.1 and Node 22. Before opening a PR, run the same gates CI runs:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --locked
npm run validate-locales --prefix frontend
npm test --prefix frontend -- --run
npm run build --prefix frontend
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for workflow and conventions.

## Roadmap

BeaRust is built in phases tracked in [docs/PRD.md](docs/PRD.md): core proxy, TLS/ACME, dashboard, RBAC, external databases, WAF, analytics, self-learning, clustering, localization, AI advisor (optional), WASM plugins, and HTTP/3 are implemented. Deliberately deferred: SSO/federated identity, long-term metric rollups, cross-node analytics aggregation, and full Coraza/OWASP CRS grammar compatibility.

## Contributing

Contributions are welcome — bug reports, translations (`en`/`id`/`ja`), docs, and code. Please read [CONTRIBUTING.md](CONTRIBUTING.md), open an issue first for larger changes, and include tests with behavior changes.

## Security

If you find a vulnerability, please do **not** open a public issue. See [SECURITY.md](SECURITY.md) for how to report it privately.

## License

Licensed under either of [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at your option.
