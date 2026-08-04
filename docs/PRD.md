# Product Requirements Document (PRD)
# BeaRust — Open Source Reverse Proxy, Load Balancer & WAF

| | |
|---|---|
| **Document version** | 1.1 |
| **Date** | July 16, 2026 |
| **Status** | Draft |
| **Implementation language** | Rust |
| **License (proposed)** | Open source (MIT/Apache-2.0 dual license, common in the Rust ecosystem) |

---

## 1. Executive Summary

BeaRust is an open source project that combines a **reverse proxy, load balancer, and Web Application Firewall (WAF)** into a single platform, built with Rust for performance and memory safety. The product draws technology concepts from Nginx Plus, F5, and SafeLine WAF on the proxy/security side, and from Nginx Proxy Manager on the ease-of-use side (GUI-first, single-command Docker installation).

Key differentiators of BeaRust:
- **All-in-one**: proxy + LB + WAF + management GUI + RBAC in a single product, instead of stitching together several separate tools.
- **Easy to install**: single Docker Compose command, default SQLite with no external database setup required.
- **Extensible**: WASM-sandboxed plugin system, letting the community build extensions without compromising the security of the core process.
- **AI-assisted (optional)**: built-in statistical self-learning (always on) + LLM-based AI advisor (optional, only active when configured).
- **HA-ready**: multi-node support with Raft-based config sync, plus virtual IP failover via `keepalived`.
- **Multi-language interface**: default English, with localization support for additional languages over time.

---

## 2. Background & Problem Statement

Today, getting a full combination of reverse proxy + load balancer + WAF + management GUI typically requires:
- Stitching together several different tools (Nginx/HAProxy + ModSecurity + a separate Nginx Proxy Manager instance), each with its own learning curve and configuration format.
- Paying for expensive enterprise licenses such as F5 or Nginx Plus, which is unrealistic for individuals, startups, or institutions with limited budgets (e.g. educational institutions).
- Open source WAF options like ModSecurity + OWASP CRS are known for high false-positive rates because they are purely regex-based; alternatives like SafeLine are strong but lock some advanced features (multi-node clustering, advanced dynamic protection) behind a paid Pro edition.

BeaRust targets this gap: **a truly complete (not artificially limited) open source WAF + proxy + LB, easy to install, and extensible by the community through plugins.**

---

## 3. Product Goals

1. Provide a production-ready reverse proxy + load balancer + WAF that is performant (native Rust) and memory-safe.
2. Provide a management experience (GUI) as easy as Nginx Proxy Manager, but with feature depth comparable to enterprise solutions.
3. Keep installation simple (single Docker command) despite the complexity behind it.
4. Build an open plugin ecosystem so the community can extend functionality without forking/modifying the core source code.
5. Offer optional AI-based intelligence that is genuinely opt-in and never compromises the reliability of the core product when disabled.

### Non-goals for v1
- Becoming a global CDN / edge network (BeaRust is a near-origin WAF+proxy, not a CDN replacement).
- Supporting non-HTTP protocols beyond WebSocket passthrough (i.e. not a generic TCP database proxy) in the initial release.
- 100% configuration syntax compatibility with existing Nginx/HAProxy setups (BeaRust has its own configuration format/GUI).

---

## 4. Target Users

| Persona | Primary needs |
|---|---|
| **Self-hosted enthusiast / homelab** | Easy installation, intuitive GUI, free, clear documentation |
| **Startup / small-medium business** | An affordable alternative to F5/Nginx Plus, WAF reliable enough without a dedicated security team |
| **Institutions (education, government)** | Full control over data (self-hosted), needs WAF protection against common attacks (SEO poisoning, defacement, etc.), RBAC for multiple admins |
| **Developer / community contributor** | A plugin system with a clear API, SDK documentation, an open contribution process |
| **DevOps / SRE at medium-large scale** | Multi-node HA, observability (Prometheus-compatible), automation via API |

---

## 5. Scope

### 5.1 In-scope (delivered incrementally, see roadmap §12)
- Core reverse proxy (HTTP/1.1, HTTP/2, optional HTTP/3, WebSocket, TLS termination + ACME)
- Load balancer with multiple algorithms + health checks
- WAF (signature-based + semantic detection + bot protection)
- Web management GUI with RBAC
- Database layer (SQLite by default, MySQL/PostgreSQL optional)
- Multi-node clustering (config sync) + VIP/keepalived integration guide
- Real-time analytics dashboard
- Statistical self-learning (traffic baselining, adaptive tuning)
- Optional AI Advisor (external LLM, OpenAI-compatible endpoint)
- WASM-based plugin system
- Localization (i18n) with multi-language UI support
- Installation via Docker/Docker Compose

### 5.2 Out-of-scope (v1)
- Global CDN/edge caching
- Native mobile management app (a responsive web GUI is sufficient)
- Generic non-HTTP protocol support (raw TCP/UDP proxying) — considered for a future release
- A paid/commercial plugin marketplace

---

## 6. Positioning vs Competitors

| Aspect | BeaRust | Nginx Proxy Manager | SafeLine WAF | F5 / Nginx Plus |
|---|---|---|---|---|
| License | Open source, free | Open source, free | Open source (advanced features paid Pro) | Commercial, expensive |
| Built-in WAF | Yes (signature + semantic) | No | Yes (semantic engine) | Yes |
| Advanced load balancer | Yes | Limited | No (WAF-focused) | Yes |
| Free multi-node clustering | Yes | No | Locked behind Pro | Yes |
| Open plugin ecosystem | Yes (WASM) | No | No | Limited |
| AI-assisted insight | Yes (optional) | No | Not publicly known | Partial (enterprise features) |
| Implementation language | Rust | Node.js | Tengine (C++/Lua) + Go | Proprietary |

---

## 7. Functional Requirements

### 7.1 Core Reverse Proxy & Load Balancer
- **FR-1.1**: Support HTTP/1.1 and HTTP/2; HTTP/3 (QUIC) as a stretch goal.
- **FR-1.2**: TLS termination using `rustls`, with automatic certificate provisioning and renewal via ACME (Let's Encrypt).
- **FR-1.3**: Support WebSocket passthrough.
- **FR-1.4**: Load balancing algorithms: round-robin, least-connection, weighted, IP-hash, and adaptive-weight (based on response-time history from the self-learning module).
- **FR-1.5**: Active health checks (periodic probing of upstreams) and passive health checks (detection from real traffic error rates).
- **FR-1.6**: Hot-reload of configuration without downtime or dropped active connections.
- **FR-1.7**: Virtual host routing based on domain/path.

### 7.2 Web Application Firewall (WAF)
- **FR-2.1**: Signature-based detection compatible with Coraza/OWASP CRS-style rule sets (SQLi, XSS, RCE, XXE, SSRF, path traversal, command injection, etc.).
- **FR-2.2**: Semantic detection engine — parsing payloads as structured grammar (SQL grammar, JS AST, shell parser) to reduce false positives, inspired by SafeLine's approach.
- **FR-2.3**: Bot protection: fingerprinting, dynamic CAPTCHA challenges for suspicious traffic.
- **FR-2.4**: Adaptive rate limiting per host/endpoint, anti-HTTP-flood protection.
- **FR-2.5**: IP reputation & GeoIP filtering.
- **FR-2.6**: Virtual patching — admins can add custom rules that take effect immediately without a restart.
- **FR-2.7**: Authentication challenge (optional per-host: visitors must authenticate before accessing).
- **FR-2.8**: False-positive feedback loop connected to the self-learning module (§7.6).

### 7.3 Management GUI & RBAC
- **FR-3.1**: Web GUI for CRUD operations on proxy hosts, upstreams, WAF rules, users, and roles.
- **FR-3.2**: Granular RBAC: roles with defined scope (e.g. full admin, per-host restricted admin, read-only auditor).
- **FR-3.3**: Audit log for every configuration change (who, when, what changed).
- **FR-3.4**: Real-time updates in the GUI (WebSocket/SSE), not polling.
- **FR-3.5**: Multi-user support with local authentication; external auth provider/SSO support as a future target (see §7.9, plugin system).
- **FR-3.6 (Frontend design system)**: The frontend is built with the latest version of **Tailwind CSS**.
  - Primary brand color: `#D99906`.
  - Theming support for three modes: **system** (follows OS preference), **light**, and **dark** — user-selectable and persisted per account.
  - Fully **responsive** layout across desktop, tablet, and mobile viewports; the dashboard and all management pages must remain usable on small screens, not just decorative scaling.
  - Component styling should derive from a small set of design tokens (primary color, semantic colors for success/warning/danger/info) so theme adjustments do not require touching individual components.

### 7.4 Database Layer
- **FR-4.1**: Uses SQLite by default, requiring no additional setup during initial installation.
- **FR-4.2**: Supports MySQL and PostgreSQL as external options via `DATABASE_URL`.
- **FR-4.3**: Database schema is DB-agnostic (not dependent on vendor-specific features).
- **FR-4.4**: Automatic schema migration on version upgrades.

### 7.5 Multi-Node & High Availability
- **FR-5.1**: Config sync across nodes using Raft consensus (`openraft`), with one leader node as the source of truth.
- **FR-5.2**: The GUI displays cluster status (leader, followers, sync state).
- **FR-5.3**: Virtual IP failover support via integration with `keepalived` (run at the host level, outside the container) — fully documented rather than natively reimplemented.
- **FR-5.4**: A new node can join a cluster with minimal configuration (`NODE_ID`, `CLUSTER_PEERS`).

### 7.6 Self-Learning (statistical, always active)
- **FR-6.1**: Per-host traffic baselining (request rate, response time, status code distribution) using a lightweight statistical model (EWMA/standard deviation).
- **FR-6.2**: Anomaly detection based on deviation from baseline.
- **FR-6.3**: Adaptive WAF tuning — rules that repeatedly produce false positives are flagged for threshold/exception adjustment (with admin approval required for permanent changes).
- **FR-6.4**: Adaptive load balancer weighting based on backend response-time history.

### 7.7 AI Intelligence (optional, external LLM-based)
- **FR-7.1**: The AI Advisor module is active only when the `LLM_API_URL` and `LLM_API_KEY` environment variables are set; otherwise, this feature is fully hidden from the GUI without affecting core functionality.
- **FR-7.2**: Compatible with OpenAI-compatible endpoints (`/v1/chat/completions`) — works with OpenAI, Azure OpenAI, or self-hosted options (Ollama, vLLM, LM Studio, etc.).
- **FR-7.3**: Features: natural-language explanation of WAF incidents, rule tuning suggestions (requiring admin approval before being applied), configuration drafts from natural-language commands, periodic traffic & security summary reports.
- **FR-7.4**: All LLM calls are asynchronous and out-of-band from the traffic path (data plane), with strict timeouts and a circuit breaker — LLM failures or slowness must never affect proxy performance.
- **FR-7.5**: Option to redact sensitive data (IP addresses, payloads) before sending to the external LLM.

### 7.8 Analytics Dashboard
- **FR-8.1**: Global overview: requests/sec, bandwidth, error rate, health status across all nodes.
- **FR-8.2**: Per-host analytics: traffic breakdown, top endpoints, response time (p50/p95/p99), upstream health.
- **FR-8.3**: Security analytics: blocked attacks (by type), top attacker IPs, trends over time, false-positive tracking.
- **FR-8.4**: Load balancer analytics: traffic distribution across backends, failover status.
- **FR-8.5**: Retention policy: raw data kept for a short window (e.g. 24 hours), then rolled up into per-minute/hour/day aggregates for long-term storage.
- **FR-8.6**: Prometheus-compatible metrics endpoint (`/metrics`) for external observability integration (Grafana, etc.).

### 7.9 Plugin System
- **FR-9.1**: Plugins run inside a WASM sandbox (`wasmtime`), isolated from the core process.
- **FR-9.2**: Minimum v1 extension points: custom WAF detector, request/response transform, custom load balancing algorithm, notification sink.
- **FR-9.3**: Every plugin must include a manifest (`plugin.toml`) declaring its permissions (network access, header access, response modification, etc.).
- **FR-9.4**: Per-plugin resource limiting (instruction/fuel metering, memory limits) using wasmtime's built-in features.
- **FR-9.5**: Hot-load/unload plugins without restarting the proxy.
- **FR-9.6**: An official SDK (`bearust-plugin-sdk` crate) to simplify plugin development in Rust; developers in other languages can contribute as long as they can compile to the WASM target.
- **FR-9.7**: (Future target) A community plugin registry/index with checksum/signature verification before installation.

### 7.10 Localization (i18n)
- **FR-10.1**: The management GUI supports multiple languages, with **English as the default**.
- **FR-10.2**: Localization architecture must allow additional languages to be added without core code changes — translations live in externalized resource files (e.g. JSON/YAML per locale), not hardcoded strings.
- **FR-10.3**: Planned initial language targets beyond English: Indonesian and Japanese, with the framework designed to accommodate further languages contributed by the community over time.
- **FR-10.4**: Users can select their preferred language from the GUI; the selection persists per account/session.
- **FR-10.5**: Locale-aware formatting for dates, numbers, and timestamps in the dashboard and logs.
- **FR-10.6**: Translation strings should be community-contributable (e.g. via a structured translation file format), similar in spirit to how other open source dashboards crowdsource localization.
- **FR-10.7**: WAF/security alert messages generated by the AI Advisor (§7.7) should also respect the selected locale where feasible, without compromising the accuracy of technical details.

### 7.11 Installation & Deployment
- **FR-11.1**: Installation via Docker Compose with minimal configuration (a single `.env` file).
- **FR-11.2**: Multi-stage build image, small footprint (non-root user, minimal base).
- **FR-11.3**: Docker Compose profile support to enable external databases (Postgres/MySQL) as needed.
- **FR-11.4**: Upgrade/update process that does not erase data (separate volumes for data & config).

---

## 8. Non-Functional Requirements

| Category | Requirement |
|---|---|
| **Performance** | WAF detection overhead targeted to stay minimal (sub-millisecond to low single-digit ms per request under reasonable load); should not add significant latency compared to a proxy without WAF |
| **Security** | Third-party plugins must run in a sandbox with no direct access to the host filesystem/network; all management communication (GUI-API) must use TLS; passwords hashed with a modern algorithm (Argon2) |
| **Reliability** | Failure of optional modules (AI Advisor, individual plugins) must never cause downtime on the primary traffic path |
| **Scalability** | Supports horizontal node addition without downtime for already-running nodes |
| **Observability** | Structured logs (JSON), Prometheus-compatible metrics, audit trail for all configuration changes |
| **Portability** | Runs on Linux x86_64 and ARM64 at minimum; official Docker images for both architectures |
| **Usability** | Initial installation through first working proxy targeted to be completed quickly by a user with basic Docker experience |
| **Compatibility** | AI Advisor endpoint compatible with the OpenAI Chat Completions API specification |
| **Accessibility & i18n** | GUI text must be externalized for translation (no hardcoded strings in components); layout must accommodate text-length variation across languages without breaking responsive design |

---

## 9. System Architecture (Summary)

The architecture is split into two main layers:

- **Data Plane** (Rust, based on a proxy framework such as Pingora): handles proxying, load balancing, WAF, and self-learning stats in-process, non-blocking relative to the request path.
- **Control Plane** (Rust, async): provides the Config API + RBAC, metrics collector/aggregator, optional AI Advisor, and the web GUI. Communicates with the data plane via config push/reload and asynchronous event channels.

The database (SQLite/MySQL/Postgres) serves as the shared persistence layer for configuration, users/roles, rules, audit logs, metrics rollups, localization preferences, and pending AI suggestions awaiting approval.

For multi-node deployments: configuration is synchronized via Raft consensus across nodes; VIP/failover is handled by `keepalived` at the host level.

The plugin system (WASM sandbox) connects to the core engine through defined hook points, with an explicit per-plugin permission model.

*(Detailed architecture diagrams and GUI mockups were discussed and visualized separately during the product design sessions.)*

---

## 10. Technology Stack (Proposed)

| Layer | Technology |
|---|---|
| Proxy engine | Rust, Pingora (or equivalent), `rustls`, `tokio` |
| Middleware/composability | `tower` |
| WAF | Coraza/OWASP CRS-style rule set adaptation + custom semantic parser |
| Plugin runtime | `wasmtime`, `wasm32-wasip1` target |
| Database access | `sqlx` (SQLite/MySQL/PostgreSQL) |
| Cluster config sync | `openraft` |
| VIP/HA | `keepalived` (external, host-level) |
| AI client | OpenAI-compatible HTTP client (e.g. `async-openai` or raw HTTP) |
| GUI frontend | SPA (React/Vue — decided at implementation time), styled with the latest **Tailwind CSS**, WebSocket/SSE for realtime updates |
| Frontend theming | Design tokens driven by primary color `#D99906`; system/light/dark mode switcher; responsive breakpoints for desktop/tablet/mobile |
| Localization | i18n library appropriate to the chosen frontend framework (e.g. `react-i18next` / `vue-i18n`), externalized locale resource files, English as default fallback |
| Observability | Prometheus-compatible endpoint, structured JSON logs |
| Deployment | Docker, Docker Compose, multi-stage build |

---

## 11. Deployment & Development Environment

The project provides two clearly separated pairs of Docker configurations: one for **production**, one for **development**. Both are not intended to run simultaneously on the same machine without adjusting ports.

### 11.1 File structure

```
bearust/
├── Dockerfile              # production, multi-stage build, small image
├── Dockerfile.dev          # development, cargo-watch, source mounted rather than copied
├── docker-compose.yml      # production
├── docker-compose.dev.yml  # development (backend hot-reload + GUI dev server + optional postgres-dev)
├── .env.example
├── DEPLOY.md                # production guide (full detail in §11.7)
└── DEVELOPMENT.md           # development guide (full detail in §11.8)
```

### 11.2 `Dockerfile` (production)

Multi-stage build: the GUI is built into static assets, the Rust binary is compiled in release mode, then both are combined into a minimal runtime image (non-root user, no build toolchain).

```dockerfile
# ---------- Stage 1: Build GUI (React/Vue SPA) ----------
FROM node:22-alpine AS gui-builder
WORKDIR /gui
COPY gui/package*.json ./
RUN npm ci
COPY gui/ ./
RUN npm run build
# output: /gui/dist

# ---------- Stage 2: Build Rust binary (data plane + control plane) ----------
FROM rust:1.82-slim-bookworm AS rust-builder
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN cargo build --release --locked

# ---------- Stage 3: Runtime image (small, no build toolchain) ----------
FROM debian:bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates libssl3 \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1000 -m -d /home/bearust bearust

COPY --from=rust-builder /app/target/release/bearust /usr/local/bin/bearust
COPY --from=gui-builder /gui/dist /usr/share/bearust/gui

RUN mkdir -p /data /etc/bearust && chown -R bearust:bearust /data /etc/bearust

USER bearust
WORKDIR /home/bearust

EXPOSE 80 443 9443
VOLUME ["/data", "/etc/bearust"]

HEALTHCHECK --interval=15s --timeout=3s --start-period=10s --retries=3 \
    CMD bearust healthcheck || exit 1

ENTRYPOINT ["bearust"]
CMD ["serve", "--config", "/etc/bearust/config.toml"]
```

### 11.3 `Dockerfile.dev` (development)

Source code is **not** `COPY`-ed into the image; instead it is mounted via a volume in `docker-compose.dev.yml`, so file changes are picked up immediately without rebuilding the image. `cargo-watch` handles automatic rebuild + restart.

```dockerfile
# Dockerfile.dev — development image, NOT for production.
FROM rust:1.82-slim-bookworm

RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config libssl-dev ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

# dev tools: cargo-watch for hot-reload, sqlx-cli for database migrations
RUN cargo install cargo-watch --locked \
    && cargo install sqlx-cli --no-default-features --features rustls,sqlite,postgres,mysql --locked

WORKDIR /app
EXPOSE 80 443 9443

ENTRYPOINT ["cargo", "watch", "-x", "run -- serve --config /etc/bearust/config.toml"]
```

### 11.4 `docker-compose.yml` (production)

```yaml
services:
  bearust:
    build: .
    image: bearust:latest
    container_name: bearust
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "9443:9443"
    volumes:
      - bearust-data:/data
      - ./config:/etc/bearust
    environment:
      DATABASE_URL: ${DATABASE_URL:-sqlite:///data/bearust.db}
      NODE_ID: ${NODE_ID:-node-1}
      CLUSTER_PEERS: ${CLUSTER_PEERS:-}
      CLUSTER_BIND_PORT: 7000
      LLM_API_URL: ${LLM_API_URL:-}
      LLM_API_KEY: ${LLM_API_KEY:-}
      ADMIN_INITIAL_EMAIL: ${ADMIN_INITIAL_EMAIL:-admin@example.com}
      ADMIN_INITIAL_PASSWORD: ${ADMIN_INITIAL_PASSWORD:-changeme123}
      DEFAULT_LOCALE: ${DEFAULT_LOCALE:-en}
      RUST_LOG: ${RUST_LOG:-info}
    networks:
      - bearust-net

  # enable with: docker compose --profile postgres up -d
  postgres:
    image: postgres:16-alpine
    container_name: bearust-postgres
    profiles: ["postgres"]
    restart: unless-stopped
    environment:
      POSTGRES_USER: bearust
      POSTGRES_PASSWORD: bearust
      POSTGRES_DB: bearust
    volumes:
      - bearust-pgdata:/var/lib/postgresql/data
    networks:
      - bearust-net

  # enable with: docker compose --profile mysql up -d
  mysql:
    image: mysql:8.4
    container_name: bearust-mysql
    profiles: ["mysql"]
    restart: unless-stopped
    environment:
      MYSQL_USER: bearust
      MYSQL_PASSWORD: bearust
      MYSQL_ROOT_PASSWORD: rootchangeme
      MYSQL_DATABASE: bearust
    volumes:
      - bearust-mysqldata:/var/lib/mysql
    networks:
      - bearust-net

volumes:
  bearust-data:
  bearust-pgdata:
  bearust-mysqldata:

networks:
  bearust-net:
    driver: bridge
```

### 11.5 `docker-compose.dev.yml` (development)

Consists of two main services: the Rust backend with hot-reload, and a GUI dev server with hot module reload — both independent so changes on one side never trigger a rebuild on the other.

```yaml
services:
  bearust-dev:
    build:
      context: .
      dockerfile: Dockerfile.dev
    container_name: bearust-dev
    ports:
      - "8080:80"
      - "8443:443"
      - "9443:9443"
    volumes:
      - .:/app
      - bearust-dev-cargo:/usr/local/cargo/registry
      - bearust-dev-target:/app/target
      - ./config.dev:/etc/bearust
      - bearust-dev-data:/data
    environment:
      DATABASE_URL: ${DATABASE_URL:-sqlite:///data/bearust-dev.db}
      NODE_ID: dev-node
      CLUSTER_PEERS: ""
      LLM_API_URL: ${LLM_API_URL:-}
      LLM_API_KEY: ${LLM_API_KEY:-}
      ADMIN_INITIAL_EMAIL: dev@example.com
      ADMIN_INITIAL_PASSWORD: dev123
      DEFAULT_LOCALE: en
      RUST_LOG: debug
      RUST_BACKTRACE: 1
    networks:
      - bearust-dev-net

  gui-dev:
    image: node:22-alpine
    container_name: bearust-gui-dev
    working_dir: /gui
    volumes:
      - ./gui:/gui
      - bearust-dev-node-modules:/gui/node_modules
    command: sh -c "npm install && npm run dev -- --host 0.0.0.0 --port 5173"
    ports:
      - "5173:5173"
    environment:
      VITE_API_URL: http://localhost:9443
    networks:
      - bearust-dev-net

  # enable with: docker compose -f docker-compose.dev.yml --profile postgres up -d
  postgres-dev:
    image: postgres:16-alpine
    container_name: bearust-postgres-dev
    profiles: ["postgres"]
    ports:
      - "5432:5432"     # exposed to host for GUI DB tools (DBeaver, TablePlus, etc.)
    environment:
      POSTGRES_USER: bearust
      POSTGRES_PASSWORD: bearust
      POSTGRES_DB: bearust_dev
    volumes:
      - bearust-dev-pgdata:/var/lib/postgresql/data
    networks:
      - bearust-dev-net

volumes:
  bearust-dev-cargo:
  bearust-dev-target:
  bearust-dev-node-modules:
  bearust-dev-data:
  bearust-dev-pgdata:

networks:
  bearust-dev-net:
    driver: bridge
```

### 11.6 `.env.example`

```bash
# --- Database ---
DATABASE_URL=sqlite:///data/bearust.db
# DATABASE_URL=postgres://bearust:bearust@postgres:5432/bearust
# DATABASE_URL=mysql://bearust:bearust@mysql:3306/bearust

# --- Cluster (leave empty for a single node) ---
NODE_ID=node-1
CLUSTER_PEERS=

# --- AI Intelligence (optional) ---
LLM_API_URL=
LLM_API_KEY=

# --- Initial admin ---
ADMIN_INITIAL_EMAIL=admin@example.com
ADMIN_INITIAL_PASSWORD=changeme123

# --- Localization ---
DEFAULT_LOCALE=en

RUST_LOG=info
```

### 11.7 Running production

```bash
git clone https://github.com/<org>/bearust.git
cd bearust
cp .env.example .env
nano .env    # adjust ADMIN_INITIAL_PASSWORD, etc.
docker compose up -d
```

Check status: `docker compose ps` and `docker compose logs -f bearust`. Access the management GUI at `https://<server-ip>:9443`, log in with the initial credentials from `.env`, then change the password immediately.

For an external database: `docker compose --profile postgres up -d` or `--profile mysql up -d` (with `DATABASE_URL` in `.env` adjusted accordingly).

For multi-node: set a distinct `NODE_ID` and `CLUSTER_PEERS` on each host, and open port `7000` between nodes only (never expose it publicly). For VIP/HA, `keepalived` is installed and configured at the host level (see the VRRP configuration example under §7.5/FR-5.3) — it does not run inside the container.

Update: `git pull && docker compose build && docker compose up -d` — data in the volume (`bearust-data`) is preserved and not rebuilt.

SQLite backup: `docker compose exec bearust sqlite3 /data/bearust.db ".backup /data/backup-$(date +%F).db"`. Postgres backup: `docker compose exec postgres pg_dump -U bearust bearust > backup.sql`.

### 11.8 Running development

```bash
git clone https://github.com/<org>/bearust.git
cd bearust
cp .env.example .env
docker compose -f docker-compose.dev.yml up
```

Two services become active:

| Service | Purpose | Access |
|---|---|---|
| `bearust-dev` | Rust backend, auto-rebuilds on any `.rs` change (`cargo-watch`) | `https://localhost:9443` (API/management), `http://localhost:8080` (traffic proxy) |
| `gui-dev` | GUI frontend with hot module reload | `http://localhost:5173` |

Live reload works automatically on both sides because source code is mounted rather than copied. Dependency caches (`bearust-dev-cargo`, `bearust-dev-target`, `bearust-dev-node-modules`) are stored in separate volumes so that the second build onward is much faster than the first.

The dev database is separate from production (`bearust-dev.db`, or `postgres-dev` via `--profile postgres`), so it is safe to experiment with. Migrations: `docker compose -f docker-compose.dev.yml exec bearust-dev sqlx migrate run`.

Testing & linting:
```bash
docker compose -f docker-compose.dev.yml exec bearust-dev cargo test
docker compose -f docker-compose.dev.yml exec bearust-dev cargo clippy --all-targets -- -D warnings
docker compose -f docker-compose.dev.yml exec bearust-dev cargo fmt --check
docker compose -f docker-compose.dev.yml exec gui-dev npm run lint
```

Full reset of the dev environment (safe, does not touch production data): `docker compose -f docker-compose.dev.yml down -v && docker compose -f docker-compose.dev.yml up --build`.

Brief contribution flow: fork & branch from `main` → develop using the dev compose stack → ensure `cargo test`/`clippy`/`fmt` pass → include new migration files if the schema changed → open a Pull Request with a clear description. Plugin contributions follow separate documentation to be created alongside the Phase 12 implementation (§12).

### 11.9 Dev vs production differences

| Aspect | Production | Development |
|---|---|---|
| Dockerfile | `Dockerfile` (multi-stage, optimized, release binary) | `Dockerfile.dev` (debug build, cargo-watch) |
| Source code | `COPY`-ed into the image at build time | Mounted live via volume |
| Rebuild | Manual (`docker compose build`) | Automatic on every file save |
| Log level | `info` | `debug` + `RUST_BACKTRACE=1` |
| GUI | Bundled as static files inside the image | Separate dev server with hot reload |
| Port | 80 / 443 / 9443 | 8080 / 8443 / 9443 (backend) + 5173 (GUI dev) |
| Default database | SQLite (`bearust.db`) | Separate SQLite (`bearust-dev.db`) or Postgres dev |

---

## 12. Roadmap / Release Phases

An **incremental** approach, not a big-bang release. Each phase should be stable before moving to the next.

| Phase | Scope |
|---|---|
| **Phase 1 — Core MVP** | Basic reverse proxy + load balancer (round robin, least-conn, health check), file/CLI configuration, no GUI yet |
| **Phase 2 — TLS & Automation** | TLS termination + Let's Encrypt auto-renewal |
| **Phase 3 — Basic GUI** | Proxy host CRUD via web GUI + SQLite |
| **Phase 4 — RBAC & Multi-user** | Roles, permissions, audit log (including the Phase 4C read-only viewer) |
| **Phase 5 — External Database** | MySQL/PostgreSQL support |
| **Phase 6 — Basic WAF** | Signature-based rule set for common attacks |
| **Phase 7 — Advanced WAF** | Semantic detection engine, bot protection, adaptive rate limiting |
| **Phase 8 — Analytics Dashboard** | Metrics collector, rollups, realtime dashboard, Prometheus endpoint |
| **Phase 9 — Self-Learning** | Baselining, anomaly detection, adaptive tuning |
| **Phase 10 — Multi-Node** | Raft config sync, keepalived integration documentation |
| **Phase 11 — Localization (complete)** | i18n framework, English default, Indonesian and Japanese as initial additional languages, community translation contribution process |
| **Phase 12 — AI Advisor** | Optional module based on external LLM |
| **Phase 13 — Plugin System** | WASM runtime, SDK, initial hook points |
| **Phase 14 — Plugin Ecosystem** | Community registry, signature verification, public contribution documentation |

### Phase 4C status: authenticated audit-log viewer

The Phase 4C increment delivers a read-only `GET /api/audit-logs` endpoint and dashboard section for authenticated `admin`, `operator`, and `viewer` sessions. The API supports exact `event` and `actor_id` filters, inclusive RFC3339 `from`/`to` bounds, and `q` text search over event/details. Responses are deterministic newest-first pages with `page` (default `1`) and `page_size` (default `25`, constrained to `1`–`100`) plus a total count.

Rows expose only an actor label, event, redacted details, timestamp, and ID. Actor labels resolve to the current email, `system`, or `deleted-user`; sensitive credentials, hashes, tokens, private keys, request bodies, and raw database errors are sanitized at the read boundary and never serialized, rendered, or otherwise exposed. No audit delete, mutation, or export operation is provided.

### Phase 4D.1 status: persistent RBAC and audit coverage

Phase 4D.1 adds additive, idempotent persistence for the ten global permission keys and the built-in `admin`, `operator`, and `viewer` roles, plus administrator-managed custom role CRUD. Built-in roles remain immutable; assigned custom roles may have permissions changed immediately but cannot be deleted while referenced by users. Existing role strings and session cookies remain compatible, and unknown roles fail closed through centralized authorization.

Administrators can revoke another user's active sessions through `POST /api/users/{id}/sessions/revoke`; self-revocation is rejected. Role, user, session, proxy-host, certificate, and authorization-denial paths record safe audit events. The dashboard includes admin-only role and session controls. Per-host scopes, audit export, system settings, realtime updates, and frontend theme work remain deferred to later Phase 4 increments.

### Phase 4D.2 status: authenticated realtime updates

Phase 4D.2 adds the authenticated `GET /api/events` Server-Sent Events (SSE) stream used by the dashboard to invalidate and reload proxy-host, certificate, user, role, and audit data without polling. Session changes are also emitted as invalidation notifications for session-view consumers. Session-cookie authentication is required, and event payloads are intentionally redacted. The hub is process-local with bounded delivery; clients receive periodic heartbeats and use bounded automatic reconnects after disconnects. Cross-node fan-out and replay of events missed during a disconnect are deferred to the multi-node phase.

### Phase 4D.3 status: Tailwind v4 frontend design system

Phase 4D.3 completes the frontend migration to Tailwind CSS v4 across all existing management pages. Shared semantic design tokens and accessible UI primitives provide consistent responsive layouts, focus states, and status treatments. Theme selection supports `system`, `light`, and `dark` modes with local persistence; account-level preference synchronization remains deferred to the future system-settings capability.

### Phase 4E status: per-host RBAC scopes

Phase 4E completes the first per-resource authorization increment. Custom roles can grant `proxy_hosts.read` and `proxy_hosts.write` for an explicit set of proxy-host IDs while retaining the existing global permissions. Scoped users see only assigned hosts and cannot create, read, update, or delete unassigned hosts; global administrators and legacy global role assignments remain backward-compatible. Scope replacements are validated and committed atomically, proxy-host deletion removes stale assignments, and role-scope mutations emit redacted audit records plus authenticated realtime invalidation events.

Phase 4E deliberately keeps certificate permissions global and does not introduce per-certificate or per-upstream scopes. It also does not provide cross-node realtime delivery, event replay after disconnect, audit export, delegated role administration, or a general-purpose policy language; those capabilities remain future work in the multi-node and later control-plane phases.

### Phase 5 status: external database support

Phase 5 is complete for the control-plane database layer. BeaRust supports
SQLite (the default, including existing file-backed installations), PostgreSQL,
and MySQL through `DATABASE_URL`; the repository and services use a database-
agnostic pool and portable SQL. Versioned SQLx migrations are applied
automatically before the control plane serves requests, are tracked by SQLx,
and preserve existing SQLite data while adding the current schema. PostgreSQL
and MySQL Compose services are opt-in profiles with persistent volumes.

External-driver integration tests are opt-in through `DATABASE_URL_EXTERNAL` so
the normal test suite never mutates a developer-managed database. The harness
verifies migration idempotency, RBAC seeds, and a basic user round trip; an
unset variable produces an explicit skip. Database export/import, read
replicas, clustering or replication, backup automation, online migration
orchestration, and cross-node database coordination are intentionally outside
Phase 5.

---

## 13. Success Metrics (KPIs)

- **Adoption**: number of active installations/Docker image pulls, repository stars & forks.
- **WAF reliability**: true-positive vs false-positive ratio for built-in rules (targeted to be competitive with comparable open source solutions).
- **Installation ease**: average time from `git clone` to a running first proxy (target: under 10 minutes for a user with Docker already installed).
- **Community contribution**: number of third-party plugins published, number of active contributors to the core repository, number of community-contributed language packs.
- **HA stability**: VIP failover time when the primary node goes down (target: within seconds, consistent with VRRP characteristics).

---

## 14. Risks & Mitigations

| Risk | Impact | Mitigation |
|---|---|---|
| Scope too large for a small team, project stalls | High | Phased roadmap (§12), release a functional MVP as early as possible |
| Semantic WAF engine hard to develop to SafeLine's standard | Medium | Start with a proven signature-based (Coraza-style) approach, add semantic detection incrementally as an enhancement, not a launch blocker |
| Third-party plugins become an attack vector | High | Mandatory WASM sandbox, explicit permission model, resource limiting, checksum verification before a public registry launches |
| Dependency on external LLMs disrupts the traffic path | Medium | AI Advisor designed to be out-of-band, async, with strict timeouts & a circuit breaker |
| Config sync across nodes fails during network partitions | Medium | Use a proven Raft implementation (`openraft`), explicitly test partition scenarios before releasing the multi-node feature |
| Localization becomes a maintenance burden as languages grow | Medium | Externalize all strings from day one, provide a clear community translation contribution process rather than centralizing translation work |
| Project name/branding changes later on | Low | Confirm final naming (`BeaRust`) availability on GitHub/crates.io before the first public release |

---

## 15. Open Questions / Pending Decisions

1. Final open source license: MIT+Apache-2.0 dual (common in Rust) or AGPL (like SafeLine, preventing unmodified commercial re-branding without contributing back)?
2. Community governance structure: who has merge rights, what is the review process for external contributions (including plugins)?
3. Will there be a paid "Pro" edition in the future (additional enterprise features), or will all features remain free forever?
4. Final GUI frontend framework (React vs Vue) — needs to be decided before Phase 3.
5. HTTP/3 support target — included in v1 or deferred to a later release?
6. Data privacy policy for the AI Advisor feature (default sensitive-data redaction: opt-in or opt-out?).
7. Translation tooling/workflow for localization: a lightweight file-based approach (JSON/YAML per locale reviewed via PR) vs a dedicated translation management platform — to be decided before Phase 11.

---

## 16. Appendix

### 16.1 Glossary
- **WAF** — Web Application Firewall, a system that filters/blocks malicious HTTP traffic.
- **RBAC** — Role-Based Access Control, access control based on user roles.
- **VIP** — Virtual IP, an IP address that can move between nodes for high-availability purposes.
- **VRRP** — Virtual Router Redundancy Protocol, the protocol underlying `keepalived`.
- **WASM** — WebAssembly, a portable bytecode format used as the plugin execution sandbox.
- **i18n / Localization** — internationalization, the practice of designing software so its interface text can be translated and adapted to different languages without code changes.
- **Data plane / Control plane** — the architectural separation between the direct traffic-processing path (data plane) and the management/configuration path (control plane).

### 16.2 Conceptual References
- Nginx Plus, F5 — reference for enterprise proxy/LB feature depth.
- Nginx Proxy Manager — reference for GUI ease of use.
- SafeLine WAF (chaitin/SafeLine) — reference for the semantic detection engine approach and bot protection.
- Coraza / OWASP CRS — reference for signature-based WAF rule sets.
- Envoy Proxy — reference for WASM-based plugin architecture patterns.

---

*This document is a living document — it will be updated as technical decisions and project scope evolve.*
### Phase 6 status: basic WAF

Phase 6 is complete for the basic in-process WAF scope. BeaRust persists and
seeds common attack signatures; supports monitor-only and block modes; validates
bounded custom rules; exposes admin CRUD and TOML import/export; publishes
immutable proxy snapshots; records redacted audit events; emits SSE
invalidation; and provides dashboard controls. Advanced OWASP CRS parity, bot
management, adaptive rate limiting, distributed synchronization, and automatic
rule updates remain future work.

### Phase 7A status: bounded semantic WAF detection

Phase 7A delivers the first increment of Advanced WAF: a deterministic,
in-process semantic evaluator layered on the existing signature rules. Request
method, path, query, headers, and up to 8 KiB of body data are normalized with
bounded percent-decoding and separator/case canonicalization before evaluating
SQL injection, XSS, path traversal, command injection, and protocol-anomaly
signals. Scores, severities, and category identifiers are stable and bounded;
explicit rule actions retain precedence, monitor-only remains the default, and
block mode uses a conservative threshold. The first 8 KiB of a request body
are bounded-buffered and withheld until evaluation; larger bodies flush that
prefix and continue streaming without unbounded memory. Proxy snapshots are
immutable and reload atomically, while audit and realtime telemetry contain only redacted
category/score/severity identifiers and never request bodies, credentials, or
sensitive header values.

### Phase 7B status: bounded bot protection and signed challenges

Phase 7B delivers deterministic bot-risk policy with monitor-only as the default,
admin-selectable challenge/block modes, bounded score threshold and challenge
TTL controls, and trusted-crawler CRUD with explicit user-agent/domain matching.
Trusted-crawler configuration is persisted and manageable, but runtime bypass is
deferred until a cryptographically signed ingress marker exists; no unsigned
Host, User-Agent, or client header is trusted.
Suspicious traffic can complete a short proof-of-work challenge backed by an
expiring, replay-safe HMAC token; challenge responses are generic and secrets,
raw fingerprints, and tokens are never rendered in the dashboard or audit data.
The responsive admin dashboard exposes policy and crawler controls with
validation and accessible loading/error states.

Adaptive rate limiting, CAPTCHA provider integrations, and tuning feedback
remain deferred to Phase 7C and later increments.

### Phase 8 status: bounded analytics dashboard

Phase 8 delivers process-local operational analytics for proxy traffic and
security decisions. A bounded one-minute ring buffer retains 24 hours (up to
1,440 buckets per host) and resets on process restart. Summary and timeseries
queries are authenticated, read-only endpoints for `admin`, `operator`, and
`viewer` roles; host and bucket limits are bounded at 100 and 1,440, and
invalid or oversized ranges return `400`. Collection is fail-open and stores
only aggregate status, latency histograms, and redacted WAF, bot, and
rate-limit counters—never raw IP addresses, complete URLs, headers, bodies,
credentials, tokens, or secrets.

The dashboard provides host/time filters, request and status cards, latency
percentiles, error views, security-event panels, and loading/error/empty
states. It refetches bounded data after the authenticated SSE
`analytics.changed` invalidation event; the event carries no metric payload.
Prometheus `/metrics` is disabled by default. When enabled, the default
internal bind is `127.0.0.1:9090`, internal-only mode requires loopback, and
external exposure requires authentication. Output uses bounded configured
proxy-host and status-class labels with a 256 KiB default cap.

Durable history, Redis/cross-node aggregation and fan-out, per-route
dimensions, custom retention, and cross-node replay remain deferred to Phase 10–13.

### Phase 9 status: self-learning (traffic baseline, anomaly detection, adaptive tuning)

Phase 9 delivers a complete three-stage self-learning framework:
- **Phase 9A — Traffic Baseline**: Bounded process-local per-host baseline collector aggregating request rate, status breakdown, error rate, latency percentiles (p50, p95, p99), and security event counters across 5m, 1h, and 24h rolling windows. Status handles `warming_up` state safely until sample counts are sufficient. Exposed via host-scoped API `GET /api/analytics/baseline` and `baseline.changed` SSE event.
- **Phase 9B — Anomaly Detection**: Deterministic monitor-only traffic deviation evaluator detecting request-rate spikes, error-rate spikes, latency regressions, and security-event surges with EWMA and standard deviation scoring. Evaluates `info`, `warning`, and `critical` severities, prevents critical anomalies during `warming_up`, enforces 5-minute deduplication cooldowns, and exposes `GET /api/analytics/anomalies` and `POST /api/analytics/anomalies/{id}/ack` with `anomaly.changed` SSE event.
- **Phase 9C — Adaptive Tuning**: Opt-in per-host policy recommendation and tuning engine with guardrails (mode defaults to `monitor`, max delta limits, min confidence floor, emergency global disable). Persisted via SQLite migration `0007_adaptive_tuning.sql` with atomic apply/rollback, audit logging, and `adaptive_tuning.changed` SSE event.

### Phase 10A status: cluster foundation (node identity, peer configuration, bounded health)

Phase 10A delivers the cluster foundation for multi-node BeaRust deployments:
- **Node Identity & Peer Configuration**: Explicit `NODE_ID`, `CLUSTER_PEERS`, and shared `CLUSTER_AUTH_TOKEN` configuration parsed via environment variables or TOML (`[cluster]` section). Validates non-empty node IDs, rejects malformed, duplicate, or self-referential peer definitions, enforces a 64-peer bound, and defaults to single-node operation (`peers = []`) when omitted.
- **Bounded Peer Health Service**: `ClusterService` executes an authenticated HMAC challenge-response handshake over out-of-band TCP connections with bounded timeouts and concurrency. Peer failures (authentication failure, connection refused, timeout, unreachable) produce per-peer unhealthy snapshots without causing process errors or affecting proxy request paths.
- **Authenticated Status API**: `GET /api/cluster/status` exposes authenticated local node identity, cluster status, and redacted peer health snapshots. Responses omit raw connection strings, secrets, and credentials.
- **Delivered in Phases 10B–10C**: Raft consensus/state replication, leader election, authenticated write forwarding, committed cross-node invalidation fan-out, and documented host-level keepalived/VIP operation. BeaRust does not execute keepalived or mutate host interfaces.

### Phase 10B status: durable Raft configuration synchronization

Phase 10B adds bounded, authenticated OpenRaft storage and membership
management for multi-node configuration state. Replicated commands are applied
through the state machine with idempotent command receipts; single-node
configurations remain compatible, and follower reads remain local. Cluster
transport frames are size-limited and authenticated with the existing
handshake; sensitive request data and raw database errors are not forwarded.

### Phase 10C status: HA operations and keepalived/VIP guidance

Phase 10C completes the multi-node control-plane operations increment. Writes
from followers use the authenticated leader gateway and return stable errors
when leadership or quorum is unavailable. Committed invalidation events fan
out through bounded peer queues, are deduplicated, and trigger local state
reload/catch-up without changing the public SSE payload contract. Failover,
quorum loss, reconnect, and idempotent retry behavior are covered by the
three-node acceptance tests.

Keepalived remains a host-level VRRP responsibility. The
[keepalived operations guide](keepalived.md) supplies a bounded, authenticated
readiness check, three-node priorities and `nopreempt` example, split-brain
fencing warnings, and rollback steps. The readiness check is fail-closed on
proxy/control listener failure, unknown leader, stale quorum, unhealthy peer
set, timeout, or malformed status; it never changes a container or host
interface.

### Phase 11 status: localization

Phase 11 is complete across three increments:

- **Phase 11A — i18n foundation:** the dashboard uses externalized i18next
  resources with English as the default and fallback, plus an accessible locale
  selector.
- **Phase 11B — translated surfaces:** Indonesian (`id`) and Japanese (`ja`)
  catalogs cover the authenticated dashboard surfaces and are checked for key
  and interpolation-placeholder parity with English (`en`).
- **Phase 11C — preference, formatting, and contribution workflow:** a
  validated account locale preference persists through the existing profile
  API; dates and numbers use the selected locale; responsive translation
  layouts are covered by frontend tests; and the documented JSON catalog review
  flow is enforced by `npm run validate-locales --prefix frontend`.

### Phase 12 status: AI Advisor

Phase 12 is complete as an optional, bounded, fail-open advisor. It remains
disabled unless explicitly configured with both provider URL and key; inputs,
results, queues, and telemetry are bounded and redacted.

### Phase 13A status: WASM plugin runtime foundation (implementation complete; acceptance gate pending)

The Phase 13A implementation is complete. BeaRust now has an optional,
deny-by-default local
`wasmtime` runtime with versioned `plugin.toml` validation, canonicalized path
containment, the health-check-only ABI, fuel/memory/timeout/output limits,
atomic load/enable/disable/unload snapshots, and authenticated lifecycle APIs.
Plugins receive no WASI, filesystem, network, environment, database, secret, or
proxy request access. Invalid manifests, traps, resource exhaustion, and
runtime initialization failures are isolated from startup and proxy traffic;
status, audit, realtime, and metrics surfaces are bounded and redacted.

The final acceptance gate remains pending: the required stable-toolchain gate
could not complete in this environment (stable Clippy is blocked by the
edition-2024 `clap_lex` dependency and the stable all-targets linker run
exhausted disk space). Nightly Clippy reports three
pre-existing unrelated diagnostics, and the full all-targets Rust run was
blocked by host disk exhaustion while compiling parallel test targets. The
focused plugin suite passes; frontend tests/build/locale validation pass after
installing frontend dependencies.

The default is `plugins.enabled = false`. Phase 13A deliberately has no public
SDK, traffic hooks, registry, remote download, signature verification, or
trust-on-first-use behavior. Phase 13B is next and will define the public SDK
and stable memory/serialization conventions. Phase 13C will add explicitly
reviewed traffic hooks with input redaction and backpressure semantics. Phase
14 remains deferred for registry distribution and signature verification.
