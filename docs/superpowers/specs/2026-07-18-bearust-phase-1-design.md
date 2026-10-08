# Bearust Phase 1 Design

**Date:** 2026-07-18
**Status:** Approved for implementation planning
**Scope:** Phase 1 — Core MVP

## 1. Objective

Phase 1 delivers a usable Rust reverse proxy and load balancer with:

- HTTP/1.1 reverse proxying, streaming bodies, and WebSocket passthrough.
- Host and path-prefix routing.
- Round-robin and least-connections load balancing.
- Active TCP or HTTP health checks.
- TOML file configuration and a command-line interface.
- Validated, atomic configuration reload without interrupting active requests.
- Native binary and Docker Compose deployment paths.

Phase 1 does not include the GUI, database persistence, TLS termination, ACME, HTTP/2, WAF, RBAC, clustering, analytics, AI assistance, localization, or plugins. Those remain in later PRD phases.

## 2. Architecture

Bearust Phase 1 is a single Rust binary implemented as a modular monolith on top of Pingora. A single process keeps deployment and debugging simple, while internal boundaries allow the data plane and control plane to be separated in a future phase.

The binary contains these modules:

- `cli`: Implements `serve`, `validate`, `reload`, and version output.
- `config`: Deserializes TOML, validates cross-field constraints, and builds immutable runtime configuration.
- `router`: Selects a route by normalized host and longest matching path prefix.
- `proxy`: Integrates the Pingora lifecycle and handles streaming HTTP and WebSocket traffic.
- `balancer`: Selects healthy backends using round-robin or least-connections.
- `health`: Runs active TCP or HTTP probes and tracks threshold-based health transitions.
- `reload`: Handles `SIGHUP` and atomically replaces validated runtime state.
- `observability`: Emits structured logs for lifecycle events, routing failures, health transitions, reloads, and proxy errors.

The request flow is:

```text
listener
  -> host/path router
  -> upstream pool
  -> healthy backend selection
  -> streaming proxy request
  -> upstream response
```

Runtime configuration is held behind an atomic, shared snapshot. Each accepted request keeps the snapshot it started with. A successful reload affects new requests; active requests continue against their original snapshot.

## 3. Configuration

Bearust uses TOML. The default configuration filename in examples is `bearust.toml`.

```toml
[server]
bind = "0.0.0.0:8080"
graceful_shutdown_seconds = 30
pid_file = "./bearust.pid"

[health]
interval_seconds = 10
timeout_seconds = 2
unhealthy_threshold = 3
healthy_threshold = 2

[[upstream_pools]]
name = "api"
algorithm = "least_connections"
connect_timeout_seconds = 3
request_timeout_seconds = 30

[[upstream_pools.backends]]
address = "127.0.0.1:9001"
health_check = "http"
health_path = "/health"

[[upstream_pools.backends]]
address = "127.0.0.1:9002"
health_check = "tcp"

[[routes]]
name = "api-v1"
host = "api.example.com"
path_prefix = "/v1"
upstream_pool = "api"
```

Validation enforces the following invariants:

- The listener address is explicit and valid.
- Route names and upstream pool names are unique.
- Every route references an existing pool.
- Every pool has at least one backend.
- Algorithms are limited to `round_robin` and `least_connections`.
- Backend addresses, timeouts, health intervals, and thresholds are valid positive values.
- HTTP health checks require a path beginning with `/`.
- Route hosts are normalized case-insensitively and without a port.
- Route path prefixes begin with `/`.
- Duplicate normalized host and path-prefix combinations are rejected.

Safe defaults are provided for health timing, timeouts, graceful shutdown, and a PID file in the current working directory. At least one route and one upstream pool must be declared. Phase 1 has no secret-bearing configuration.

## 4. Routing

For an incoming request, the router:

1. Normalizes the request host to lowercase and removes its port.
2. Selects routes with an exact normalized host match.
3. Chooses the matching route with the longest path prefix.
4. Returns `404 Not Found` when no route matches.

Path-prefix matching respects segment boundaries: `/api` matches `/api` and `/api/users`, but not `/apiv2`. Wildcard hosts and path rewriting are not part of Phase 1.

## 5. Load Balancing and Failure Handling

`round_robin` walks the currently healthy backends in sequence. Concurrent selection uses an atomic cursor so requests do not require a global mutex.

`least_connections` chooses a healthy backend with the fewest in-flight requests. Ties use stable rotation to avoid permanently favoring the first backend. An RAII-style guard decrements the counter on every completion and error path.

Weighted balancing is not part of Phase 1 and no weight field is accepted.

When an upstream connection fails before any request bytes are forwarded, Bearust may try one other healthy backend. A request is never retried after transmission begins, preventing duplicate execution of non-idempotent requests.

If a route has no healthy backend, Bearust immediately returns `503 Service Unavailable`. Internal upstream details are not exposed in client error bodies.

## 6. Proxy Semantics

Phase 1 supports:

- HTTP/1.1 downstream and upstream traffic.
- Streaming request and response bodies without whole-body buffering.
- WebSocket upgrade and bidirectional passthrough.
- Configurable connection and request timeouts per upstream pool.

Bearust preserves the original `Host` header and maintains:

- `X-Forwarded-For`, appending the immediate client address.
- `X-Forwarded-Proto`, set to `http` in Phase 1.
- `X-Request-ID`, preserving a valid incoming value or generating one when absent.

Pingora handles hop-by-hop header semantics. Phase 1 does not perform caching, compression, body transformation, authentication, or rate limiting.

## 7. Health Checks

Each backend uses either:

- A TCP check that succeeds when a connection can be established within the configured timeout.
- An HTTP check that sends `GET` to `health_path` and treats a `2xx` response as success.

A healthy backend becomes unhealthy after `unhealthy_threshold` consecutive failures. An unhealthy backend becomes healthy after `healthy_threshold` consecutive successes. State transitions are logged; routine successful probes are not logged at the default level.

Health-check workers are rebuilt when configuration reload changes the backend set or health settings. Removed workers are cancelled, unchanged backend state is retained where its identity and check definition match, and new backends begin in a probing state. A new backend becomes eligible only after satisfying the healthy threshold, avoiding traffic before readiness is established.

## 8. Reload and Shutdown

`SIGHUP` triggers this sequence:

1. Read the configured TOML file.
2. Parse and fully validate it.
3. Build routing, balancing, and health-check runtime state.
4. Atomically publish the new snapshot.
5. Retire obsolete background workers.

If any step before publication fails, the current configuration remains active and the failure is logged with actionable field context.

`SIGTERM` and `SIGINT` stop accepting new connections, allow active requests to finish for up to `graceful_shutdown_seconds`, stop background workers, and exit. Requests remaining after the deadline are terminated.

## 9. Command-Line Interface

```text
bearust serve --config bearust.toml
bearust validate --config bearust.toml
bearust reload --pid-file /run/bearust.pid
bearust --version
```

- `serve` loads the configuration, writes the configured PID file, and starts the proxy.
- `validate` parses and validates configuration without opening a listener.
- `reload` reads the PID file and sends `SIGHUP` to the active process.
- Validation errors identify the affected field or object and explain the violated constraint.
- Commands use non-zero exit codes for invalid input or failed operations.

PID-file creation fails rather than overwriting a file that points to a live process. A stale PID file may be replaced after verifying that its process does not exist.

## 10. Observability

Logs are structured JSON in production and human-readable in development. Each request log includes request ID, matched route, chosen upstream, response status, latency, and error category when applicable. A client-supplied request ID is accepted only when it is 1–128 characters long and contains ASCII letters, digits, `.`, `_`, `:`, or `-`; otherwise Bearust generates a new ID.

Lifecycle logs cover startup, shutdown, configuration reload outcome, and health transitions. Sensitive request or response bodies are never logged. Prometheus metrics and long-term analytics remain outside Phase 1.

## 11. Repository Layout

```text
bearust/
├── src/
│   ├── main.rs
│   ├── cli.rs
│   ├── config/
│   ├── router/
│   ├── proxy/
│   ├── balancer/
│   ├── health/
│   ├── reload.rs
│   └── observability.rs
├── tests/
│   ├── fixtures/
│   ├── config_validation.rs
│   ├── routing.rs
│   ├── load_balancing.rs
│   ├── health_failover.rs
│   ├── websocket.rs
│   └── reload.rs
├── config/bearust.example.toml
├── Dockerfile
├── Dockerfile.dev
├── docker-compose.yml
├── docker-compose.dev.yml
├── .env.example
├── README.md
├── DEVELOPMENT.md
├── DEPLOY.md
└── docs/
```

Phase 1 starts as one application crate. Workspace extraction is deferred until a real reusable crate boundary appears. The existing Bearust logo is used in the README and documentation; GUI work remains out of scope.

## 12. Deployment

Delivery includes:

- A native release binary.
- A multi-stage production image with a minimal runtime and non-root user.
- Docker Compose configuration that mounts the TOML configuration read-only.
- A development image with source mounting and automatic rebuild.
- A container health check that verifies the Bearust process is running and its listener is accepting connections.

The production container persists no application database in Phase 1. Example configuration is safe for local evaluation and clearly marks values that must change for real deployment.

The project uses the MIT and Apache-2.0 dual-license model proposed by the PRD.

## 13. Testing

Unit tests cover:

- TOML parsing and every validation invariant.
- Host normalization and segment-aware longest-prefix routing.
- Round-robin sequencing under concurrency.
- Least-connections selection, tie rotation, and counter cleanup.
- Health threshold state transitions.

Integration tests start local test backends and cover:

- Streaming request and response bodies.
- Forwarded headers and request IDs.
- `404` for unmatched routes.
- `503` when no backend is healthy.
- Backend failover before forwarding begins.
- No retry after forwarding begins.
- WebSocket upgrade and bidirectional messages.
- Successful reload, rejected invalid reload, and in-flight request continuity.
- Graceful shutdown with an active request.

Required verification commands are:

```bash
cargo fmt --check
cargo clippy --all-targets -- -D warnings
cargo test
docker compose config
docker build .
```

GitHub Actions runs formatting, linting, tests, and the production container build.

## 14. Completion Criteria

Phase 1 is complete when a user can:

1. Copy the example TOML configuration.
2. Start Bearust natively or with `docker compose up`.
3. Route HTTP/1.1 and WebSocket traffic by domain and path prefix.
4. Observe round-robin and least-connections distribution across healthy backends.
5. Observe unhealthy backends leave rotation and recover after successful probes.
6. Receive deterministic `404` and `503` responses for routing and availability failures.
7. Validate and reload configuration without interrupting active requests.
8. Stop Bearust gracefully.

All required verification commands must pass, and the implementation documentation must describe local development, production deployment, configuration, and operational reload.
