# Development

Native development needs Rust 1.84.1, Cargo, clang, cmake, make, perl, and pkg-config. Without local Rust, run `docker compose -f docker-compose.dev.yml up --build`; the repository and Cargo caches are mounted and cargo-watch reruns the server.

Tests in `src/` and `tests/` cover routing, balancing, health, reload, logs, HTTP, WebSocket, and shutdown. Use `cargo test --locked`, `cargo fmt --check`, and `cargo clippy --all-targets -- -D warnings`.

External database integration tests are opt-in so the normal test suite never
mutates a developer database. Start a PostgreSQL or MySQL instance, then run:

```bash
DATABASE_URL_EXTERNAL=postgres://bearust:bearust@127.0.0.1:5432/bearust cargo test --locked --test external_database
DATABASE_URL_EXTERNAL=mysql://bearust:bearust@127.0.0.1:3306/bearust cargo test --locked --test external_database
```

When `DATABASE_URL_EXTERNAL` is absent, the external test reports an explicit
skip and exits successfully.

The application runs the checked-in SQLx migrations during startup. SQLite
remains the default for local development; switching to PostgreSQL or MySQL
requires setting `DATABASE_URL` and starting the matching Compose profile.
Phase 5 does not automate data export/import between backends, so verify a
backup and restore plan before changing a production database URL.

Focused TDD: add a minimal regression test, run it to observe failure, implement the smallest change, then rerun the focused test and the full suite.

## Localization contribution workflow

The supported dashboard locale codes are `en` (English, the source and
fallback catalog), `id` (Indonesian), and `ja` (Japanese). Translation catalogs
live in `frontend/src/locales/`; follow [docs/localization.md](docs/localization.md)
for key naming, interpolation, and review guidance.

For every locale catalog change, run the key and interpolation-placeholder
validator before requesting review:

```bash
npm run validate-locales --prefix frontend
npm test --prefix frontend
npm run build --prefix frontend
```

For a release or cross-stack change, use the complete acceptance gate from the
repository root:

```bash
npm run validate-locales --prefix frontend
npm test --prefix frontend
npm run build --prefix frontend
cargo +stable test --all-targets -- --test-threads=1
cargo +stable fmt --all -- --check
cargo +stable clippy --all-targets -- -D warnings
git diff --check
```

## Phase 8 analytics checks

Analytics is deliberately process-local: the one-minute ring buffer is bounded
to 24 hours (1,440 buckets per host) and resets whenever the process restarts.
Queries clamp host and timeseries limits to 100 and 1,440 respectively. The
collector stores only aggregate status, latency histograms, and redacted WAF,
bot, and rate-limit counters; raw IPs, URLs, headers, bodies, credentials,
tokens, and secrets are excluded. Recording is fail-open so an analytics error
does not reject or materially delay a proxy request.

The summary and timeseries endpoints require an authenticated admin, operator,
or viewer session and are read-only. Prometheus is disabled by default; when
enabled, its default internal bind is `127.0.0.1:9090`, and internal-only mode
requires loopback. An externally bound endpoint must require authentication.
Output uses bounded proxy-host/status-class labels and a 256 KiB default cap.
The frontend Analytics panel renders filters, summary cards, latency/error
views, security panels, and loading/error/empty states, then refetches on the
redacted `analytics.changed` SSE invalidation event.

Focused verification commands:

```bash
cargo +nightly fmt --all -- --check
cargo +nightly check --all-targets
cargo +nightly test --test analytics --test prometheus --test control_plane_analytics --test proxy_analytics
npm test --prefix frontend -- --run src/analytics.test.tsx src/realtime.test.tsx
npm run build --prefix frontend
git diff --check
```

Durable historical storage, Redis/cross-node aggregation and replay,
per-route analytics, anomaly detection, adaptive tuning, custom retention, and
alerting are intentionally deferred.
## Basic WAF

Migration `0004_basic_waf.sql` seeds four built-in rules and defaults to
`monitor-only`. Administrators manage configuration through `/api/waf/config`
and `/api/waf/rules` or the dashboard. TOML imports use `version = 1` and are
rejected when any matcher is invalid. The evaluator inspects bounded request
fields and at most 8 KiB of body data.

Focused checks:

```bash
cargo +stable test --test waf_repository --test waf_engine --test proxy_waf --test control_plane_waf
npm test --prefix frontend -- --run waf.test.tsx
```
