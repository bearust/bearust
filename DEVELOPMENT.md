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
