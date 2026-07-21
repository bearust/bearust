# Phase 5 External Database Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add PostgreSQL and MySQL support to BeaRust's control plane while preserving SQLite as the default and keeping existing API behavior stable.

**Architecture:** `control_plane::repository` will expose `sqlx::AnyPool`, validate supported URL schemes, and run ordered SQLx migrations. Repository queries will use portable SQL and small helpers for generated IDs and conflict-safe seeds; handlers and services will remain database-agnostic.

**Tech Stack:** Rust 1.84, SQLx 0.8 (`any`, `sqlite`, `postgres`, `mysql`, `migrate`), Tokio, Docker Compose, SQLite/PostgreSQL/MySQL.

## Global Constraints

- SQLite remains the zero-configuration default.
- Accepted URLs are `sqlite:///data/bearust.db`, `postgres://user:password@host:5432/database`, and `mysql://user:password@host:3306/database`.
- Existing authentication, RBAC, audit, certificate, proxy-host, and realtime API contracts must remain unchanged.
- Database credentials must never appear in API responses, audit details, or structured logs.
- Existing SQLite databases must upgrade without data loss.
- External integration tests are opt-in through explicit environment URLs.
- Do not add clustering, replication, backup automation, or online migration orchestration in Phase 5.

---

### Task 1: Enable SQLx drivers and centralize database URL validation

**Files:**
- Modify: `Cargo.toml`
- Modify: `src/control_plane/repository.rs`
- Modify: `src/control_plane/mod.rs`
- Test: `tests/control_plane_repository.rs`

**Interfaces:**
- Produces `pub type DbPool = sqlx::AnyPool`.
- Produces `pub fn validate_database_url(url: &str) -> Result<(), sqlx::Error>`.
- Produces `pub async fn connect(url: &str) -> Result<DbPool, sqlx::Error>`.

- [ ] **Step 1: Add SQLx feature flags**

Update the `sqlx` dependency to include `any`, `migrate`, `postgres`, and `mysql` alongside the existing runtime, SQLite, UUID, chrono, and macros features. Run `cargo check --locked` to refresh `Cargo.lock` and confirm all selected drivers compile.

- [ ] **Step 2: Write URL validation tests**

Add tests asserting that `sqlite://`, `postgres://`, and `mysql://` URLs are accepted, while `redis://` and an empty URL return an error whose text contains `unsupported database URL` and never echoes a password.

- [ ] **Step 3: Implement validation and connection setup**

Parse the scheme before connecting. Configure `AnyPoolOptions::new().max_connections(8)`, call `sqlx::any::install_default_drivers()` exactly once during connection setup, and return a sanitized `sqlx::Error::Configuration` for unsupported or empty schemes. Keep SQLite parent-directory creation in `build_state` only for `sqlite://` paths.

- [ ] **Step 4: Run focused tests**

Run `cargo test --locked control_plane_repository::database_url -- --nocapture`. Expected: all URL validation tests pass.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src/control_plane/repository.rs src/control_plane/mod.rs tests/control_plane_repository.rs
git commit -m "feat: add database driver selection"
```

### Task 2: Move inline schema into ordered portable migrations

**Files:**
- Create: `migrations/0001_initial.sql`
- Create: `migrations/0002_add_disabled_and_secret_ref.sql`
- Modify: `src/control_plane/repository.rs`
- Test: `tests/control_plane_repository.rs`

**Interfaces:**
- Produces `pub async fn migrate(pool: &DbPool) -> Result<(), sqlx::Error>` backed by `sqlx::migrate!("./migrations")`.
- Existing tables and seed rows remain available through the same repository functions.

- [ ] **Step 1: Capture the current schema in a migration fixture**

Create `0001_initial.sql` with users, sessions, proxy_hosts, certificates, acme_certificates, audit_logs, roles, permissions, role_permissions, and the scope index. Use portable `INTEGER`, `VARCHAR/TEXT`, `BIGINT` where needed, nullable foreign keys, and no `PRAGMA`, `AUTOINCREMENT`, or SQLite-only functions.

- [ ] **Step 2: Add the additive upgrade migration**

Create `0002_add_disabled_and_secret_ref.sql` so new installations and existing databases both end with `users.disabled` and `acme_certificates.secret_ref`. The migration must use portable conditional handling supported by SQLx's migration path; if conditional `ADD COLUMN` is not portable, split vendor-specific migration files and document the reason in the migration header.

- [ ] **Step 3: Write migration tests**

Add a test that creates a fresh SQLite pool, runs `migrate`, asserts the `_sqlx_migrations` rows and the ten permission seeds, then runs `migrate` a second time and asserts no duplicate roles or permissions. Add a legacy SQLite fixture test that creates the pre-Phase-5 schema, inserts representative users/roles/scopes/audit data, runs `migrate`, and verifies all records remain.

- [ ] **Step 4: Implement SQLx migrator and portable seed logic**

Replace the inline `CREATE TABLE`, `ALTER TABLE`, and seed loop with `sqlx::migrate!("./migrations").run(pool).await`. Seed built-in permissions and roles using `INSERT ... SELECT ... WHERE NOT EXISTS` statements, and populate role-permission rows with the same pattern so reruns are idempotent on all three vendors.

- [ ] **Step 5: Run migration tests**

Run `cargo test --locked control_plane_repository::migrations -- --nocapture`. Expected: fresh and legacy upgrade tests pass.

- [ ] **Step 6: Commit**

```bash
git add migrations src/control_plane/repository.rs tests/control_plane_repository.rs
git commit -m "feat: add portable control-plane migrations"
```

### Task 3: Port repository queries and transactions to `AnyPool`

**Files:**
- Modify: `src/control_plane/repository.rs`
- Modify: `src/control_plane/rbac.rs`
- Modify: `src/control_plane/audit.rs`
- Modify: `src/certificates/acme_service.rs`
- Modify: all tests importing `sqlx::SqlitePool`

**Interfaces:**
- Every repository, RBAC, audit, and certificate service function accepts `&DbPool` or stores `DbPool`.
- Return models and error behavior remain unchanged.

- [ ] **Step 1: Inventory non-portable SQL**

Run `rg -n "INSERT OR IGNORE|RETURNING|datetime\(|PRAGMA|SqlitePool|SqliteRow|SqliteConnectOptions" src tests` and record each occurrence in the task checklist before editing.

- [ ] **Step 2: Replace SQLite-specific pool and row types**

Use `DbPool`, `sqlx::AnyRow`, and `AnyPool::begin()` throughout the control plane. Keep bind placeholders as `?`, which SQLx translates for the selected driver.

- [ ] **Step 3: Replace generated-ID queries**

For inserts currently using `RETURNING`, execute the insert, then query the row by its unique natural key (email, domain, certificate name, or role slug) inside the same transaction where atomicity matters. Preserve the current `Option` and `RowNotFound` semantics.

- [ ] **Step 4: Replace conflict and time expressions**

Use `INSERT ... SELECT ... WHERE NOT EXISTS` for seeds and application-level duplicate checks for unique resources. Bind RFC3339 timestamps from Rust instead of calling SQLite `datetime('now')`; preserve newest-first audit ordering by the stored timestamp and ID.

- [ ] **Step 5: Preserve transaction guarantees**

Keep setup-account locking safe on SQLite and use the selected database's transaction semantics for PostgreSQL/MySQL. If `BEGIN IMMEDIATE` cannot be expressed portably, add a `DbPool` vendor helper that uses a PostgreSQL/MySQL transaction plus a unique sentinel row to serialize first-admin creation, with a regression test for concurrent setup attempts.

- [ ] **Step 6: Run the full SQLite suite**

Run `cargo test --locked` and `cargo fmt --check`. Expected: all existing tests pass without API behavior changes.

- [ ] **Step 7: Commit**

```bash
git add src tests
git commit -m "refactor: make control-plane repository database agnostic"
```

### Task 4: Add external database integration harness

**Files:**
- Create: `tests/external_database.rs`
- Modify: `tests/support/mod.rs`
- Modify: `DEVELOPMENT.md`

**Interfaces:**
- `DATABASE_URL_EXTERNAL` selects an external database; when absent, tests skip with an explicit message.
- The harness runs the same migration and RBAC seed assertions used by SQLite.

- [ ] **Step 1: Write opt-in integration tests**

Add tests that read `DATABASE_URL_EXTERNAL`, connect with `repository::connect`, run `migrate`, verify all ten permissions and three built-in roles, create/read a user, and drop the pool. Do not print the URL; on failure print only the scheme and host.

- [ ] **Step 2: Add test commands**

Document these commands:

```bash
DATABASE_URL_EXTERNAL=postgres://bearust:bearust@127.0.0.1:5432/bearust cargo test --locked --test external_database
DATABASE_URL_EXTERNAL=mysql://bearust:bearust@127.0.0.1:3306/bearust cargo test --locked --test external_database
```

- [ ] **Step 3: Commit**

```bash
git add tests/external_database.rs tests/support/mod.rs DEVELOPMENT.md
git commit -m "test: add external database integration harness"
```

### Task 5: Add Docker Compose profiles and deployment documentation

**Files:**
- Modify: `docker-compose.yml`
- Modify: `docker-compose.dev.yml`
- Modify: `.env.example` if present, otherwise create `.env.example`
- Modify: `DEPLOY.md`
- Modify: `README.md`

**Interfaces:**
- Default Compose startup continues using the bundled SQLite volume.
- `postgres` and `mysql` profiles provide service names, health checks, persistent volumes, and environment-driven credentials.

- [ ] **Step 1: Add PostgreSQL and MySQL profiles**

Define `postgres` and `mysql` services with profiles, health checks, named volumes, and credentials read from environment variables. Do not expose credentials in committed YAML values beyond documented development defaults.

- [ ] **Step 2: Wire application profile examples**

Document `DATABASE_URL=postgres://...@postgres:5432/...` and `DATABASE_URL=mysql://...@mysql:3306/...`, and make the application depend on the selected database health check when that profile is enabled.

- [ ] **Step 3: Document migration and upgrade behavior**

Explain that migrations run at startup, data lives in the database volume, and changing database backends requires an explicit export/import procedure outside Phase 5. Include password-redaction guidance for logs and support bundles.

- [ ] **Step 4: Verify Compose configuration**

Run `docker compose config`, `docker compose --profile postgres config`, and `docker compose --profile mysql config`. Expected: all commands exit successfully and show no unresolved variables for documented example files.

- [ ] **Step 5: Commit**

```bash
git add docker-compose.yml docker-compose.dev.yml .env.example DEPLOY.md README.md
git commit -m "docs: add external database compose profiles"
```

### Task 6: Final compatibility verification and Phase 5 documentation

**Files:**
- Modify: `docs/PRD.md`
- Modify: `README.md`
- Modify: `DEVELOPMENT.md`
- Test: `tests/control_plane_repository.rs`, `tests/external_database.rs`

- [ ] **Step 1: Add the Phase 5 status note**

Document supported drivers, default SQLite behavior, migration guarantees, opt-in external tests, and explicit non-goals under the roadmap section in `docs/PRD.md`.

- [ ] **Step 2: Run required verification**

Run:

```bash
cargo fmt --check
cargo test --locked
cargo clippy --all-targets -- -D warnings
git diff --check
```

Expected: all commands pass. If a Rust toolchain or Docker daemon is unavailable, record the exact command and environment limitation without claiming it passed.

- [ ] **Step 3: Review the final diff**

Run `git diff origin/main...HEAD --stat`, inspect every migration and query change, and verify `rg -n "password|DATABASE_URL"` does not reveal committed secrets.

- [ ] **Step 4: Commit**

```bash
git add docs/PRD.md README.md DEVELOPMENT.md tests
git commit -m "docs: mark phase 5 external databases complete"
```

