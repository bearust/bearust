# Phase 5 — External Database Support Design

## Goal

Add PostgreSQL and MySQL support to the control plane while keeping SQLite the zero-configuration default. Existing authentication, RBAC, audit, certificate, proxy-host, and realtime behavior must remain unchanged.

## Scope

Phase 5 includes:

- A database-neutral pool and repository boundary using SQLx `AnyPool`.
- SQLite, PostgreSQL, and MySQL driver features and connection URL validation.
- Versioned migration files that can be applied idempotently on startup.
- Portable schema and query syntax for all control-plane operations.
- Docker Compose profiles and documentation for PostgreSQL and MySQL.
- Integration coverage for SQLite plus opt-in external-database test runs.

Phase 5 does not include database clustering, cross-node replication, online migration orchestration, backup automation, or changing the default SQLite deployment.

## Architecture

`control_plane::repository` owns connection setup and migration execution. It exposes `AnyPool` to the control plane; handlers and services do not select a database vendor. Database-specific behavior is limited to connection options and migration SQL where the three engines cannot share syntax.

The application selects the database from `DATABASE_URL` (or the existing configured control database value). SQLite remains the default when no external URL is configured. Startup creates the parent directory for file-backed SQLite, connects with a bounded pool, and runs all migrations before serving requests. A failed connection or migration is fatal and returns a safe error without exposing credentials.

## Schema and migrations

The current inline schema is moved into ordered migration files under `migrations/`. The schema uses portable types and constraints:

- integer primary keys and text timestamps remain compatible across vendors;
- boolean flags are represented through values SQLx can decode consistently;
- foreign keys and indexes are declared in migrations;
- seed permissions and built-in roles use portable inserts and conflict handling;
- the existing additive `disabled` and `secret_ref` upgrades become explicit migrations.

Migration execution is tracked by SQLx's migrator table. Applying migrations repeatedly must be safe, and an existing SQLite database must upgrade without data loss.

## Query portability

Repository queries use SQLx bind parameters and portable SQL. Vendor-specific constructs (`INSERT OR IGNORE`, SQLite `datetime()`, `RETURNING`, and `PRAGMA`) are replaced with portable alternatives or small repository helpers. Inserted IDs use a follow-up lookup or SQLx-compatible approach rather than relying on one vendor's `RETURNING` syntax. Transactions retain the same atomicity guarantees for setup, role-scope replacement, and certificate state changes.

## Configuration and deployment

Accepted URLs:

- `sqlite:///data/bearust.db` (default/container path)
- `postgres://user:password@host:5432/database`
- `mysql://user:password@host:3306/database`

The production Compose file keeps the application service unchanged by default and exposes `postgres` and `mysql` services behind profiles. Development examples document how to start one external database and point `DATABASE_URL` at its service name. Secrets remain environment-driven and are not committed.

## Error handling and compatibility

- Unsupported schemes fail during startup with an actionable configuration error.
- Connection, migration, and query errors are logged in structured form without logging the full URL or password.
- Existing API responses, role semantics, audit redaction, and realtime invalidation events remain stable.
- SQLite tests continue to run offline; external integration tests are skipped unless their dedicated environment URL is set.

## Verification criteria

1. `cargo fmt --check`, `cargo test --locked`, and `cargo clippy --all-targets -- -D warnings` pass for the default SQLite path.
2. A fresh database reaches the same schema and built-in RBAC seed state on SQLite, PostgreSQL, and MySQL.
3. An existing SQLite database upgrades through migrations without losing users, sessions, proxy hosts, certificates, roles, scopes, or audit records.
4. Compose profile documentation starts each external database and the application can connect using its service hostname.
5. No credential-bearing database URL appears in API responses, audit details, or structured logs.

## Non-goals and follow-ups

Database-specific performance tuning, read replicas, pooling benchmarks, backup/restore tooling, and multi-node database coordination remain follow-up work. These can be addressed after Phase 5 without changing the repository API.
