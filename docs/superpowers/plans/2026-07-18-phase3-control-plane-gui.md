# Phase 3 Control Plane and GUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a first-run-secured, RBAC-protected management plane with SQLite persistence, Proxy Host and custom certificate APIs, and a React/Vite/Tailwind GUI.

**Architecture:** An Axum control-plane server owns authentication, authorization, SQLite repositories, audit events, and desired-state mutations. Existing `CertificateStore` validates and atomically activates certificate material; a reload adapter applies validated desired state to the Pingora data plane and reports failures without replacing the active snapshot. A Vite React SPA consumes the API with an HTTP-only session cookie.

**Tech Stack:** Rust 1.84+, Axum 0.8, Tokio, SQLx 0.8 SQLite, Argon2id (`argon2`), Serde, React, Vite, TypeScript, Tailwind CSS, Vitest, Playwright or a documented browser smoke script.

## Global Constraints

- Use Rust edition 2021 and `rust-version = "1.84"`.
- Keep certificate private keys inside `CertificateStore`; API responses contain metadata only.
- Enforce permissions in the API; GUI visibility is not a security boundary.
- First-run initialization is one-time and requires `BEARUST_SETUP_TOKEN` or the documented generated startup token.
- Passwords use Argon2id; session cookies are `HttpOnly`, `Secure`, and `SameSite=Lax`.
- Failed data-plane reloads preserve the currently active configuration.
- Every sensitive mutation writes a redacted audit event.
- Do not add custom roles, invitations, realtime updates, ACME issuance UI, clustering, or WAF screens in this slice.
- Every task follows test-first development and ends with a focused verification command and commit.

---

## File Map

- Create `src/control_plane/mod.rs`: server state, router construction, and shared application services.
- Create `src/control_plane/auth.rs`: Argon2id hashing, session issuance/revocation, auth extractors.
- Create `src/control_plane/rbac.rs`: built-in roles, permission constants, and authorization checks.
- Create `src/control_plane/setup.rs`: setup status and one-time admin initialization.
- Create `src/control_plane/models.rs`: API/domain DTOs and persistence structs.
- Create `src/control_plane/repository.rs`: SQLite migrations and repositories.
- Create `src/control_plane/proxy_hosts.rs`: Proxy Host handlers and validation.
- Create `src/control_plane/certificates.rs`: multipart upload/activation handlers.
- Create `src/control_plane/audit.rs`: redacted audit event writer.
- Modify `src/lib.rs`, `src/cli.rs`, `src/config/mod.rs`, and runtime startup wiring to expose and launch the control plane.
- Create `tests/control_plane_auth.rs`, `tests/control_plane_proxy_hosts.rs`, `tests/control_plane_certificates.rs`, and `tests/control_plane_reload.rs`.
- Create `frontend/package.json`, `frontend/tsconfig.json`, `frontend/vite.config.ts`, `frontend/src/*`, and `frontend/tests/*` for the SPA.
- Modify `Dockerfile`, `Dockerfile.dev`, compose files, and `README.md` with frontend build/runtime and setup-token instructions.

## Interfaces

The control-plane router is constructed by:

```rust
pub fn router(state: AppState) -> axum::Router;
```

Shared state is:

```rust
#[derive(Clone)]
pub struct AppState {
    pub db: SqlitePool,
    pub certificates: Arc<CertificateStore>,
    pub reloader: Arc<dyn ConfigReloader>,
    pub setup_token: Arc<str>,
}
```

The reload seam is:

```rust
#[async_trait]
pub trait ConfigReloader: Send + Sync {
    async fn apply(&self, desired: DesiredConfig) -> Result<(), ReloadError>;
}
```

---

### Task 1: Control-plane dependencies, migrations, and server seam

**Files:**
- Modify: `Cargo.toml`, `Cargo.lock`
- Create: `src/control_plane/mod.rs`, `src/control_plane/models.rs`, `src/control_plane/repository.rs`
- Modify: `src/lib.rs`
- Test: `tests/control_plane_repository.rs`

**Interfaces:**
- Produces `AppState`, `router`, `DesiredConfig`, and SQLite migration/bootstrap functions consumed by Tasks 2–8.

- [ ] **Step 1: Write failing repository tests** for an in-memory SQLite pool, migration creation, and a transaction that inserts and reads a user and proxy host.
- [ ] **Step 2: Run `cargo test --locked --test control_plane_repository`** and verify it fails because the control-plane modules and migrations do not exist.
- [ ] **Step 3: Add Axum, SQLx SQLite, Argon2, and multipart dependencies; implement migrations for `users`, `sessions`, `proxy_hosts`, `certificates`, and `audit_logs` with foreign keys and timestamps.
- [ ] **Step 4: Implement `AppState`, repository helpers, DTO structs, and an empty `router` that exposes `/api/health`.
- [ ] **Step 5: Run `cargo fmt --check` and `cargo test --locked --test control_plane_repository`; expect all repository tests to pass.
- [ ] **Step 6: Commit with `git add Cargo.toml Cargo.lock src/control_plane src/lib.rs tests/control_plane_repository.rs && git commit -m "feat: add control plane persistence foundation"`.

### Task 2: RBAC, password hashing, sessions, and first-run setup

**Files:**
- Create: `src/control_plane/rbac.rs`, `src/control_plane/auth.rs`, `src/control_plane/setup.rs`, `src/control_plane/audit.rs`
- Modify: `src/control_plane/mod.rs`, `src/control_plane/repository.rs`
- Test: `tests/control_plane_auth.rs`

**Interfaces:**
- Produces `Role`, `Permission`, `require_permission`, `POST /api/auth/login`, `POST /api/auth/logout`, `GET /api/auth/me`, `GET /api/setup/status`, and `POST /api/setup/initialize`.

- [ ] **Step 1: Write tests** for the permission matrix, Argon2id hash verification, invalid setup token, successful first admin creation, concurrent initialization, login cookie attributes, logout revocation, and expired sessions.
- [ ] **Step 2: Run `cargo test --locked --test control_plane_auth`; expect failures for missing handlers and auth services.
- [ ] **Step 3: Implement built-in roles and permission mapping exactly as specified in the design; reject unknown roles and permissions.
- [ ] **Step 4: Implement Argon2id hashing and verification with a random salt; never log passwords or raw session tokens.
- [ ] **Step 5: Implement setup initialization in a transaction with a setup-token comparison and an empty-users guard; return a generic conflict after setup completes.
- [ ] **Step 6: Implement server-side sessions storing only a token hash, secure cookie creation, revocation, expiry checks, and the `CurrentUser` extractor.
- [ ] **Step 7: Add audit writes for setup, login success/failure, logout, and authorization failures with redacted details.
- [ ] **Step 8: Run the focused test, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`; expect PASS.
- [ ] **Step 9: Commit with `git add src/control_plane tests/control_plane_auth.rs && git commit -m "feat: add first-run setup authentication and rbac"`.

### Task 3: Proxy Host CRUD and desired-state reload

**Files:**
- Create: `src/control_plane/proxy_hosts.rs`
- Modify: `src/control_plane/models.rs`, `src/control_plane/repository.rs`, `src/control_plane/mod.rs`
- Test: `tests/control_plane_proxy_hosts.rs`, `tests/control_plane_reload.rs`

**Interfaces:**
- Produces `GET/POST /api/proxy-hosts`, `GET/PATCH/DELETE /api/proxy-hosts/:id`, and `ConfigReloader` integration.

- [ ] **Step 1: Write API tests** for viewer read access, viewer mutation denial, operator mutation access, admin access, domain/port validation, duplicate domain rejection, and not-found handling.
- [ ] **Step 2: Write reload tests** using a fake `ConfigReloader` that succeeds and fails; assert a failed reload returns an error and leaves the previous desired/active record unchanged.
- [ ] **Step 3: Run `cargo test --locked --test control_plane_proxy_hosts --test control_plane_reload` and verify both tests fail.
- [ ] **Step 4: Implement DTO validation for non-empty name, normalized domains, valid host, port range `1..=65535`, supported TLS modes, and certificate reference compatibility.
- [ ] **Step 5: Implement repository CRUD in transactions, audit every mutation, build `DesiredConfig`, and invoke the reloader only after persistence validation.
- [ ] **Step 6: Implement list/get response redaction and stable JSON error envelopes (`code`, `message`, optional `field_errors`).
- [ ] **Step 7: Run focused tests, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`; expect PASS.
- [ ] **Step 8: Commit with `git add src/control_plane tests/control_plane_proxy_hosts.rs tests/control_plane_reload.rs && git commit -m "feat: add rbac protected proxy host api"`.

### Task 4: Custom certificate upload and activation API

**Files:**
- Create: `src/control_plane/certificates.rs`
- Modify: `src/control_plane/models.rs`, `src/control_plane/mod.rs`
- Test: `tests/control_plane_certificates.rs`

**Interfaces:**
- Produces `GET/POST /api/certificates`, `GET /api/certificates/:id`, and `POST /api/certificates/:id/activate`.

- [ ] **Step 1: Write tests** for valid multipart PEM/key upload, invalid PEM, mismatched key, expired certificate, oversized upload, viewer denial, operator success, metadata-only responses, and activation audit events.
- [ ] **Step 2: Run `cargo test --locked --test control_plane_certificates`; expect failures.
- [ ] **Step 3: Implement bounded multipart parsing into memory-limited temporary files; reject unknown fields and missing `name`, `certificate`, or `key` parts.
- [ ] **Step 4: Call `CertificateStore` import/activation APIs, persist only metadata/path references, and remove database rows if staging/activation fails.
- [ ] **Step 5: Implement certificate listing/get responses without private key contents and wire activation to Proxy Host TLS selection plus reload.
- [ ] **Step 6: Run focused tests, `cargo fmt --check`, and `cargo clippy --all-targets --all-features -- -D warnings`; expect PASS.
- [ ] **Step 7: Commit with `git add src/control_plane tests/control_plane_certificates.rs && git commit -m "feat: add custom certificate management api"`.

### Task 5: Runtime integration and configuration persistence

**Files:**
- Modify: `src/cli.rs`, `src/config/mod.rs`, `src/runtime.rs`, `src/control_plane/mod.rs`
- Modify: `config/bearust.example.toml`, `docker-compose.yml`, `docker-compose.dev.yml`
- Test: `tests/control_plane_startup.rs`

**Interfaces:**
- Produces startup wiring that creates the SQLite database, reads `BEARUST_SETUP_TOKEN`, serves the control-plane API, and connects `ConfigReloader` to the existing reload path.

- [ ] **Step 1: Write a startup test** that sets an isolated database path and setup token, starts the control plane, verifies `/api/setup/status`, and shuts it down cleanly.
- [ ] **Step 2: Run `cargo test --locked --test control_plane_startup`; expect failure because CLI/runtime do not create the control plane.
- [ ] **Step 3: Add explicit config fields for control-plane bind address, SQLite path, and setup-token source with safe defaults documented in the example TOML.
- [ ] **Step 4: Wire migrations and `AppState` into runtime startup; bind the API listener without changing the existing traffic listener.
- [ ] **Step 5: Mount the database and certificate store in both compose files, pass the setup token environment variable, and preserve non-root runtime permissions.
- [ ] **Step 6: Run the startup test, both `docker compose config` commands, and `cargo fmt --check`; expect PASS.
- [ ] **Step 7: Commit with `git add src/cli.rs src/config src/runtime.rs src/control_plane config docker-compose.yml docker-compose.dev.yml tests/control_plane_startup.rs && git commit -m "feat: wire control plane into runtime"`.

### Task 6: React/Vite/Tailwind management GUI

**Files:**
- Create: `frontend/package.json`, `frontend/package-lock.json`, `frontend/index.html`, `frontend/tsconfig.json`, `frontend/vite.config.ts`, `frontend/tailwind.config.ts`
- Create: `frontend/src/main.tsx`, `frontend/src/App.tsx`, `frontend/src/api.ts`, `frontend/src/auth.ts`, `frontend/src/types.ts`, `frontend/src/components/*`, `frontend/src/pages/*`, `frontend/src/styles.css`
- Test: `frontend/src/**/*.test.tsx`, `frontend/tests/setup-flow.spec.ts`

**Interfaces:**
- Consumes the API endpoints from Tasks 2–5 using same-origin requests with credentials.
- Produces setup, login, dashboard, Proxy Hosts, and Certificates screens with permission-aware actions.

- [ ] **Step 1: Write component tests** for setup redirect, login error, viewer-hidden mutation controls, proxy form validation, certificate upload error, and successful list refresh.
- [ ] **Step 2: Run `npm ci && npm test -- --run`; expect failures because the SPA does not exist.
- [ ] **Step 3: Scaffold Vite React TypeScript and Tailwind with scripts `dev`, `build`, `test`, and `test:e2e`.
- [ ] **Step 4: Implement typed API client with `credentials: "include"`, generic error-envelope handling, setup status, auth, proxy-host, and certificate methods.
- [ ] **Step 5: Implement setup and login pages; route uninitialized users to setup and authenticated users to dashboard.
- [ ] **Step 6: Implement dashboard, Proxy Hosts table/form, and Certificates table/upload form; hide mutation actions from viewers and render expiry/source/active metadata.
- [ ] **Step 7: Add accessible loading, validation, success, and failure states; never render certificate key contents.
- [ ] **Step 8: Run `npm test -- --run` and `npm run build`; expect PASS.
- [ ] **Step 9: Commit with `git add frontend && git commit -m "feat: add management gui"`.

### Task 7: Container packaging, end-to-end smoke tests, and documentation

**Files:**
- Modify: `Dockerfile`, `Dockerfile.dev`, `docker-compose.yml`, `docker-compose.dev.yml`, `README.md`, `DEVELOPMENT.md`, `DEPLOY.md`
- Modify: `scripts/smoke-test.sh`
- Create: `tests/e2e/control_plane_smoke.sh`

**Interfaces:**
- Produces a production image serving the compiled SPA and API, a dev setup with Vite hot reload, and a repeatable setup/login/CRUD/certificate smoke test.

- [ ] **Step 1: Write the shell smoke test** with assertions for setup status, one-time setup rejection, login, viewer mutation denial, admin Proxy Host creation, valid certificate upload, and invalid certificate rejection.
- [ ] **Step 2: Run the smoke script against a local test server and verify it fails before packaging changes.
- [ ] **Step 3: Add a multi-stage frontend build to `Dockerfile`, copy static assets into the runtime image, and serve the SPA fallback from the control plane.
- [ ] **Step 4: Add frontend dev-server service and API proxy configuration to `docker-compose.dev.yml`; mount persistent SQLite/certificate directories.
- [ ] **Step 5: Update deployment docs with first-run token generation, setup URL, role behavior, certificate upload constraints, and backup paths.
- [ ] **Step 6: Run the smoke script, `docker compose config`, `docker compose -f docker-compose.dev.yml config`, `cargo test --locked`, `npm test -- --run`, and `npm run build`; expect PASS.
- [ ] **Step 7: Commit with `git add Dockerfile Dockerfile.dev docker-compose.yml docker-compose.dev.yml README.md DEVELOPMENT.md DEPLOY.md scripts tests/e2e && git commit -m "test: package and document phase 3 control plane"`.

### Task 8: Final verification and review checkpoint

**Files:**
- Modify: only files needed to correct failures discovered by verification.
- Test: complete Rust and frontend test suites plus compose validation.

- [ ] **Step 1: Run `cargo fmt --check`, `cargo clippy --all-targets --all-features -- -D warnings`, and `cargo test --locked`.
- [ ] **Step 2: Run `npm ci`, `npm test -- --run`, and `npm run build` in `frontend`.
- [ ] **Step 3: Run both compose config commands and the container smoke test from a clean temporary data directory.
- [ ] **Step 4: Review the diff for secret leakage, private-key responses, missing permission checks, setup-token reuse, and unbounded uploads.
- [ ] **Step 5: Commit any focused fixes separately and record command output in `.superpowers/sdd/task-8-report.md`.
