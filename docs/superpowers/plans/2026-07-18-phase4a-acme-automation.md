# Phase 4A ACME Certificate Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task with verification checkpoints.

**Goal:** Add a production-ready Let's Encrypt workflow with HTTP-01 and Cloudflare DNS-01 issuance, background renewal, redacted control-plane APIs, and a GUI wizard that can attach certificates to proxy hosts without a restart.

**Architecture:** Keep ACME orchestration outside the Pingora request path. Introduce a production ACME client behind the existing `AcmeTransport` seam, a file-backed secret store for account/provider credentials, and a certificate lifecycle service shared by API and renewal jobs. Extend the existing SQLite metadata and reload boundary atomically; preserve the active certificate whenever an issuance or renewal fails.

**Tech Stack:** Rust 1.88 toolchain, `instant-acme` for ACME protocol, existing `reqwest` Cloudflare client, OpenSSL certificate validation, Axum 0.8, SQLx SQLite, Tokio background tasks, React/Vite frontend.

## Global Constraints

- ACME operations must never run on the traffic/request path.
- Supported CA environments are Let's Encrypt staging and production only.
- Supported challenge methods are HTTP-01 and Cloudflare DNS-01 only.
- Cloudflare tokens, ACME account keys, private keys, and challenge values must not appear in logs, JSON responses, audit records, or frontend assets.
- A failed operation must leave the last-known-good active certificate untouched.
- DNS records must be cleaned up after success, failure, timeout, or cancellation.
- Renewal eligibility is certificates expiring within 30 days; retries use bounded exponential backoff.
- Every task must add deterministic tests and preserve the existing full verification gate.

---

### Task 1: Define ACME request/status models and migration

**Files:**
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/repository.rs`
- Create: `tests/acme_repository.rs`

**Interfaces:**
- Produce `AcmeEnvironment::{Staging, Production}`, `AcmeChallenge::{Http01, CloudflareDns01}`, `AcmeRequest`, and redacted `AcmeStatus` serializable models.
- Produce repository functions `insert_acme_certificate`, `update_acme_status`, `get_acme_status`, and `list_due_acme_certificates`.

- [ ] **Step 1: Write failing migration/repository tests** for a certificate row containing environment, challenge, renewal state, next attempt, and last error category; assert no secret columns or values are returned.
- [ ] **Step 2: Run the focused test** with `cargo test --locked --test acme_repository`; verify it fails because the migration and functions do not exist.
- [ ] **Step 3: Extend `repository::migrate`** with an idempotent `acme_certificates` table keyed to `certificates.id`, storing `environment`, `challenge`, `renewal_state`, `next_renewal_at`, `last_attempt_at`, and `last_error_code`.
- [ ] **Step 4: Add strict model validation**: production/staging are the only environments, HTTP-01 rejects wildcard names, DNS-01 allows wildcard names, hostnames are normalized and deduplicated, and at least one hostname is required.
- [ ] **Step 5: Run the focused test** and commit `feat: add acme certificate lifecycle metadata`.

### Task 2: Add file-backed secret storage and production ACME client

**Files:**
- Create: `src/secrets.rs`
- Modify: `src/lib.rs`
- Create: `src/acme/client.rs`
- Modify: `src/acme/mod.rs`
- Modify: `Cargo.toml`
- Modify: `Cargo.lock`
- Create: `tests/acme_client.rs`

**Interfaces:**
- `SecretStore::open(root: &Path) -> Result<Self, SecretError>`
- `SecretStore::put(name: &str, value: &[u8]) -> Result<(), SecretError>`
- `SecretStore::get(name: &str) -> Result<Option<Vec<u8>>, SecretError>`
- `LetsEncryptClient::new(environment, secrets, http_client) -> Result<Self, AcmeError>` implementing `AcmeTransport`.

- [ ] **Step 1: Write failing tests** for 0600 secret files, path traversal rejection, account-key reuse, staging/production directory selection, and token/key redaction from `Debug`/error strings.
- [ ] **Step 2: Run `cargo test --locked --test acme_client`** and verify failure.
- [ ] **Step 3: Add the pinned `instant-acme` dependency** and implement `LetsEncryptClient` with persisted account key, directory selection, order creation, authorization polling, finalize, certificate download, and strict per-operation timeout.
- [ ] **Step 4: Implement `SecretStore`** with atomic writes, symlink rejection, parent-directory creation, Unix mode 0600, and names limited to `[A-Za-z0-9._-]`.
- [ ] **Step 5: Ensure the ACME client maps CA failures** to stable categories (`directory`, `account`, `authorization`, `finalize`, `timeout`, `transport`) without including response bodies or JWS values.
- [ ] **Step 6: Run focused tests and commit `feat: add persisted acme client and secret store`**.

### Task 3: Harden Cloudflare DNS-01 provider and challenge lifecycle

**Files:**
- Modify: `src/acme/cloudflare.rs`
- Modify: `src/acme/dns.rs`
- Modify: `src/acme/mod.rs`
- Create: `tests/acme_dns01.rs`

**Interfaces:**
- Add `CloudflareProvider::with_secret_store(token_name, secrets, endpoint, ...)` so the token is loaded only inside the provider.
- Add `AcmeManager::request_dns01_with_status(request, provider, status_callback)` while preserving `request_dns01` as a test-friendly wrapper.

- [ ] **Step 1: Write failing tests** for wildcard normalization, least-privilege bearer header construction, record cleanup after partial `present` failure, propagation timeout, and absence of token in tracing fields/errors.
- [ ] **Step 2: Run `cargo test --locked --test acme_dns01`** and verify failure.
- [ ] **Step 3: Refactor Cloudflare HTTP calls** behind an injectable transport so tests use a local fake server and never contact Cloudflare.
- [ ] **Step 4: Track created record IDs per operation** and make cleanup idempotent; never delete a pre-existing TXT record whose value was not created by the current operation.
- [ ] **Step 5: Add status callbacks** for `creating_order`, `presenting_dns`, `waiting_propagation`, `finalizing`, `stored`, and `failed`.
- [ ] **Step 6: Run focused tests and commit `fix: harden cloudflare dns01 lifecycle`**.

### Task 4: Build certificate lifecycle service and renewal wiring

**Files:**
- Create: `src/certificates/acme_service.rs`
- Modify: `src/certificates/mod.rs`
- Modify: `src/certificates/renewal.rs`
- Modify: `src/cli.rs`
- Modify: `src/control_plane/mod.rs`
- Create: `tests/acme_service.rs`

**Interfaces:**
- `AcmeService::issue(&self, actor_id: i64, request: AcmeRequest) -> Result<AcmeStatus, AcmeServiceError>`
- `AcmeService::renew(&self, actor_id: Option<i64>, certificate_id: i64) -> Result<AcmeStatus, AcmeServiceError>`
- `AcmeService::status(&self, certificate_id: i64) -> Result<AcmeStatus, AcmeServiceError>`
- `AcmeService::run_due_renewals(&self) -> Result<(), AcmeServiceError>`

- [ ] **Step 1: Write failing service tests** for single-flight issuance, successful activation, failed issuance preserving the previous active record, 30-day due selection, retry backoff, and audit event categories.
- [ ] **Step 2: Run `cargo test --locked --test acme_service`** and verify failure.
- [ ] **Step 3: Implement the service** around `CertificateStore`, `AcmeManager`, repository metadata, secret store, and the existing `ConfigReloader`; use a per-certificate mutex/map to reject duplicate jobs with a conflict status.
- [ ] **Step 4: Adapt `RenewalIssuer`** to call the service for Let's Encrypt records and make `run_forever` refresh due records from the database rather than relying on one in-memory active record.
- [ ] **Step 5: Start the renewal task from `serve_proxy`** with a 15-minute scan interval and a shutdown watch channel; do not start it for tests using `NoopReloader` unless explicitly injected.
- [ ] **Step 6: Run focused tests and commit `feat: add acme lifecycle service and renewal jobs`**.

### Task 5: Expose authenticated ACME control-plane APIs

**Files:**
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/models.rs`
- Modify: `src/control_plane/repository.rs`
- Modify: `src/control_plane/audit.rs`
- Create: `tests/acme_api.rs`

**Interfaces:**
- Add routes `POST /api/certificates/acme`, `POST /api/certificates/{id}/renew`, and `GET /api/certificates/{id}/status`.
- Require `CertificatesWrite` for issue/renew and `CertificatesRead` for status.

- [ ] **Step 1: Write failing Axum contract tests** for viewer/operator/admin permissions, hostname/challenge validation, body limit, redacted response fields, and audit records.
- [ ] **Step 2: Run `cargo test --locked --test acme_api`** and verify failure.
- [ ] **Step 3: Add `AcmeService` to `AppState`** and wire route handlers that return `202 Accepted` for background jobs, a stable job/certificate ID, and `409` for an already-running operation.
- [ ] **Step 4: Accept Cloudflare token only in the request**, store it through `SecretStore`, overwrite request buffers after use where practical, and never echo it.
- [ ] **Step 5: Add sanitized `ErrorEnvelope` codes** (`invalid_hostname`, `unsupported_challenge`, `acme_busy`, `acme_failed`, `not_found`) and audit every operation outcome.
- [ ] **Step 6: Run focused tests and commit `feat: expose acme certificate api`**.

### Task 6: Connect activation to proxy-host TLS reload

**Files:**
- Modify: `src/control_plane/mod.rs`
- Modify: `src/control_plane/repository.rs`
- Modify: `src/config/mod.rs`
- Modify: `src/reload.rs`
- Create: `tests/acme_activation.rs`

**Interfaces:**
- Add `ConfigReloader::apply_certificate_change(certificate_id: i64) -> Result<(), ReloadError>` or an equivalent atomic snapshot method used by activation.

- [ ] **Step 1: Write failing tests** for attaching an issued certificate to a TLS proxy host, invalid certificate rejection, reload failure rollback, and active certificate preservation.
- [ ] **Step 2: Run `cargo test --locked --test acme_activation`** and verify failure.
- [ ] **Step 3: Make activation validate the certificate/key pair, update repository active state, rebuild the desired config, and atomically apply the TLS snapshot.
- [ ] **Step 4: Roll back both database active state and runtime snapshot on reload failure; record `certificate_activation_failed`.
- [ ] **Step 5: Run focused tests and commit `fix: reload tls snapshots on certificate activation`**.

### Task 7: Add GUI certificate wizard and proxy-host certificate selector

**Files:**
- Modify: `frontend/src/api.ts`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/styles.css`
- Create: `frontend/src/acme.test.tsx`

**Interfaces:**
- Add typed API calls `certificates()`, `issueAcme(request)`, `renewCertificate(id)`, `certificateStatus(id)`, and `activateCertificate(id)`.
- Add `AcmeWizard` and `CertificateTable` components; keep token state local to the wizard and never persist it to `localStorage`.

- [ ] **Step 1: Write failing frontend tests** for HTTP-01 form, Cloudflare-only token field, wildcard validation, sanitized error rendering, status refresh, and certificate selection on a proxy host.
- [ ] **Step 2: Run `npm test --prefix frontend -- --run`** and verify failure.
- [ ] **Step 3: Implement the wizard** with staging as the safe default, explicit production confirmation, challenge-specific fields, domain list editing, and disabled submit while a job is active.
- [ ] **Step 4: Implement certificate list/status cards** showing source, domains, expiry, active state, renewal state, and redacted errors; add manual renew and activate actions by role.
- [ ] **Step 5: Extend proxy-host form** with TLS mode and certificate selector, then refresh hosts after activation.
- [ ] **Step 6: Keep responsive layout and existing brand tokens; run `npm run build --prefix frontend` and commit `feat: add acme certificate wizard`.

### Task 8: Documentation, integration gate, and release notes

**Files:**
- Modify: `README.md`
- Modify: `DEPLOY.md`
- Modify: `.env.example`
- Create: `docs/acme.md`
- Modify: `tests/log_contract.rs` if new lifecycle events require contract entries

- [ ] **Step 1: Document staging-first setup**, HTTP-01 reachability requirements, Cloudflare token permissions (`Zone DNS Edit`), wildcard behavior, secret file permissions, renewal policy, and failure recovery.
- [ ] **Step 2: Add a deterministic end-to-end harness** that boots the control plane with fake ACME and fake Cloudflare transports, issues a certificate, activates it, and verifies the proxy-host config snapshot.
- [ ] **Step 3: Run the complete verification gate:**
  ```bash
  docker run --rm -v "$PWD":/src -w /src rust:1.88-bookworm sh -c '
    apt-get update -qq && apt-get install -y -qq clang lld cmake make pkg-config libssl-dev >/dev/null &&
    RUSTUP_TOOLCHAIN=1.88.0 CARGO_BUILD_JOBS=1 \
    CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=clang \
    RUSTFLAGS="-C link-arg=-fuse-ld=lld" cargo test --locked
  '
  docker run --rm -v "$PWD/frontend":/app -w /app node:22-alpine sh -c 'npm ci && npm run build && npm test -- --run'
  docker compose config
  docker compose -f docker-compose.dev.yml config
  ```
- [ ] **Step 4: Run `git diff --check`, inspect secret redaction manually, and confirm `git status --short` is clean.
- [ ] **Step 5: Commit `docs: document acme certificate automation` and summarize the Phase 4A acceptance evidence.

## Plan self-review

- All design acceptance criteria map to Tasks 1–8.
- No task exposes private keys or Cloudflare tokens through a public interface.
- Production ACME and Cloudflare calls are isolated behind injectable boundaries for tests.
- Existing custom certificate upload remains supported.
- The plan does not include external databases, WAF, analytics, clustering, AI, or plugin work.
