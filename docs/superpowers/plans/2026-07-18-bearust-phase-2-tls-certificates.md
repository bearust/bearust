# BeaRust Phase 2 TLS & Certificate Automation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Nginx Proxy Manager-like certificate foundations: custom certificates, native TLS, Let’s Encrypt HTTP-01, Cloudflare DNS-01, and safe renewal.

**Architecture:** Keep Phase 1 routing and runtime snapshots unchanged. Add a certificate store as the only owner of certificate material, a TLS adapter that builds Pingora’s TLS settings from an active certificate, and an asynchronous ACME/provider layer outside the request path. Expose service APIs now so the Phase 3 GUI can consume them later.

**Tech Stack:** Rust 1.84+, Pingora 0.8.1, rustls, Tokio, serde/TOML, reqwest, `instant-acme`, Cloudflare REST API, tempfile/rcgen for tests.

## Global Constraints

- `server.tls` is optional; configurations without it retain Phase 1 HTTP behavior.
- No private-key contents, DNS tokens, or authorization headers may enter logs/errors/status responses.
- Certificate activation is atomic; failed validation or issuance preserves the last-known-good certificate.
- ACME and DNS operations never execute on the traffic path.
- Certificate material is stored below configured data/certificate roots with restrictive private-key permissions.
- Every production behavior is preceded by a failing test and verified in the Rust 1.84.1 Docker toolchain.
- Existing routing, reload, shutdown, observability, and Docker acceptance tests remain green.

---

### Task 1: Add the TLS configuration model and validation

**Files:**
- Modify: `src/config/mod.rs`
- Modify: `src/config/error.rs` if a dedicated certificate validation error is needed
- Modify: `config/bearust.example.toml`
- Test: `tests/config_validation.rs`

**Interfaces:**
- Produces `ServerConfig.tls: Option<TlsConfig>` with `cert_path: PathBuf` and `key_path: PathBuf`.
- Produces validation errors for missing or empty certificate/key paths; certificate-root containment is enforced by `CertificateStore` in Task 2.

- [ ] **Step 1: Write failing parsing tests** for an accepted optional `[server.tls]` block, rejection of one-sided blocks, empty paths, and unknown TLS keys.
- [ ] **Step 2: Run the focused tests** with `docker run --rm -v "$PWD":/work -w /work rust:1.84.1-bookworm cargo test --test config_validation tls` and confirm failure because `TlsConfig` is absent.
- [ ] **Step 3: Implement the serde model and minimal validation** while preserving equality/debug derives and HTTP-only defaults.
- [ ] **Step 4: Re-run focused tests** and then the complete configuration test target.
- [ ] **Step 5: Update the example TOML** with a commented manual TLS block.
- [ ] **Step 6: Commit** `feat: add optional tls configuration`.

### Task 2: Implement secure certificate material parsing and atomic storage

**Files:**
- Create: `src/certificates/mod.rs`
- Modify: `src/lib.rs`
- Modify: `Cargo.toml`
- Test: `tests/certificates.rs`

**Interfaces:**
- `CertificateStore::import_custom(name, cert_pem, key_pem) -> Result<CertificateRecord, CertificateError>`.
- `CertificateStore::activate(name) -> Result<ActiveCertificate, CertificateError>`.
- `CertificateStore::active() -> Option<ActiveCertificate>`.
- `CertificateRecord` includes name, source, covered hostnames, expiry, and material paths but never secret contents.

- [ ] **Step 1: Add failing tests** for valid PEM import, mismatched key rejection, malformed PEM rejection, restrictive key permissions on Unix, and preserving the old active material after a failed replacement.
- [ ] **Step 2: Run `tests/certificates.rs`** and confirm failures are caused by missing store types/behavior.
- [ ] **Step 3: Add the smallest compatible PEM/X.509 dependencies** and implement parsing plus certificate/key correspondence checks.
- [ ] **Step 4: Implement temp-file write, permission application, fsync/rename activation, and metadata persistence under a caller-provided root.
- [ ] **Step 5: Re-run focused tests and inspect error strings** to ensure no PEM/key/token material appears.
- [ ] **Step 6: Commit** `feat: add secure certificate store`.

### Task 3: Wire native Pingora TLS into startup

**Files:**
- Create: `src/tls.rs`
- Modify: `src/cli.rs`
- Modify: `Cargo.toml`
- Test: `tests/tls_listener.rs`

**Interfaces:**
- `tls::settings(config: &TlsConfig) -> Result<TlsSettings, TlsError>`.
- `cli::serve_proxy` creates a TLS listener when `server.tls` exists and the existing TCP listener otherwise.

- [ ] **Step 1: Write a failing integration test** that starts BeaRust with a generated test certificate, performs an HTTPS request to a local upstream, and asserts the upstream response is returned.
- [ ] **Step 2: Run the test** in Rust 1.84.1 Docker and confirm failure because the server currently accepts plaintext only.
- [ ] **Step 3: Implement `tls::settings`** using Pingora 0.8.1’s native TLS/rustls service API, loading the certificate chain and private key through the certificate store boundary.
- [ ] **Step 4: Select the TLS service/listener based on `server.tls`** without changing route resolution or upstream behavior.
- [ ] **Step 5: Re-run HTTPS and existing HTTP integration tests**; correct protocol-specific errors without exposing key material.
- [ ] **Step 6: Commit** `feat: add native tls listener`.

### Task 4: Make TLS certificate reload atomic

**Files:**
- Modify: `src/reload.rs`
- Modify: `src/runtime.rs`
- Modify: `src/tls.rs`
- Test: `tests/reload.rs`
- Test: `tests/tls_listener.rs`

**Interfaces:**
- Reload preparation returns a fully validated immutable TLS/certificate snapshot.
- A failed certificate reload leaves the previous snapshot and listener state active.

- [ ] **Step 1: Add failing reload tests** for valid certificate replacement, invalid replacement fallback, and unchanged HTTP reload behavior.
- [ ] **Step 2: Run the focused reload tests** and confirm they fail before snapshot integration exists.
- [ ] **Step 3: Extend the reload transaction** so config and TLS material validate before the ArcSwap/runtime update.
- [ ] **Step 4: Keep active connections alive** while new connections use the new certificate, following Pingora’s supported service reload mechanism.
- [ ] **Step 5: Verify SIGHUP behavior** with the existing supervised-process tests.
- [ ] **Step 6: Commit** `feat: reload tls certificates atomically`.

### Task 5: Add ACME HTTP-01 orchestration

**Files:**
- Create: `src/acme/mod.rs`
- Create: `src/acme/http01.rs`
- Modify: `src/lib.rs`
- Modify: `Cargo.toml`
- Test: `tests/acme_http01.rs`

**Interfaces:**
- `AcmeManager::request_http01(certificate_request) -> Result<CertificateRecord, AcmeError>`.
- `Http01Store::put(token, key_authorization)` and `Http01Store::get(token)`.
- Challenge handling is explicit and cannot proxy arbitrary paths.

- [ ] **Step 1: Write failing local-harness tests** for challenge token retrieval, successful order/finalization, timeout, and preservation of the active certificate after failure.
- [ ] **Step 2: Run the tests** and confirm failure because the ACME manager is absent.
- [ ] **Step 3: Implement the HTTP-01 challenge store and dedicated request handling** with strict token validation and bounded lifetime.
- [ ] **Step 4: Implement the ACME client flow** against an injectable directory/transport so tests never call a production CA.
- [ ] **Step 5: Add structured events** for request/start/success/failure with redacted identifiers.
- [ ] **Step 6: Commit** `feat: add acme http01 issuance`.

### Task 6: Add DNS provider abstraction and Cloudflare DNS-01

**Files:**
- Create: `src/acme/dns.rs`
- Create: `src/acme/cloudflare.rs`
- Modify: `src/acme/mod.rs`
- Modify: `Cargo.toml`
- Test: `tests/cloudflare_dns.rs`

**Interfaces:**
- `trait DnsProvider { async fn present(&self, record: TxtRecord) -> Result<()>; async fn cleanup(&self, record: TxtRecord) -> Result<()>; async fn wait_for_propagation(&self, record: TxtRecord) -> Result<()>; }`.
- `CloudflareProvider` uses scoped API tokens, zone lookup, record create/delete, and redacted error mapping.

- [ ] **Step 1: Write failing contract tests** using a local HTTP server for zone lookup, record creation/deletion, non-2xx responses, and propagation timeout.
- [ ] **Step 2: Run the focused tests** and confirm failure before the provider implementation exists.
- [ ] **Step 3: Implement the provider trait and Cloudflare REST client** with request timeouts, no token logging, and idempotent cleanup.
- [ ] **Step 4: Connect DNS-01 orchestration** to the provider interface and support wildcard names.
- [ ] **Step 5: Re-run contract and ACME tests** with deterministic fake DNS responses.
- [ ] **Step 6: Commit** `feat: add cloudflare dns01 provider`.

### Task 7: Add renewal scheduling and operational persistence

**Files:**
- Create: `src/certificates/renewal.rs`
- Modify: `src/certificates/mod.rs`
- Modify: `src/cli.rs`
- Modify: `docker-compose.yml`
- Modify: `docker-compose.dev.yml`
- Modify: `DEPLOY.md`
- Modify: `README.md`
- Test: `tests/certificate_renewal.rs`

**Interfaces:**
- `RenewalScheduler::next_due(record, now) -> Instant`.
- `RenewalScheduler::run_once(now) -> RenewalOutcome`.

- [ ] **Step 1: Write failing scheduler tests** for renewal window, success activation, bounded retry/backoff, and last-known-good fallback.
- [ ] **Step 2: Run focused tests** and confirm failure before scheduler logic exists.
- [ ] **Step 3: Implement a Tokio task** that runs outside request handling, persists metadata, and reloads the active certificate after successful issuance.
- [ ] **Step 4: Add Docker mounts and non-root directory permissions** for `/data` and `/etc/bearust/tls`.
- [ ] **Step 5: Document custom certificates, Cloudflare token scope, HTTP-01/DNS-01 prerequisites, renewal behavior, and secret handling.
- [ ] **Step 6: Commit** `feat: schedule certificate renewal`.

### Task 8: Full verification and Phase 2 acceptance

**Files:**
- Modify: `scripts/smoke-test.sh`
- Create: `tests/fixtures/tls/README.md`
- Create: `docs/superpowers/task-11-report.md`

- [ ] **Step 1: Add smoke coverage** for plaintext compatibility, HTTPS proxying, invalid certificate startup, and certificate reload.
- [ ] **Step 2: Run formatting, clippy, unit/integration tests, and Docker Compose config/build checks** using Rust 1.84.1.
- [ ] **Step 3: Run the smoke suite twice**: once with no TLS block and once with a generated test certificate.
- [ ] **Step 4: Review logs for secret leakage** and verify production image runs as non-root with writable certificate/data volumes only.
- [ ] **Step 5: Write the acceptance report** with exact commands/results and disclose any environment limitations.
- [ ] **Step 6: Commit** `test: verify phase 2 tls acceptance`.
