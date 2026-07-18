# Phase 4A — ACME Certificate Automation Design

## Goal

Deliver an end-to-end certificate workflow comparable to Nginx Proxy Manager: users can issue and renew Let's Encrypt certificates through the GUI using HTTP-01 or Cloudflare DNS-01, then attach an issued certificate to a proxy host without restarting the traffic path.

## Scope

### Included

- Let's Encrypt staging and production directory selection.
- HTTP-01 issuance for publicly reachable hostnames.
- DNS-01 issuance through Cloudflare API tokens, including wildcard hostnames.
- Persistent ACME account key and certificate metadata.
- Background renewal with retry/backoff and an expiry threshold of 30 days.
- Control-plane API and GUI wizard for issue, renew, activate, and status.
- Atomic TLS snapshot reload after certificate activation.
- Audit events for issuance, renewal, activation, and failures.
- Unit, contract, and deterministic integration tests without calling a public CA.

### Excluded

- DNS providers other than Cloudflare.
- External database support.
- WAF, analytics, clustering, or AI features.
- Automatic DNS zone discovery beyond the Cloudflare API calls needed for the selected hostname.
- Storing or returning private keys through the frontend after issuance.

## Architecture

The existing `AcmeTransport` abstraction remains the seam for deterministic tests. A production `AcmeClient` implements the Let's Encrypt ACME protocol outside the request path. It persists the account key in the certificate store, creates an order, delegates challenge fulfillment to a solver, polls authorization/order status, finalizes the order, and imports the resulting certificate through `CertificateStore`.

`Http01Solver` uses the existing in-memory challenge store and exact-path lookup in the proxy. `CloudflareDns01Solver` implements the existing `DnsProvider` interface and uses a least-privilege API token. DNS records are presented, propagation is polled, and records are always cleaned up in a finally-style path, including partial failures and timeouts.

The control plane owns orchestration and persistence. Long-running issuance and renewal jobs run in background tasks with bounded timeouts, cancellation-safe cleanup, exponential backoff, and a per-certificate single-flight guard. The data plane only observes the active certificate snapshot; an ACME failure leaves the previously active certificate untouched.

## Persistence and secrets

Certificate metadata records include source (`custom` or `letsencrypt`), environment, challenge method, covered hostnames, expiry, active state, and renewal status. ACME account material and Cloudflare credentials are stored under the data directory with restrictive file permissions and are never serialized into API responses, audit payloads, or logs. The API accepts a Cloudflare token only during the issuance request and returns redacted status thereafter.

## API and GUI

The control plane adds:

- `POST /api/certificates/acme` to start an issuance request.
- `POST /api/certificates/{id}/renew` to request an on-demand renewal.
- `GET /api/certificates/{id}/status` to retrieve redacted lifecycle status.

The request validates hostname syntax, challenge-specific constraints, environment, and body limits before starting work. The GUI wizard lets an authorized operator choose the environment, challenge method, hostnames, and (for Cloudflare DNS-01) token. It displays progress and sanitized errors, refreshes certificate status, and exposes issued certificates in the proxy-host TLS selector.

## Error handling and safety

- Public CA, DNS API, propagation, and parsing errors are classified and exposed as actionable but non-secret messages.
- Every operation has a strict deadline; retries use exponential backoff and stop at the deadline.
- DNS cleanup runs after success, failure, timeout, or cancellation; cleanup failures are logged as warnings without replacing the primary error.
- A failed issuance or renewal never deactivates the current certificate.
- Activation validates certificate/key correspondence before atomically publishing a new TLS snapshot.
- Audit events contain actor, certificate id/name, operation, outcome, and reason category; they exclude tokens, private keys, and challenge values.

## Verification

- Unit tests for hostname validation, directory/environment selection, challenge lifecycle, Cloudflare request construction, token redaction, retry/backoff, and renewal eligibility.
- Contract tests for API authorization, validation, status redaction, and audit records.
- Deterministic ACME integration tests using a fake transport and fake DNS provider; no network calls to Let's Encrypt or Cloudflare.
- Regression gate: `cargo test --locked`, `cargo fmt --all -- --check`, `cargo clippy --locked --all-targets --all-features -- -D warnings`, `npm run build --prefix frontend`, and both Compose config validations.

## Acceptance criteria

1. A staging HTTP-01 request can issue and activate a certificate through the GUI/API.
2. A staging Cloudflare DNS-01 request can issue and activate a wildcard certificate.
3. An active certificate can be attached to a proxy host and reloaded without process restart.
4. Certificates expiring within 30 days are renewed by the background scheduler.
5. Failed issuance, renewal, propagation, and cleanup paths are recoverable and leave the active certificate intact.
6. Cloudflare tokens and private key material are absent from logs, API responses, audit records, and frontend assets.
