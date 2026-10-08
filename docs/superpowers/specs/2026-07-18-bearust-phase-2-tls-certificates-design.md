# Bearust Phase 2 — TLS & Certificate Automation Design

## Goal

Provide an Nginx Proxy Manager-like certificate experience while preserving the
Phase 1 HTTP proxy behavior: operators can use custom certificates, request
and renew Let’s Encrypt certificates, and use DNS providers such as Cloudflare
for DNS-01 challenges.

## Scope

Phase 2 delivers the backend and data-plane foundations for certificate
management. The management GUI workflow is scheduled for Phase 3, but the
certificate service must expose stable internal APIs that the GUI can consume.

In scope:

- Native TLS termination with `rustls` through Pingora.
- Optional TLS configuration; existing HTTP-only configurations remain valid.
- A certificate store for custom and ACME-issued certificates.
- Custom certificate and private-key import through a control-plane API boundary.
- Let’s Encrypt issuance using HTTP-01.
- DNS-01 issuance using a provider abstraction, with Cloudflare as the first
  provider.
- Automatic renewal before expiry, with bounded retries and observable errors.
- Atomic certificate activation and reload without dropping active connections.
- Secure file permissions, redacted errors/logs, and persistent storage under
  the configured data volume.

Out of scope for this phase:

- The full web GUI for uploading certificates or requesting certificates.
- A public DNS-provider marketplace or plugin registry.
- Wildcard certificates through HTTP-01 (wildcards require DNS-01).
- TLS passthrough or generic TCP proxying.

## User-facing configuration

The existing server configuration remains valid:

```toml
[server]
bind = "0.0.0.0:443"

[server.tls]
cert_path = "/etc/bearust/tls/fullchain.pem"
key_path = "/etc/bearust/tls/privkey.pem"
```

`server.tls` is optional. When omitted, Bearust starts the existing plain HTTP
listener. Certificate records used by the control plane contain a stable name,
the covered hostnames, source (`custom` or `letsencrypt`), certificate/key
locations, expiry, and activation state. Secrets such as private keys and DNS
API tokens are never serialized into logs or returned by status endpoints.

## Architecture

### Certificate store

`CertificateStore` owns certificate metadata and the on-disk material. It
validates PEM certificate/key pairs before activation, writes new material to a
temporary file, applies restrictive permissions, then atomically renames it
into place. A failed write or validation leaves the currently active material
untouched.

The store is the only component allowed to resolve certificate material for the
TLS listener. This keeps path handling, permissions, and redaction in one
boundary.

### TLS listener

The server builds Pingora `TlsSettings` from the active certificate store entry.
TLS setup errors fail startup with an actionable, non-secret error. On reload,
the new configuration and certificate pair are fully validated before the
runtime snapshot is swapped; existing connections continue using their current
connection state.

### ACME manager

`AcmeManager` owns account/order/challenge state and runs outside the request
path. It supports:

1. HTTP-01 through a dedicated challenge response path.
2. DNS-01 through a `DnsProvider` trait.

The first provider is Cloudflare, configured with a token and zone lookup. The
provider interface must support create-record, delete-record, and propagation
polling so additional providers can be added without changing ACME orchestration.

Renewal is scheduled before expiry, uses bounded exponential backoff, and keeps
the last known-good certificate active when issuance fails.

### Control-plane boundary

Phase 2 defines service methods for importing, listing, activating, requesting,
and renewing certificates. Phase 3 maps these methods to the GUI. The data
plane consumes only an immutable active-certificate snapshot and never calls a
DNS provider or ACME endpoint while serving traffic.

## Error handling and security

- Reject malformed PEM, mismatched certificate/key pairs, expired custom
  certificates, and paths outside the configured certificate/data roots.
- Never include private-key contents, API tokens, or authorization headers in
  errors or structured logs.
- Use restrictive permissions for private-key files and verify them before
  activation.
- Treat ACME/provider timeouts and propagation failures as recoverable; do not
  replace a valid active certificate with an incomplete order.
- Ensure challenge endpoints cannot proxy arbitrary user paths.
- Make certificate activation atomic and idempotent.

## Testing strategy

- Configuration tests for optional TLS, required fields, invalid paths, and
  unknown keys.
- Certificate-store tests for PEM parsing, key mismatch, permission handling,
  atomic activation, and preservation of the old certificate on failure.
- TLS integration test that connects with a real test certificate and verifies
  the request reaches an upstream.
- ACME orchestration tests using a local deterministic challenge/provider
  harness; no production CA calls in the test suite.
- Cloudflare provider contract tests covering record creation, deletion,
  propagation timeout, and redacted errors.
- Renewal tests covering success, retry/backoff, and last-known-good fallback.
- Existing Phase 1 routing, reload, shutdown, and HTTP tests must remain green.

## Delivery sequence

1. Certificate model/store and secure material handling.
2. Native TLS listener and reload integration.
3. ACME HTTP-01 orchestration.
4. DNS-01 provider interface and Cloudflare implementation.
5. Renewal scheduler, observability, Docker mounts, and operations docs.
6. Phase 3 GUI integration against the stable certificate service API.

