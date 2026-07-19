# Task 2 review fixes

## Changes

- Added challenge-mode selection to `AcmeTransport`; the manager explicitly
  requests HTTP-01 or DNS-01, avoiding wildcard/SAN orders silently selecting
  the wrong challenge type.
- Added internal per-authorization challenge metadata to the production
  client. Each hostname now retains its own token and key authorization; the
  public `AcmeOrder` remains source-compatible and only exposes its first
  challenge for backwards compatibility.
- DNS-01 issuance now accepts multi-SAN requests and computes one TXT value per
  authorization. HTTP-01 stores the matching token/key authorization for every
  hostname.
- CSR generation already includes a `subjectAltName` extension for every
  requested hostname; metadata is released after successful finalization.
- Secret-store roots reject symlinks, and JSON-looking persisted credentials
  that cannot deserialize are rejected rather than triggering account creation.
- Transport polling/finalization operations remain bounded by the client
  operation deadline, including challenge readiness and certificate polling.

## Verification

Executed with Rust 1.88 in Docker:

```text
cargo test --locked --test acme_client --test acme_http01
7 acme_http01 tests passed
4 acme_client tests passed
```

The legacy direct `new_order` API still rejects multi-host requests for
compatibility with existing callers; the manager uses the new explicit
`new_order_for_challenge` path for production HTTP/DNS issuance.

## Concerns

The existing public `AcmeOrder` shape cannot expose a vector without breaking
downstream struct literals. Per-authorization data therefore stays private to
the production transport and is accessed through the new trait hook. Custom
transports that do not override the hook retain the legacy single-value
fallback and should override it before accepting SAN orders.
