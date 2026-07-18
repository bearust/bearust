# ACME certificate automation

BeaRust can issue, activate, inspect, and renew Let's Encrypt certificates from
the authenticated control plane. The issue endpoint returns a job envelope;
certificate metadata and renewal state are available from the status endpoint.
Private keys, account credentials, and Cloudflare tokens are never included in
responses or structured logs.

## Staging-first rollout

1. Create the proxy host and confirm its upstream is healthy.
2. Use the ACME form/API with `environment: staging` and one or more hostnames.
3. For HTTP-01, publish each hostname in public DNS and forward TCP port 80 to
   the proxy. The challenge path is `/.well-known/acme-challenge/<token>` and
   must not be intercepted by another proxy or authentication layer.
4. Check the certificate status and confirm that activation/reload leaves the
   proxy-host configuration serving the new certificate.
5. Only after a successful staging run, repeat with `environment: production`.

HTTP-01 cannot issue wildcard certificates. Use Cloudflare DNS-01 for names
such as `*.example.com`; the `_acme-challenge.example.com` TXT record is
created temporarily and removed after validation, including on failure.

## Cloudflare DNS-01

Create a Cloudflare API token restricted to the target zone with:

- `Zone:DNS:Edit`
- `Zone:Zone:Read`

Do not use a global API key. Enter the token only in the authenticated issue
request. BeaRust stores it under `/data/secrets` with restrictive permissions;
rotate it by issuing the next request with the replacement token. Wildcard and
non-wildcard names may be requested according to the ACME hostname validation
rules.

## Renewal and recovery

Certificates enter the renewal window before expiry and are renewed by the
background scheduler. Operations are serialized per certificate, transient
failures are retried with bounded backoff, and the last-known-good active
certificate remains selected if issuance, validation, or reload fails. A failed
job reports a stable error code in status; retry from the UI/API after fixing
DNS, port 80 reachability, credentials, or CA rate limits.

If activation or reload fails, do not delete the previous certificate material.
Inspect `acme_status`, restore DNS/reachability, and retry. For an emergency
rollback, restore the prior image/configuration and send `SIGHUP`; certificate
activation uses an atomic pointer so a partial write cannot become active.

## Deterministic verification

The repository includes fake-transport tests for HTTP-01 issuance, timeout
cleanup, Cloudflare record ownership/cleanup, renewal persistence, and log
redaction. Run the complete gate from the task plan (Rust tests, frontend build
and tests, both Compose config checks), then run `git diff --check` before a
release. These tests never contact Let's Encrypt or Cloudflare.
