# Task 5 report — authenticated ACME control-plane APIs

Implemented the authenticated ACME endpoints in `src/control_plane`:

- `POST /api/certificates/acme` (CertificatesWrite, 202 job response)
- `POST /api/certificates/:id/renew` (CertificatesWrite, 202 job response)
- `GET /api/certificates/:id/status` (CertificatesRead)

Requests normalize and validate hostnames, reject unsupported wildcard/http-01 combinations, enforce the existing 3 MiB router body limit, and return sanitized `ErrorEnvelope` codes. Cloudflare tokens are accepted only on the request, persisted in `SecretStore`, passed to the service as bytes, then zeroed where practical. Responses and audit details do not include credentials.

Verification: `git diff --check` passed. Cargo tooling is unavailable on the host; Docker toolchain attempts were unable to complete before the environment timeout. Full compile/test verification remains a parent-agent checkpoint.

Concern for integration: Task 4 has concurrent uncommitted changes in `control_plane/mod.rs`, `acme`, and certificate service files. The route/state edits intentionally preserve those changes; parent should commit the combined diff after resolving the production `AcmeService` wiring (the current default is `NoopAcmeService` for control-plane contract tests).
