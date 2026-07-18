# Task 7 report

Implemented the certificate automation UI in the frontend.

- Added typed ACME/certificate APIs for issue, list, status, renew, activate, and host updates.
- Added `AcmeWizard` with staging default, production confirmation, HTTP-01/Cloudflare DNS-01 fields, wildcard validation, local-only token state, busy-state submit lock, and redacted errors.
- Added `CertificateTable` with expiry/source/domain/active/renewal status, manual renew/activate actions, and refresh after changes.
- Extended proxy-host creation with TLS mode and certificate selector.
- Added responsive certificate cards and form styles.
- Added validation/redaction tests in `frontend/src/acme.test.tsx`.

Verification:

```text
npm test --prefix frontend -- --run  # 3 passed
npm run build --prefix frontend       # passed
```
