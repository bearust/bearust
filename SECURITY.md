# Security policy

## Supported versions

Only the latest `0.1.x` release line receives security fixes. If you deploy from `main`, keep it updated.

## Reporting a vulnerability

Please **do not** open a public issue, discussion, or pull request for a suspected vulnerability. Instead, use GitHub's private vulnerability reporting: open the repository's **Security** tab and choose **Report a vulnerability**. If private reporting is unavailable, open a minimal public issue that describes only the affected area (no exploit details) and ask for a private contact.

Include in your report:

- Affected component and version/commit
- Steps to reproduce or a minimal proof of concept
- Expected vs. actual behavior and the suspected impact
- Any relevant logs with secrets redacted

## Handling

Reports are reviewed by the maintainers, who will confirm receipt, investigate, and coordinate a fix and disclosure timeline with you. Please allow reasonable time for a fix before any public disclosure, and avoid testing suspected vulnerabilities against deployments you do not own.

## Scope notes

Bearust's threat model assumes the operator keeps the control plane (`:8081`) loopback-only or behind an authenticated boundary, keeps `/data` (sessions, ACME credentials, certificate material) private with the documented file modes, and deploys only reviewed WASM plugins. Reports about deployments that ignore this documented guidance (for example, an internet-exposed unauthenticated dashboard) are still welcome as hardening ideas but may be handled as documentation improvements rather than security fixes.

When sharing any diagnostic output, redact `DATABASE_URL` passwords, `BEARUST_SETUP_TOKEN`, API keys, private keys, and session cookies.
