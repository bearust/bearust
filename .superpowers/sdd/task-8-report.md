# Task 8 report: Phase 4A acceptance

## Delivered

- Documented staging-first ACME rollout, HTTP-01 port/DNS requirements,
  Cloudflare least-privilege token permissions, wildcard behavior, renewal,
  recovery, atomic activation, and secret-file permissions in `docs/acme.md`.
- Linked the ACME runbook from `README.md` and `DEPLOY.md` and added safe
  control-plane setup-token guidance to `.env.example`.
- The deterministic fake-transport coverage already present in
  `tests/acme_http01.rs` and `tests/acme_dns01.rs` exercises issuance,
  activation, timeout cleanup, record ownership, and redaction without
  contacting either CA or Cloudflare. The certificate lifecycle and repository
  tests cover durable status/renewal transitions; these are the release gate
  harness for this phase.

## Verification

- `git diff --check`: passed.
- Full Rust/frontend/Compose verification is run by the parent implementation
  agent because shared Phase 4A source changes are still in the worktree. The
  exact commands are recorded in `task-8-brief.md`.

## Security notes

ACME credentials are accepted through authenticated control-plane requests,
stored below `/data/secrets` with `0700`/`0600` permissions, and excluded from
responses and structured logs. HTTP-01 is explicitly staging-first and
wildcards are directed to DNS-01.
