# Phase 4D.2 final review fixes

## Findings addressed

- Successful ACME issue and renewal job acceptance now publish `certificates.changed` after the existing redacted audit record. Failed and denied paths remain audit-only.
- Realtime subscriptions now map `sessions.changed` to a safe `/api/auth/me` refresh. The authenticated dashboard updates the current user when it changes and logs out when the session is unauthorized.

## Verification

- `docker run --rm -e RUSTUP_TOOLCHAIN=1.88.0 -e CARGO_BUILD_JOBS=1 -v "$PWD":/app -w /app rust:1.88-bookworm cargo test --locked --test control_plane_realtime` — 6 passed.
- `cd frontend && npm test -- --run` — 18 passed across 4 files.
- `cd frontend && npm run build` — passed.
- `git diff --check` — passed.
