# Phase 11 Task 4 Report — Persist Account Locale Preference

## Delivered

- Added a nullable `users.preferred_locale` through migration `0014` and the
  repository's existing backend-neutral, idempotent startup column check.
- Added the strict shared Rust allowlist validator. Only `en`, `id`, and `ja`
  are accepted; empty, unsupported, and oversized values are rejected.
- Included nullable `preferred_locale` in serialized users and `GET /api/auth/me`.
- Added authenticated `PATCH /api/auth/me/preferences`. It accepts a locale or
  `null`, returns the updated sanitized profile, and returns a generic
  `invalid_input`/`Invalid locale` error for invalid input. It does not use or
  change RBAC authorization paths.
- Added the typed frontend request and a `LocalePreferenceProvider` hook. It
  updates the local locale/storage first, then persists to the account without
  propagating persistence failures.
- Added regression coverage for validator boundaries, existing-database
  migration, authenticated account update, API request shape, and fail-soft
  local persistence.

## Red/green evidence

Before implementation:

```text
tests/control_plane_locale.rs: unresolved import
  bearust::control_plane::locale

frontend/src/localePreference.test.tsx:
  api.updateLocalePreference is not a function
```

After implementation, the focused suites passed:

```text
cargo +stable test --locked --test control_plane_locale --test control_plane_users --test control_plane_repository
32 passed; 0 failed

npm test --prefix frontend -- --run src/localePreference.test.tsx
2 passed; 0 failed
```

## Verification

```text
cargo +stable test --locked --quiet
passed (full Rust suite; 0 failures)

cargo +stable fmt --all -- --check
passed

npm test --prefix frontend
passed

npm run build --prefix frontend
passed

node frontend/scripts/validate-locales.mjs
passed

git diff --check
passed
```

## Review-fix evidence

The regression test first failed as intended against the review baseline:

```text
cargo +stable test --locked --test control_plane_users authenticated_users_can_persist_a_preferred_locale
FAILED: unauthenticated malformed JSON returned 400 instead of the generic 401
```

After authenticating before interpreting the JSON extraction result and
preserving an explicit `null` field during deserialization:

```text
cargo +stable test --locked --test control_plane_users authenticated_users_can_persist_a_preferred_locale
1 passed; 0 failed

cargo +stable test --locked --test control_plane_locale --test control_plane_users --test control_plane_repository
32 passed; 0 failed

npm test --prefix frontend -- --run src/localePreference.test.tsx
2 passed; 0 failed

cargo +stable fmt --all -- --check
passed

cargo +stable clippy --locked --all-targets -- -D warnings
passed

git diff --check
passed
```

The Rust regression covers an unauthenticated malformed JSON request (exact
generic 401), authenticated wrong-type and unknown-field JSON (exact generic
400), unsupported `fr` (exact generic 400), and clearing the value with JSON
`null`.

## Commit

- `c290b18 feat: persist account locale preference`

## Concerns

- The repository's pinned default Cargo is 1.84.1 and cannot parse one locked
  dependency requiring edition 2024. All Rust verification used the installed
  stable toolchain (`cargo +stable`, Cargo 1.97.1) and passed.
- This shared checkout retains unrelated pre-existing edits in
  `.superpowers/sdd/progress.md` and `.superpowers/sdd/task-5-report.md`; they
  were neither staged nor committed.
