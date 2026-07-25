# Task 7 report

## Status

Complete. Phase 11 localization documentation and its final acceptance gate are
complete. The public `npm run validate-locales --prefix frontend` command now
validates both catalog keys and i18next interpolation placeholders.

## Commit

- `63d473d docs: document phase 11 localization`

## Delivered

- Added `docs/localization.md` covering supported codes (`en`, `id`, `ja`),
  key naming, interpolation, translation review, validation, and the
  synchronized registration and allowlist workflow for proposing a new locale.
- Added the public frontend locale-validation script and its placeholder-parity
  regression coverage.
- Added the exact localization contribution and full acceptance workflows to
  `DEVELOPMENT.md`, with README links and supported-code documentation.
- Marked Phase 11A/11B/11C complete and Phase 12 next in the README and PRD
  only after the acceptance gate passed.

## Verification

All commands exited successfully from the repository root:

```text
npm run validate-locales --prefix frontend
npm test --prefix frontend                 # 21 files, 123 tests passed
npm run build --prefix frontend
cargo +stable test --all-targets -- --test-threads=1
cargo +stable fmt --all -- --check
cargo +stable clippy --all-targets -- -D warnings
git diff --check
```

The diff review found no secrets, new untranslated UI literals, API semantic
changes, or responsive-layout changes. Existing frontend tests emit Node's
experimental localStorage warning; it is non-failing and pre-existing.

## Concerns

None for the Task 7 implementation. The pre-existing modified
`.superpowers/sdd/progress.md` was left untouched.

## Follow-up review remediation

The new-locale workflow in `docs/localization.md` now states that adding a
locale is not catalog-only or configuration-only. It requires synchronized
frontend registration, selector, validator allowlist, catalog, Rust allowlist,
and test updates, while preserving existing component behavior and API
semantics.
