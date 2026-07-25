# Phase 11 Final Fix Report

## Status

Resolved the two final-review findings: anomaly enum/catalog drift is now
impossible at the TypeScript type boundary, and responsive overflow is checked
in a real Chromium browser rather than inferred from JSDOM layout values.

## Changes

- `frontend/src/api.ts` exports `ANOMALY_RULES` and `ANOMALY_SEVERITIES`; the
  corresponding API types are derived directly from those runtime arrays.
- `App.tsx` and `catalog-keys.test.ts` import the API-owned arrays. The catalog
  test explicitly proves that every rule and severity runtime value has its
  required English catalog key. The locale validator continues to enforce that
  the matching keys exist in Indonesian and Japanese.
- Added `@playwright/test`, `frontend/playwright.config.ts`, and six Chromium
  layout tests for Indonesian and Japanese at 390, 768, and 1280 pixels. They
  render the dashboard with controlled API responses, assert
  `documentElement.scrollWidth <= documentElement.clientWidth`, and confirm
  that the users table keeps local horizontal scrolling enabled.
- Vitest excludes Playwright's `e2e/**` directory, preserving the existing
  JSDOM structural tests as a separate test layer.
- `DEVELOPMENT.md` documents the required browser install command:
  `npx playwright install chromium`.

## Verification

All commands completed successfully:

```text
npm test --prefix frontend
22 files, 138 tests passed

npm run validate-locales --prefix frontend
npm run build --prefix frontend
npm run test:e2e --prefix frontend
6 Playwright Chromium tests passed

cargo +stable test --all-targets -- --test-threads=1
cargo +stable fmt --all -- --check
cargo +stable clippy --all-targets -- -D warnings
git diff --check
```

Chromium was installed for this verification with `npx playwright install
chromium` from `frontend/`.

## Concerns

- Playwright browser binaries are intentionally not committed; developers and
  CI workers must run the documented install command after installing frontend
  dependencies.
- JSDOM assertions remain structural only. The Chromium suite is the source of
  evidence for measured document overflow.
