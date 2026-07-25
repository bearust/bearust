# Phase 11 Task 1 Implementation Report

## Status

Completed and committed.

Commit: `2dddaabc131b9b5eed5fd346b058718f34ea208b` (`feat: add localization primitives`)

## Scope

- Added typed locale primitives in `frontend/src/i18n.ts`:
  `Locale`, `SUPPORTED_LOCALES`, normalization, preference precedence, and locale-aware date/number formatting.
- Added the initial matching English, Indonesian, and Japanese `common` and `errors` catalogs.
- Added `frontend/scripts/validate-locales.mjs`, which compares flattened catalog key sets to English and exits non-zero for missing or extra keys.
- Added focused unit coverage, including the validator's missing-key failure path.
- Added `i18next` and `react-i18next` dependencies and lockfile entries.

## TDD evidence

The initial required focused run was performed before the implementation:

```text
npm test --prefix frontend -- --run src/i18n.test.ts
```

It failed as expected because `./i18n` did not yet exist:

```text
Error: Cannot find module './i18n' imported from .../frontend/src/i18n.test.ts
```

The validator test was then extended to exercise a temporary catalog with a missing nested key. Its red run failed as expected because the validator did not yet honor the test catalog directory:

```text
AssertionError: expected +0 to be 1
- Expected: 1
+ Received: 0
```

The minimal `LOCALES_DIR` override was added for that test path; production validation continues to use `frontend/src/locales` by default.

## Verification

All commands exited 0:

```text
npm test --prefix frontend -- --run src/i18n.test.ts
```

```text
Test Files  1 passed (1)
Tests       5 passed (5)
```

```text
node frontend/scripts/validate-locales.mjs
```

```text
npm run --prefix frontend build
```

```text
vite v8.1.5 building client environment for production...
✓ built in 219ms
```

```text
git diff --check
git diff --cached --check
```

Both whitespace checks completed with no output and exit 0. The staged commit was reviewed to confirm it contained only the eight Task 1 frontend files.

## Concerns

- None. Existing unrelated changes in `.superpowers/sdd/progress.md` and `.superpowers/sdd/task-5-report.md` were preserved and not staged.

## Review Fix (Phase 11 Task 1)

- `normalizeLocale` now canonicalizes the complete tag through `Intl.getCanonicalLocales` after converting accepted underscore separators to hyphens. Invalid tags therefore fall back to English instead of accepting only their first language segment.
- Added regression assertions for `ja---` and `id_____`, both of which now resolve to `en`.
- The locale validator now enumerates `.json` files in the catalog directory and reports unsupported locale catalogs. Its temporary-catalog test verifies that a matching but unsupported `fr.json` is detected alongside missing flattened keys.

### Fix verification

The new tests were run before the implementation and failed as expected:

```text
FAIL: normalizeLocale('ja---') expected 'en', received 'ja'
FAIL: expected validator output to contain 'fr: unsupported locale catalog'
```

After the fix, all requested checks exited 0:

```text
npm test --prefix frontend -- --run src/i18n.test.ts
Test Files  1 passed (1)
Tests       5 passed (5)
```

```text
node frontend/scripts/validate-locales.mjs
```

```text
npm run --prefix frontend build
✓ built in 170ms
```
