# Phase 11 Task 2 Report — React shell localization

## Status

Completed in commit `f005e89 feat: integrate frontend localization`.

## Changed scope

- `frontend/src/main.tsx`: initializes the static i18next resource instance and wraps the React application in `I18nextProvider`.
- `frontend/src/i18n.ts`: registers the three existing JSON catalogs, derives the initial locale from local storage or browser languages, normalizes invalid stored values to English, and changes the active i18next language before best-effort persistence.
- `frontend/src/App.tsx`: provides locale state to the standalone application shell and adds the selector to the shared authenticated dashboard header without changing role checks or feature visibility.
- `frontend/src/ui.tsx`: adds the typed, accessible `LanguageSelect` with English, Indonesian, and Japanese option labels.
- `frontend/src/i18n.test.ts`: covers invalid stored locale normalization.
- `frontend/src/localeSelector.test.tsx`: renders an authenticated viewer shell, selects Indonesian without reload, and observes the active i18next translation change from `Save` to `Simpan`.

## TDD evidence

The selector test was added before implementation and failed because no language selector existed:

```text
AssertionError: expected null to be truthy
```

The invalid-storage regression test also failed before the preference reader was updated:

```text
AssertionError: expected undefined to be 'en'
```

Both now pass with the minimal provider and i18next wiring.

## Verification

Focused locale and shell regression suite:

```text
npm test --prefix frontend -- --run src/localeSelector.test.tsx src/i18n.test.ts src/theme.test.tsx src/ui.test.tsx src/responsive-smoke.test.tsx
```

Result: 5 test files passed; 24 tests passed.

Production build:

```text
npm run build --prefix frontend
```

Result: `tsc -b && vite build` completed successfully.

Diff validation:

```text
git diff --check
```

Result: passed with no whitespace errors before the commit.

## Scope notes and concerns

- Existing RBAC conditions remain intact; the selector is in the shared authenticated header and does not expose any management action.
- Translation extraction of dashboard copy remains Task 3. This task proves live i18next switching with the existing catalog key while preserving all current UI copy.
- `.superpowers/sdd/progress.md` and `.superpowers/sdd/task-5-report.md` were already modified by other work and were not changed or staged.

## Review remediation — account locale and selector safety

- `LocalePreferenceProvider` now accepts the authenticated account locale and re-applies the documented account → local storage → browser → English precedence when authentication state changes. `AppContent` passes `user?.preferred_locale`, so a returning user receives their saved account language after `api.me()`, while setup, login, storage, i18next, and preference-save failures remain fail-soft.
- `LanguageSelect` now obtains its accessible label and all option labels from `language.*` translation keys present in the English, Indonesian, and Japanese catalogs. Its DOM change handler normalizes the submitted value before calling consumers, so injected or unsupported values fall back to `en` instead of crossing the typed boundary.
- Added regression coverage for account-locale precedence over a stored locale, Japanese selector labels, and an invalid injected select value.

Verification after the review fix:

```text
npm test --prefix frontend -- --run src/localeSelector.test.tsx src/localePreference.test.tsx src/i18n.test.ts src/theme.test.tsx src/ui.test.tsx src/responsive-smoke.test.tsx
```

Result: 6 test files passed; 29 tests passed.

```text
npm test --prefix frontend -- --run
```

Result: 18 test files passed; 64 tests passed.

```text
npm run build --prefix frontend
node frontend/scripts/validate-locales.mjs
git diff --check
```

Result: production build and locale validation passed; no whitespace errors.
