# Task 3 report

Implemented catalog-backed dashboard copy for the localization migration slice.

- Added an App source literal guard and moved the covered shell, auth, certificate, user, role, WAF, bot, rate-limit, analytics, baseline, anomaly, tuning, proxy-host, audit, and challenge strings into catalog namespaces.
- Preserved component RBAC gates, DOM roles, test IDs, and error sanitization. The app initializes i18n before independently mounted component tests use `useTranslation`.
- Added matching English fallback catalogs for Indonesian and Japanese to maintain catalog parity until Task 5 supplies translations.

Verification:

- `npm test --prefix frontend -- --run src/acme.test.tsx src/analytics.test.tsx src/audit.test.tsx src/baseline.test.tsx src/bot.test.tsx src/rateLimit.test.tsx src/roles.test.tsx src/users.test.tsx src/waf.test.tsx src/responsive-smoke.test.tsx src/catalog-keys.test.tsx` passed after the i18n initialization change, except for one updated generic-error assertion which was then rerun with `users.test.tsx` and `catalog-keys.test.ts` (18 passed).
- `node frontend/scripts/validate-locales.mjs` passed.
- `npm run build --prefix frontend` passed.

Remaining concern: full-suite locale-selector/UI expectations still assert the original Indonesian/Japanese translations; those tests need Task 5's translated catalogs rather than the requested English fallback values.

## Review follow-up

- Replaced every remaining user-facing literal in `App.tsx` for analytics, baseline, anomaly detection, adaptive tuning, bot challenge, proxy-host CRUD, and audit controls/table/pagination. This includes visible labels, option values, placeholders, loading/empty/error states, and accessibility labels.
- Updated `ThemeSelect` in `ui.tsx` to use the `theme` namespace for its label and mode options.
- Expanded the catalog guard to scan both component sources. It rejects the prior known literals, direct visible JSX prose, and literal `label`, `placeholder`, `title`, or `aria-label` attributes.
- Restored the Indonesian and Japanese leaves present before `4a17029` (`common.cancel`, `common.save`, `errors.required`, `errors.unexpected`, and the locale selector labels/options). All other and newly introduced keys use the English catalog fallback, preserving exact catalog parity for Task 5 translation work.

Review verification (2026-07-25):

```text
npm test --prefix frontend -- --run
19 test files passed; 111 tests passed.

npm run build --prefix frontend
tsc -b && vite build passed.

node frontend/scripts/validate-locales.mjs
Passed with no catalog-parity output.

git diff --check
Passed with no output.
```

The test command emits Node's existing localStorage experimental warnings only; it has no test failures.
