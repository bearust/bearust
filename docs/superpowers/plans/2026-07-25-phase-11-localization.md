# Bearust Phase 11 Localization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a tested English/Indonesian/Japanese localization system to the React dashboard, including per-account language preference and locale-aware formatting.

**Architecture:** Keep translation resources in frontend-owned JSON files and expose a small typed locale module (`Locale`, `initI18n`, `setLocale`, `formatLocaleDate`, `formatLocaleNumber`). React components consume `useTranslation()` rather than hardcoded UI copy. The control plane stores a validated nullable `preferred_locale` on users and exposes it through the existing authenticated user/profile API; client persistence remains a safe fallback.

**Tech Stack:** React, TypeScript, Vite, Vitest/jsdom, `i18next`, `react-i18next`, Rust/Axum, SQLx migrations, SQLite/MySQL/PostgreSQL compatibility, browser `Intl`.

## Global Constraints

- English (`en`) is the default and fallback locale.
- Supported locales are exactly `en`, `id`, and `ja` in Phase 11.
- Translation resources are externalized JSON; no new user-facing prose may be hardcoded in React components.
- Locale selection is presentation-only and must not change API sorting, filtering, identifiers, audit events, or persisted domain values.
- Unsupported locale values are rejected by the server and resolve to English in the client.
- Translation resources must not contain secrets, tokens, private keys, request bodies, or confidential user-generated data.
- Existing RBAC, sanitized errors, realtime behavior, and responsive Tailwind v4 UI must remain unchanged.
- Every task uses TDD and ends with focused tests plus a small commit.

---

## File map

- Create `frontend/src/i18n.ts`: locale type, resource registration, initialization, persistence helpers, and `Intl` formatting helpers.
- Create `frontend/src/i18n.test.ts`: locale normalization, fallback, persistence, and formatting tests.
- Create `frontend/src/locales/en.json`, `frontend/src/locales/id.json`, `frontend/src/locales/ja.json`: complete translation catalogs.
- Modify `frontend/package.json` and `frontend/package-lock.json`: add i18n dependencies and validation scripts.
- Modify `frontend/src/main.tsx`: initialize the i18n provider before rendering the app.
- Modify `frontend/src/App.tsx`, `frontend/src/ui.tsx`, and feature tests: replace user-facing literals and add the language selector.
- Modify `frontend/src/api.ts`: add typed profile/preference API calls and sanitized error handling.
- Modify Rust user models/routes/migrations under `src/control_plane/` and `migrations/`: validate and persist `preferred_locale`.
- Create `src/control_plane/locale.rs` and add `pub mod locale;` in `src/control_plane/mod.rs`; keep validator unit tests in `src/control_plane/locale.rs`.
- Create `frontend/scripts/validate-locales.mjs`: flatten locale JSON keys and fail on catalog drift.
- Modify `frontend/package.json`, `DEVELOPMENT.md`, and `README.md`: expose locale validation and contribution workflow.

## Task 1: Add locale primitives and resource validation

**Files:**
- Create: `frontend/src/i18n.ts`
- Create: `frontend/src/i18n.test.ts`
- Create: `frontend/src/locales/en.json`
- Create: `frontend/src/locales/id.json`
- Create: `frontend/src/locales/ja.json`
- Create: `frontend/scripts/validate-locales.mjs`
- Modify: `frontend/package.json`
- Modify: `frontend/package-lock.json`

**Interfaces:**
- `export type Locale = 'en' | 'id' | 'ja'`
- `export const SUPPORTED_LOCALES: readonly Locale[]`
- `export function normalizeLocale(value: unknown): Locale`
- `export function localeFromPreferences(account: unknown, stored: unknown, browser: unknown): Locale`
- `export function formatLocaleDate(value: string | number | Date, locale: Locale, options?: Intl.DateTimeFormatOptions): string`
- `export function formatLocaleNumber(value: number, locale: Locale, options?: Intl.NumberFormatOptions): string`
- `validate-locales.mjs` exits `0` only when every locale has the exact flattened key set of `en.json`.

- [ ] **Step 1: Add the failing unit tests** for supported values, malformed/unsupported values, preference precedence (account > local storage > browser > English), date/number formatting, and missing key detection.
- [ ] **Step 2: Run `npm test --prefix frontend -- --run src/i18n.test.ts`; verify it fails because the module and catalogs do not exist.**
- [ ] **Step 3: Add `i18next` and `react-i18next` dependencies, implement the locale helpers, and create an initial catalog containing `common` and `errors` keys.
- [ ] **Step 4: Expand all three catalogs to the same initial key set and implement `scripts/validate-locales.mjs`.
- [ ] **Step 5: Run `npm test --prefix frontend -- --run src/i18n.test.ts` and `node frontend/scripts/validate-locales.mjs`; expect all tests and validation to pass.
- [ ] **Step 6: Commit with `git add frontend && git commit -m "feat: add localization primitives"`.

## Task 2: Integrate i18n into the React shell

**Files:**
- Modify: `frontend/src/main.tsx`
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/ui.tsx`
- Modify: `frontend/src/i18n.ts`
- Modify: `frontend/src/i18n.test.ts`
- Create: `frontend/src/localeSelector.test.tsx`

**Interfaces:**
- `I18nextProvider` wraps `<App />` in `main.tsx`.
- `LanguageSelect` accepts `{ value: Locale; onChange: (locale: Locale) => void }` and renders accessible labels for `en`, `id`, and `ja`.
- `useLocalePreference()` returns `{ locale: Locale; setLocale(locale: Locale): Promise<void> }` and never rejects due to a preference persistence failure.

- [ ] **Step 1: Add a failing selector test** that renders the dashboard shell, changes the select to `id`, and observes translated text without a reload.
- [ ] **Step 2: Run `npm test --prefix frontend -- --run src/localeSelector.test.tsx`; verify failure.
- [ ] **Step 3: Initialize i18next in `main.tsx`, add `LanguageSelect`, and mount it in the authenticated dashboard shell without changing RBAC visibility.
- [ ] **Step 4: Add local-storage/browser preference loading and a fail-soft setter; ensure invalid stored values normalize to `en`.
- [ ] **Step 5: Run the focused selector and existing `theme`, `ui`, and `responsive-smoke` tests.
- [ ] **Step 6: Commit with `git add frontend/src/main.tsx frontend/src/App.tsx frontend/src/ui.tsx frontend/src/i18n.ts frontend/src/*locale*test.tsx && git commit -m "feat: integrate frontend localization"`.

## Task 3: Externalize English UI copy

**Files:**
- Modify: `frontend/src/App.tsx`
- Modify: `frontend/src/ui.tsx`
- Modify: `frontend/src/api.ts`
- Modify: all existing feature tests that assert visible text (`acme`, `analytics`, `audit`, `baseline`, `bot`, `rateLimit`, `roles`, `users`, `waf`, and responsive smoke tests)
- Modify: `frontend/src/locales/en.json`

**Interfaces:**
- Components use `const { t } = useTranslation()` and call stable keys such as `common.save`, `auth.login`, `proxyHosts.empty`, and `errors.generic`.
- Dynamic values use interpolation (`t('audit.pageOf', { page, total })`) and never concatenate untrusted server error text into translated copy.

- [ ] **Step 1: Add a catalog-key test that scans the compiled component source for known user-facing literals in the dashboard shell and fails for each remaining literal outside technical data, test fixtures, and accessibility-required icon labels.
- [ ] **Step 2: Run the focused feature tests and record the expected failures from changed text and missing keys.
- [ ] **Step 3: Move setup/login, navigation, CRUD forms, alerts, empty states, validation messages, audit, analytics, WAF, bot, rate-limit, anomaly, and baseline labels into namespaced `en.json` keys.
- [ ] **Step 4: Replace literals with `t()` calls while preserving DOM roles, labels, test IDs, sanitized error boundaries, and RBAC conditions.
- [ ] **Step 5: Update assertions to assert semantic translated output through English keys; run `npm test --prefix frontend -- --run` for the affected files and `node frontend/scripts/validate-locales.mjs`.
- [ ] **Step 6: Commit with `git add frontend/src frontend/scripts frontend/package.json frontend/package-lock.json && git commit -m "refactor: externalize dashboard copy"`.

## Task 4: Persist the preferred locale on user accounts

**Files:**
- Create: `migrations/0014_add_user_preferred_locale.sql` adding nullable `preferred_locale` to `users` with the repository’s SQLite/MySQL/PostgreSQL-compatible conventions
- Modify: `src/control_plane/locale.rs`
- Modify: `src/control_plane/mod.rs` and `src/control_plane/models.rs`
- Modify: `src/control_plane/repository.rs`
- Modify: `frontend/src/api.ts`
- Create: `frontend/src/localePreference.test.tsx`

**Interfaces:**
- `fn validate_locale(value: &str) -> Result<Locale, LocaleError>` accepts only `en`, `id`, or `ja`.
- `GET /api/auth/me` includes nullable `preferred_locale`.
- `PATCH /api/auth/me/preferences` accepts `{ "preferred_locale": "en" | "id" | "ja" | null }` and returns the sanitized updated profile/preference object.
- The endpoint requires an authenticated session and does not alter admin/operator/viewer authorization.

- [ ] **Step 1: Add Rust tests for allowlist acceptance, rejection of `fr`/empty/oversized values, unauthenticated rejection, and successful account update; add frontend tests for API request shape and fail-soft local fallback.
- [ ] **Step 2: Run the focused Rust and frontend tests; verify failure because the migration, validator, and endpoint do not exist.
- [ ] **Step 3: Add `migrations/0014_add_user_preferred_locale.sql` using the project’s established cross-database SQLx pattern and load it in fresh and existing databases.
- [ ] **Step 4: Implement the shared locale validator, profile serialization, authenticated GET/PATCH handlers, and sanitized validation errors.
- [ ] **Step 5: Wire `useLocalePreference().setLocale()` to update the account after applying the locale locally; retain the local value when the request fails.
- [ ] **Step 6: Run focused Rust tests, `cargo test --locked`, frontend preference tests, and the locale validator; expect all to pass.
- [ ] **Step 7: Commit with `git add migrations src frontend/src/api.ts frontend/src/i18n.ts frontend/src/localePreference.test.tsx && git commit -m "feat: persist account locale preference"`.

## Task 5: Add Indonesian and Japanese catalogs

**Files:**
- Modify: `frontend/src/locales/id.json`
- Modify: `frontend/src/locales/ja.json`
- Create: `frontend/src/locales.test.ts`
- Modify: feature tests where long translated copy changes responsive assertions

**Interfaces:**
- `en.json`, `id.json`, and `ja.json` have identical flattened key sets.
- Translation interpolation placeholders match exactly between locales (for example `{count}` and `{name}`).

- [ ] **Step 1: Add tests that compare flattened keys and interpolation placeholder sets for all catalogs and render representative auth, CRUD, audit, analytics, WAF, and security-alert surfaces in each locale.
- [ ] **Step 2: Run `npm test --prefix frontend -- --run src/locales.test.ts`; verify failure for incomplete catalogs/placeholders.
- [ ] **Step 3: Translate every English catalog value into Indonesian and Japanese, preserving placeholders, technical identifiers, and security terminology.
- [ ] **Step 4: Run locale parity tests, all frontend tests, and `node frontend/scripts/validate-locales.mjs`; fix every mismatch.
- [ ] **Step 5: Commit with `git add frontend/src/locales frontend/src/locales.test.ts frontend/src/*test.tsx && git commit -m "feat: add Indonesian and Japanese translations"`.

## Task 6: Locale-aware formatting and responsive QA

**Files:**
- Modify: `frontend/src/App.tsx`, `frontend/src/ui.tsx`, and existing dashboard feature modules/tests
- Modify: `frontend/src/i18n.ts`
- Create: `frontend/src/formatting.test.tsx`
- Modify: `frontend/src/responsive-smoke.test.tsx`

**Interfaces:**
- All displayed timestamps call `formatLocaleDate` or a locale-aware hook.
- All displayed counts, rates, percentages, and sizes call `formatLocaleNumber` with explicit options.
- API values remain raw ISO strings/numbers for sorting and mutation payloads.

- [ ] **Step 1: Add failing tests for a representative audit timestamp, analytics count/percentage, and WAF/rate-limit numeric value in `en`, `id`, and `ja`, plus a long-string responsive smoke case.
- [ ] **Step 2: Run the focused tests and verify the current hardcoded formatting fails the expectations.
- [ ] **Step 3: Replace presentation formatting with the shared `Intl` helpers and make table/card layouts tolerate the longer strings without clipping or horizontal overflow.
- [ ] **Step 4: Run `npm test --prefix frontend -- --run src/formatting.test.tsx src/responsive-smoke.test.tsx` and `npm run build --prefix frontend`.
- [ ] **Step 5: Commit with `git add frontend/src && git commit -m "feat: localize dashboard formatting"`.

## Task 7: Document contribution workflow and complete the acceptance gate

**Files:**
- Modify: `DEVELOPMENT.md`
- Modify: `README.md`
- Modify: `docs/PRD.md` with Phase 11A/11B/11C status only after implementation passes
- Modify: `frontend/package.json` to expose `npm run validate-locales`
- Create: `docs/localization.md`

**Interfaces:**
- `npm run validate-locales --prefix frontend` runs the locale key/placeholder validator.
- `docs/localization.md` documents key naming, interpolation, translation review, test/build commands, and how to add a locale without editing application logic.

- [ ] **Step 1: Add a documentation check that references the exact validation command and supported locale codes.
- [ ] **Step 2: Run `npm run validate-locales --prefix frontend`, `npm test --prefix frontend`, `npm run build --prefix frontend`, `cargo +stable test --all-targets -- --test-threads=1`, `cargo +stable fmt --all -- --check`, `cargo +stable clippy --all-targets -- -D warnings`, and `git diff --check`.
- [ ] **Step 3: Review the diff for secrets, untranslated user-facing literals, API semantic changes, and broken responsive layouts.
- [ ] **Step 4: Update PRD/README status to mark the completed increments and Phase 12 as next only after all checks pass.
- [ ] **Step 5: Commit with `git add README.md DEVELOPMENT.md docs/PRD.md docs/localization.md frontend/package.json && git commit -m "docs: document phase 11 localization"`.

## Final verification gate

Run from repository root:

```bash
npm run validate-locales --prefix frontend
npm test --prefix frontend
npm run build --prefix frontend
cargo +stable test --all-targets -- --test-threads=1
cargo +stable fmt --all -- --check
cargo +stable clippy --all-targets -- -D warnings
git diff --check
```

Expected result: every command exits successfully; all supported UI surfaces
use translation keys; all three catalogs have matching keys/placeholders; the
account preference is validated and persisted; locale-aware formatting and
responsive layouts pass their tests; and documentation explains contribution.
