# Bearust Phase 11 — Localization Design

**Date:** 2026-07-25  
**Status:** Proposed  
**Scope:** Phase 11 from `docs/PRD.md`

## Goal

Make the Bearust management GUI localization-ready and deliver English,
Indonesian, and Japanese translations without hardcoding user-facing text in
React components. English remains the default and fallback locale.

## Requirements

Phase 11 must satisfy the following product requirements:

- The GUI supports multiple languages with English as the default.
- Locale resources are externalized so new languages can be added without
  changing application logic.
- Indonesian (`id`) and Japanese (`ja`) are included alongside English (`en`).
- An authenticated user can choose a preferred language and retain it across
  sessions; unauthenticated/setup screens use browser or local-storage
  preference when available.
- Dates, times, numbers, and dashboard/log formatting respect the active
  locale.
- Translation files and their contribution workflow are easy to review through
  normal pull requests.
- Security and WAF messages preserve technical meaning and never expose
  secrets while being translated.

## Recommended approach

Use `i18next` with `react-i18next` in the existing React/Vite frontend. Keep
translation resources as versioned JSON files:

```text
frontend/src/locales/en.json
frontend/src/locales/id.json
frontend/src/locales/ja.json
```

The application initializes English synchronously when possible, then resolves
the preferred locale from the authenticated account, local storage, and browser
language in that order. Only the allowlisted locales (`en`, `id`, `ja`) are
accepted. Unknown or malformed values resolve to English.

This file-based workflow is preferred over a hosted translation platform for
Phase 11 because it keeps the project self-contained, reviewable, and usable
offline. A future platform can consume the same JSON contract without changing
component APIs.

## Architecture

### Translation boundary

Components call `t('namespace.key', values)` and do not contain user-facing
English prose. Translation keys are grouped by feature (`common`, `auth`,
`proxyHosts`, `certificates`, `users`, `roles`, `audit`, `analytics`, `waf`,
`settings`, and `errors`). Technical identifiers, hostnames, certificate
subjects, rule names, and user-provided values remain runtime data and are not
translated.

### Locale state and persistence

The frontend owns the active locale through an i18n provider/hook. A language
selector is available to authenticated users in the existing dashboard shell.
Changing it immediately updates visible UI and stores the value locally.

The control plane persists the preference on the user account through the
existing authenticated user/profile surface and a nullable `preferred_locale`
field. The server validates the same allowlist and returns a safe validation
error for unsupported values. If persistence is unavailable, the UI continues
using the local value and reports only a sanitized, non-blocking error.

Setup and login screens do not require an account preference; they use the
browser locale when supported and otherwise local storage/English fallback.

### Formatting

Use the browser `Intl` APIs (or i18next formatting integration) for dates,
times, relative timestamps, numbers, and percentages. Existing ISO timestamps
remain canonical API data. Formatting is presentation-only and must not alter
sorting, filtering, audit semantics, or persisted values.

### Fallback and missing keys

English is the fallback namespace. Missing Indonesian/Japanese keys render the
English value and emit a development/test diagnostic. Production UI must not
show raw translation keys. CI tests compare locale key sets and fail on missing
or extra keys unless an explicit metadata exception is documented.

## Delivery increments

### 11A — Framework and English extraction

- Add i18next integration and locale initialization.
- Create the English resource catalog.
- Replace hardcoded UI copy across setup, login, dashboard, management pages,
  alerts, empty states, and validation messages.
- Add locale context, selector shell, fallback handling, and formatting helpers.

### 11B — Indonesian and Japanese

- Add complete `id.json` and `ja.json` catalogs.
- Add language selection and preference persistence.
- Translate user-facing dashboard, auth, CRUD, audit, analytics, WAF, and
  system-state copy while preserving security terminology and dynamic values.

### 11C — Contribution and quality gate

- Add key-parity, fallback, locale-switching, persistence, and formatting tests.
- Add contributor documentation describing key naming, interpolation, review,
  and validation commands.
- Add a locale validation command to the frontend check/build workflow.
- Verify responsive layouts with longer Indonesian and Japanese strings.

## Error handling and security

- Unsupported locale values are rejected server-side and fall back client-side.
- Translation loading failures fail closed to English; they do not block login,
  proxy operations, certificate management, or WAF controls.
- Translation resources contain no secrets, tokens, private keys, request bodies,
  or user-generated confidential data.
- Error rendering continues to use the existing sanitized API error boundary;
  server details are never passed directly to translation interpolation.

## Testing and acceptance criteria

Frontend tests must cover:

1. English default and fallback when locale data is missing or invalid.
2. Language switching without a page reload.
3. Account preference persistence and local-storage fallback.
4. Locale-aware date, number, and timestamp formatting.
5. Translation key parity across `en`, `id`, and `ja`.
6. Long-string rendering in the existing responsive dashboard surfaces.

The Phase 11 acceptance gate is:

- All supported UI surfaces use translation keys for user-facing copy.
- English, Indonesian, and Japanese are selectable and complete.
- Preference persistence works for authenticated users and fails soft when
  unavailable.
- Formatting respects the selected locale without changing API semantics.
- Locale validation, frontend tests, production build, Rust tests, formatting,
  Clippy, and `git diff --check` pass.
- Contribution documentation explains how to add or update a locale.

## Explicit non-goals

- Translating API field names, hostnames, certificate data, or user content.
- Translating server-side log storage or changing audit event identifiers.
- Right-to-left layout support in this phase.
- A hosted translation management platform.
- AI-generated translation at runtime.
- Localizing external documentation beyond the contributor workflow.

