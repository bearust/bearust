# Task 4 report — application shell and page migration

## Scope

Migrated setup, login, authenticated shell, proxy hosts, certificates, ACME,
users, roles, and audit log views in `frontend/src/App.tsx` to Tailwind v4
utilities and shared UI primitives. API calls, auth/session handling, RBAC
visibility, realtime reload callbacks, filters, pagination, and redacted error
messages were preserved. Legacy CSS selectors were removed from JSX; the
stylesheet retains Tailwind import, semantic tokens/theme overrides, and
reduced-motion behavior from the design-system tasks.

## Verification

Command: `npm test -- --run` (from `frontend/`)

Result: **29 tests passed across 6 files**.

Command: `npm run build` (from `frontend/`)

Result: **TypeScript and Vite production build passed**; generated bundle:
`dist/assets/index-CRS5IakZ.js` and `dist/assets/index-BtF9hMrk.css`.

Command: `rg -n 'className="(card|error|section-heading|certificate|certificate-grid|danger|muted|host-form|audit-|realtime-status)' frontend/src`

Result: no obsolete selector references found. Existing test-only hooks
(`users-card`, `user-form`) remain as stable selectors and have no stylesheet
rules.

## Concerns

- Existing Vitest/jsdom setup emits React `act(...)` and Node localStorage
  warnings; these are pre-existing test-environment warnings and do not fail
  the suite.
- The root `main.tsx` still wraps `App` in `ThemeProvider`; `App` also wraps
  itself so direct component tests receive theme context. This is harmless but
  can be simplified in a follow-up cleanup.
