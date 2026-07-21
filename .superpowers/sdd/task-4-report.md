# Task 4 report — admin role scope editor

## Scope

Added per-role proxy-host read/write scope controls to `RolesSection`. Admins
can select or clear hosts independently for each permission, normalized scope
assignments are sent in role create/update payloads, and built-in roles remain
read-only. Scope controls use responsive Tailwind v4 grid utilities and stable
test IDs. Validation failures use the existing alert pattern and retain the
unsaved draft selections.

## Verification

Command: `npm test -- --run` (from `frontend/`)

Result: **38 tests passed across 8 files**.

Command: `npm run build` (from `frontend/`)

Result: **TypeScript and Vite production build passed**.

## Notes

Vitest may emit pre-existing React `act(...)` and Node localStorage warnings;
they do not fail the suite.
