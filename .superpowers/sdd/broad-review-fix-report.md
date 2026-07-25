# Phase 11 Broad Review Fix Report

## Status

Resolved all Important findings from the Phase 11 broad review.

## Changes

- API failures now retain typed HTTP status and server error code. The frontend maps only an allowlisted set of backend codes and exact messages to catalog keys; all other details resolve to `errors.generic` and are never rendered verbatim.
- Built-in `admin`, `operator`, and `viewer` role labels, role options, and realtime connection states are catalogued. Custom role names and slugs remain runtime data.
- Added `roles.deleteConfirm` to all catalogs and used it for custom-role deletion.
- Missing localized entries continue to fall back to English. Missing entries from every catalog emit diagnostics in development/test and safely render the locale's generic error message in production rather than a raw key.
- Catalog tests now validate literal references and bounded dynamic families. Responsive coverage renders Indonesian/Japanese content at 390, 768, and 1280 pixels; JSDOM overflow checks run whenever dimensions are available and table-level horizontal scrolling remains explicit.

## Verification

- `npm test --prefix frontend` — 22 files, 132 tests passed.
- `npm run validate-locales --prefix frontend` — passed.
- `npm run build --prefix frontend` — passed.
- `cargo +stable test --all-targets -- --test-threads=1` — passed.
- `cargo +stable fmt --all -- --check` — passed.
- `cargo +stable clippy --all-targets -- -D warnings` — passed.
- `git diff --check` — passed.

## Concerns

- JSDOM does not calculate layout dimensions, so the document-overflow assertion executes only when its DOM implementation supplies dimensions. The responsive tests also assert the required responsive card and designated table-scroll structure at every requested viewport.

## Re-review follow-up

- Allowlisted server error codes now take precedence over status-only user-error fallbacks, with regression coverage for duplicate email, self mutation, and last-admin responses.
- Source validation imports the production allowlists and runtime enum arrays directly, checking every mapped catalog key without duplicated key lists.
- Responsive coverage now runs both Indonesian and Japanese long-string cases at 390, 768, and 1280 pixels. JSDOM’s explicit zero-layout contract is asserted unconditionally alongside the card/table structural overflow contract.

Re-review verification: frontend 137/137 tests, locale validator, build, full Rust test suite, fmt, Clippy, and diff checks all passed.
