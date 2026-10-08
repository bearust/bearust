# Localization contribution guide

Bearust currently supports these dashboard locale codes:

- `en` — English, the source and fallback catalog
- `id` — Indonesian
- `ja` — Japanese

Locale catalogs are JSON files in `frontend/src/locales/`. English is the
canonical key set. User-facing React copy must use `react-i18next` translation
keys instead of new hard-coded strings; use locale-aware date and number
formatters for displayed values.

## Keys and interpolation

Use a stable, dot-separated namespace and a lower-camel-case leaf name, such
as `certificates.expires` or `analytics.p95Latency`. Add a new key to
`en.json`, then add the identical nested key to every supported catalog. Do
not rename, reuse, or delete a key as part of a translation-only change,
because keys are the interface between components and every catalog.

Interpolation uses i18next placeholders such as `{{count}}` and `{{expiry}}`.
Keep every placeholder name and occurrence exactly the same as English, while
translating the surrounding sentence. Do not interpolate secrets, credentials,
tokens, private keys, raw request bodies, or unredacted error details into UI
copy.

## Translation review

Review a translation as product copy: preserve the meaning, technical terms,
and safety warnings; keep examples and protocol names accurate; and check that
longer Indonesian or Japanese text still fits the responsive layout. Verify
that a translation does not introduce user-facing English literals where a
catalog key is required, or expose sensitive data. Keep locale changes limited
to catalogs unless a component needs a new message key.

Run this exact validation command from the repository root after every catalog
change:

```bash
npm run validate-locales --prefix frontend
```

It fails when the `en`, `id`, and `ja` catalog files differ in flattened keys
or i18next interpolation placeholders. Before opening a pull request, also
run:

```bash
npm test --prefix frontend
npm run build --prefix frontend
```

For a full release gate, use the complete command sequence in
[DEVELOPMENT.md](../DEVELOPMENT.md#localization-contribution-workflow).

## Adding or updating a locale

Updating an existing supported locale requires no application-logic change:
edit only its JSON catalog and retain key and placeholder parity with English.

Adding a newly supported locale does not require new component behavior or API
semantics, but it is not a catalog-only or configuration-only change. The
frontend and control plane each have an explicit supported-locale registry, so
make these synchronized changes in one pull request (replace `<code>` with the
new lowercase locale code):

1. Copy `frontend/src/locales/en.json` to
   `frontend/src/locales/<code>.json`, translate every value, and preserve the
   complete key and i18next placeholder set. Add `language.options.<code>` to
   every catalog, including English.
2. In `frontend/src/i18n.ts`, import the new catalog; add `<code>` to the
   `Locale` type, `SUPPORTED_LOCALES`, `LOCALE_TAGS`, and the i18next
   `resources` object.
3. In `frontend/src/ui.tsx`, add the corresponding `LanguageSelect` option
   using `language.options.<code>`; this exposes the registered locale without
   changing selector behavior.
4. In `frontend/scripts/validate-locales.mjs`, add `<code>` to `localeNames`.
   Otherwise the validator rejects the new JSON file as an unsupported locale
   catalog.
5. In `src/control_plane/locale.rs`, add the `Locale` enum variant and extend
   both `Locale::as_str` and `validate_locale`. This keeps the account
   preference API's allowlist synchronized with the frontend.
6. Update the affected frontend registry, catalog, selector, and formatting
   tests (including `frontend/src/i18n.test.ts`, `locales.test.ts`,
   `ui.test.tsx`, `localeSelector.test.tsx`, and `formatting.test.tsx`), plus
   Rust allowlist and preference tests in `tests/control_plane_locale.rs` and
   `tests/control_plane_users.rs`.

Run these commands from the repository root before requesting review:

```bash
npm run validate-locales --prefix frontend
npm test --prefix frontend
npm run build --prefix frontend
cargo test --test control_plane_locale --test control_plane_users
git diff --check
```

The locale validator only passes after its catalog allowlist and every
registered catalog agree. The frontend tests and Rust tests then verify that
the selector, locale-aware formatting, and persisted account preference accept
the new code while unsupported values remain rejected.
