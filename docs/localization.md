# Localization contribution guide

BeaRust currently supports these dashboard locale codes:

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

Updating an existing locale requires no application-logic change: edit only
the matching JSON catalog and retain key and placeholder parity with English.
To propose a newly supported locale, copy `en.json` to a new locale-code JSON
file and translate every value; no React component or business/API semantic
change is needed. The same pull request must deliberately update the frontend
locale registration and the backend locale allowlist, then add parity and
formatting coverage for the new code. This keeps unsupported account
preferences rejected and preserves the frontend's English fallback.
