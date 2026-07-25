import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const localeNames = ['en', 'id', 'ja'];

export function flattenKeys(value, prefix = '') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return prefix ? [prefix] : [];
  }

  return Object.entries(value).flatMap(([key, child]) =>
    flattenKeys(child, prefix ? `${prefix}.${key}` : key),
  );
}

export function validateLocaleCatalogs(catalogs) {
  const expected = new Set(flattenKeys(catalogs.en));
  const issues = [];

  for (const locale of Object.keys(catalogs).filter((name) => name !== 'en').sort()) {
    const actual = new Set(flattenKeys(catalogs[locale]));
    for (const key of [...expected].filter((key) => !actual.has(key)).sort()) {
      issues.push(`${locale}: missing ${key}`);
    }
    for (const key of [...actual].filter((key) => !expected.has(key)).sort()) {
      issues.push(`${locale}: extra ${key}`);
    }
  }

  return issues;
}

function loadCatalogs() {
  const localeDirectory = process.env.LOCALES_DIR ?? fileURLToPath(new URL('../src/locales/', import.meta.url));
  return Object.fromEntries(
    localeNames.map((locale) => [
      locale,
      JSON.parse(readFileSync(join(localeDirectory, `${locale}.json`), 'utf8')),
    ]),
  );
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const issues = validateLocaleCatalogs(loadCatalogs());
  if (issues.length > 0) {
    console.error(issues.join('\n'));
    process.exitCode = 1;
  }
}
