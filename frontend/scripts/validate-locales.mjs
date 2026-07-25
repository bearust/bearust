import { readdirSync, readFileSync } from 'node:fs';
import { basename, extname, join } from 'node:path';
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

function flattenStrings(value, prefix = '') {
  if (!value || typeof value !== 'object' || Array.isArray(value)) {
    return prefix ? { [prefix]: typeof value === 'string' ? value : '' } : {};
  }

  return Object.entries(value).reduce(
    (flat, [key, child]) => Object.assign(flat, flattenStrings(child, prefix ? `${prefix}.${key}` : key)),
    {},
  );
}

function interpolationPlaceholders(value) {
  return [...value.matchAll(/{{\s*([^{}\s]+)\s*}}/g)].map((match) => match[1]).sort();
}

export function validateLocaleCatalogs(catalogs) {
  const expected = new Set(flattenKeys(catalogs.en));
  const englishStrings = flattenStrings(catalogs.en);
  const issues = [];

  for (const locale of Object.keys(catalogs).filter((name) => name !== 'en').sort()) {
    const actual = new Set(flattenKeys(catalogs[locale]));
    const translatedStrings = flattenStrings(catalogs[locale]);
    for (const key of [...expected].filter((key) => !actual.has(key)).sort()) {
      issues.push(`${locale}: missing ${key}`);
    }
    for (const key of [...actual].filter((key) => !expected.has(key)).sort()) {
      issues.push(`${locale}: extra ${key}`);
    }
    for (const key of [...expected].filter((key) => actual.has(key)).sort()) {
      const expectedPlaceholders = interpolationPlaceholders(englishStrings[key]);
      const actualPlaceholders = interpolationPlaceholders(translatedStrings[key]);
      if (expectedPlaceholders.join('\u0000') !== actualPlaceholders.join('\u0000')) {
        issues.push(`${locale}: ${key} interpolation placeholders must match English (expected ${expectedPlaceholders.join(', ') || 'none'}; found ${actualPlaceholders.join(', ') || 'none'})`);
      }
    }
  }

  return issues;
}

function loadCatalogs() {
  const localeDirectory = process.env.LOCALES_DIR ?? fileURLToPath(new URL('../src/locales/', import.meta.url));
  const catalogNames = readdirSync(localeDirectory, { withFileTypes: true })
    .filter((entry) => entry.isFile() && extname(entry.name) === '.json')
    .map((entry) => basename(entry.name, '.json'));
  const issues = [
    ...localeNames.filter((locale) => !catalogNames.includes(locale)).map((locale) => `${locale}: missing catalog`),
    ...catalogNames.filter((locale) => !localeNames.includes(locale)).sort().map((locale) => `${locale}: unsupported locale catalog`),
  ];
  const catalogs = Object.fromEntries(
    catalogNames.filter((locale) => localeNames.includes(locale)).map((locale) => [
      locale,
      JSON.parse(readFileSync(join(localeDirectory, `${locale}.json`), 'utf8')),
    ]),
  );
  return { catalogs, issues };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { catalogs, issues: catalogIssues } = loadCatalogs();
  const issues = [...catalogIssues, ...validateLocaleCatalogs(catalogs)];
  if (issues.length > 0) {
    console.error(issues.join('\n'));
    process.exitCode = 1;
  }
}
