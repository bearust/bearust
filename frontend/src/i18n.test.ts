import { describe, expect, it } from 'vitest';
import {
  SUPPORTED_LOCALES,
  formatLocaleDate,
  formatLocaleNumber,
  localeFromPreferences,
  normalizeLocale,
} from './i18n';

describe('locale primitives', () => {
  it('recognizes supported locale values and locale tags', () => {
    expect(SUPPORTED_LOCALES).toEqual(['en', 'id', 'ja']);
    expect(normalizeLocale('id-ID')).toBe('id');
    expect(normalizeLocale('JA_jp')).toBe('ja');
  });

  it('falls back to English for malformed or unsupported locale values', () => {
    expect(normalizeLocale(undefined)).toBe('en');
    expect(normalizeLocale({ locale: 'ja' })).toBe('en');
    expect(normalizeLocale('fr-FR')).toBe('en');
    expect(normalizeLocale('ja---')).toBe('en');
    expect(normalizeLocale('id_____')).toBe('en');
  });

  it('uses account, stored, browser, then English locale preferences', () => {
    expect(localeFromPreferences({ locale: 'ja' }, 'id', 'en-US')).toBe('ja');
    expect(localeFromPreferences({}, 'id-ID', 'ja-JP')).toBe('id');
    expect(localeFromPreferences(null, null, ['fr-FR', 'ja-JP'])).toBe('ja');
    expect(localeFromPreferences({ locale: 'fr' }, 'xx', 'de-DE')).toBe('en');
  });

  it('formats dates and numbers using the requested locale', () => {
    const options = { year: 'numeric', month: 'long', day: 'numeric', timeZone: 'UTC' } as const;
    expect(formatLocaleDate('2024-01-02T00:00:00Z', 'ja', options)).toBe(
      new Intl.DateTimeFormat('ja-JP', options).format(new Date('2024-01-02T00:00:00Z')),
    );
    expect(formatLocaleNumber(1234567.89, 'id')).toBe(
      new Intl.NumberFormat('id-ID').format(1234567.89),
    );
  });
});

describe('locale catalog validation', () => {
  it('detects missing flattened catalog keys', async () => {
    const { mkdtempSync, rmSync, writeFileSync } = await import('node:' + 'fs');
    const { spawnSync } = await import('node:' + 'child_process');
    const { tmpdir } = await import('node:' + 'os');
    const { join } = await import('node:' + 'path');
    const runtimeProcess = (globalThis as typeof globalThis & {
      process: { cwd(): string; env: Record<string, string | undefined> };
    }).process;
    const localeDir = mkdtempSync(join(tmpdir(), 'bearust-locales-'));
    try {
      writeFileSync(join(localeDir, 'en.json'), JSON.stringify({ common: { save: 'Save' }, errors: { required: 'Required' } }));
      writeFileSync(join(localeDir, 'id.json'), JSON.stringify({ common: { save: 'Simpan' }, errors: {} }));
      writeFileSync(join(localeDir, 'ja.json'), JSON.stringify({ common: { save: '保存' }, errors: { required: '必須です' } }));
      writeFileSync(join(localeDir, 'fr.json'), JSON.stringify({ common: { save: 'Enregistrer' }, errors: { required: 'Obligatoire' } }));

      const result = spawnSync('node', ['scripts/validate-locales.mjs'], {
        cwd: runtimeProcess.cwd(),
        env: { ...runtimeProcess.env, LOCALES_DIR: localeDir },
        encoding: 'utf8',
      });

      expect(result.status).toBe(1);
      expect(result.stderr).toContain('id: missing errors.required');
      expect(result.stderr).toContain('fr: unsupported locale catalog');
    } finally {
      rmSync(localeDir, { recursive: true, force: true });
    }
  });
});
