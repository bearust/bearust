// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it } from 'vitest';
import { createElement } from 'react';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { I18nextProvider, useTranslation } from 'react-i18next';
import { i18n, initI18n, SUPPORTED_LOCALES, type Locale } from './i18n';
import en from './locales/en.json';
import id from './locales/id.json';
import ja from './locales/ja.json';

interface Catalog {
  [key: string]: string | Catalog;
}

function flattenCatalog(catalog: Catalog, prefix = ''): Record<string, string> {
  return Object.entries(catalog).reduce<Record<string, string>>((flat, [key, value]) => {
    const path = prefix ? `${prefix}.${key}` : key;
    if (typeof value === 'string') flat[path] = value;
    else Object.assign(flat, flattenCatalog(value, path));
    return flat;
  }, {});
}

function placeholders(value: string): string[] {
  return [...value.matchAll(/{{\s*([^{}\s]+)\s*}}/g)].map((match) => match[1]).sort();
}

const catalogs: Record<Locale, Catalog> = { en, id, ja };

function RepresentativeSurface() {
  const { t } = useTranslation();
  return createElement('main', null,
    createElement('h1', null, t('auth.setupTitle')),
    createElement('h2', null, t('users.title')),
    createElement('h2', null, t('audit.title')),
    createElement('h2', null, t('analytics.title')),
    createElement('h2', null, t('waf.title')),
    createElement('p', { role: 'alert' }, t('errors.challengeVerification')),
  );
}

describe('locale catalogs', () => {
  beforeAll(async () => { await initI18n('en'); });

  it('has identical flattened keys in every supported locale', () => {
    const englishKeys = Object.keys(flattenCatalog(en)).sort();
    for (const locale of SUPPORTED_LOCALES) {
      expect(Object.keys(flattenCatalog(catalogs[locale])).sort()).toEqual(englishKeys);
    }
  });

  it('has identical interpolation placeholders in every supported locale', () => {
    const english = flattenCatalog(en);
    for (const locale of SUPPORTED_LOCALES) {
      const translated = flattenCatalog(catalogs[locale]);
      for (const [key, value] of Object.entries(english)) {
        expect(placeholders(translated[key]), `${locale}.${key}`).toEqual(placeholders(value));
      }
    }
  });

  it('would catch missing keys and altered placeholders', () => {
    expect(Object.keys(flattenCatalog({ common: { save: 'Save' } }))).not.toEqual(
      Object.keys(flattenCatalog({ common: { save: 'Simpan' }, audit: { page: 'Halaman {{page}}' } })),
    );
    expect(placeholders('Halaman {{page}} dari {{total}}')).not.toEqual(placeholders('ページ {{page}}'));
  });

  it.each([
    ['id', ['Penyiapan Bearust', 'Pengguna', 'Log Audit', 'Analitik', 'WAF Dasar', 'Verifikasi tantangan gagal. Silakan coba lagi.']],
    ['ja', ['Bearust のセットアップ', 'ユーザー', '監査ログ', '分析', '基本 WAF', 'チャレンジの検証に失敗しました。もう一度お試しください。']],
  ] as const)('renders representative auth, CRUD, audit, analytics, WAF, and security-alert copy in %s', async (locale, expected) => {
    await i18n.changeLanguage(locale);
    const container = document.createElement('div');
    const root: Root = createRoot(container);
    await act(async () => {
      root.render(createElement(I18nextProvider, { i18n }, createElement(RepresentativeSurface)));
    });
    expect(container.textContent).toContain(expected[0]);
    expect(container.textContent).toContain(expected[1]);
    expect(container.textContent).toContain(expected[2]);
    expect(container.textContent).toContain(expected[3]);
    expect(container.textContent).toContain(expected[4]);
    expect(container.querySelector('[role="alert"]')?.textContent).toBe(expected[5]);
    root.unmount();
  });

  afterEach(() => { document.body.replaceChildren(); });
});
