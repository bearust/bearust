// @vitest-environment jsdom
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import { createElement } from 'react';
import { act } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { I18nextProvider } from 'react-i18next';
import App, { AnalyticsSection, AuditLogSection, BotChallengePage, UsersSection, WafSection } from './App';
import { api, type User } from './api';
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

const admin: User = { id: 1, email: 'admin@example.com', role: 'admin', disabled: false };
const originalNavigatorLanguages = Object.getOwnPropertyDescriptor(navigator, 'languages');

function RepresentativeSurfaces() {
  return createElement('main', null,
    createElement(App),
    createElement(UsersSection, { user: admin, users: [admin], onChanged: () => undefined }),
    createElement(AuditLogSection, { user: admin }),
    createElement(AnalyticsSection, { hosts: [] }),
    createElement(WafSection, { user: admin }),
    createElement(BotChallengePage, { fingerprint: '' }),
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

  it('renders Indonesian latency values with the milliseconds unit', async () => {
    await i18n.changeLanguage('id');
    expect(i18n.t('analytics.milliseconds', { value: 42 })).toBe('42 ms');
  });

  it.each([
    ['id', ['Penyiapan Bearust', 'Pengguna', 'Log Audit', 'Analitik', 'WAF Dasar', 'Pemeriksaan browser cepat', 'Konteks tantangan tidak tersedia. Kembali ke halaman yang dilindungi lalu coba lagi.']],
    ['ja', ['Bearust のセットアップ', 'ユーザー', '監査ログ', '分析', '基本 WAF', 'ブラウザーの簡易チェック', 'チャレンジのコンテキストを利用できません。保護されたページに戻って、もう一度お試しください。']],
  ] as const)('renders auth, CRUD, audit, analytics, WAF, and security-challenge surfaces in %s', async (locale, expected) => {
    await i18n.changeLanguage(locale);
    Object.defineProperty(navigator, 'languages', { configurable: true, value: [locale] });
    vi.spyOn(api, 'status').mockResolvedValue({ initialized: false });
    vi.spyOn(api, 'auditLogs').mockResolvedValue({ items: [], page: 1, page_size: 25, total: 0 });
    vi.spyOn(api, 'wafConfig').mockResolvedValue({ mode: 'monitor-only', updated_at: 'now' });
    vi.spyOn(api, 'wafRules').mockResolvedValue([]);
    const container = document.createElement('div');
    const root: Root = createRoot(container);
    await act(async () => {
      root.render(createElement(I18nextProvider, { i18n }, createElement(RepresentativeSurfaces)));
      await Promise.resolve();
    });
    expect(container.textContent).toContain(expected[0]);
    expect(container.textContent).toContain(expected[1]);
    expect(container.textContent).toContain(expected[2]);
    expect(container.textContent).toContain(expected[3]);
    expect(container.textContent).toContain(expected[4]);
    expect(container.textContent).toContain(expected[5]);
    expect(container.querySelector('[role="alert"]')?.textContent).toBe(expected[6]);
    root.unmount();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    if (originalNavigatorLanguages) Object.defineProperty(navigator, 'languages', originalNavigatorLanguages);
    else delete (navigator as { languages?: readonly string[] }).languages;
    document.body.replaceChildren();
  });
});
