// @vitest-environment jsdom
import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { I18nextProvider, useTranslation } from 'react-i18next';
import App from './App';
import { api } from './api';
import { i18n, initI18n } from './i18n';
import { ThemeProvider } from './theme';

const viewer = { id: 1, email: 'viewer@example.test', role: 'viewer', disabled: false } as const;

function TranslationProbe() {
  const { t } = useTranslation();
  return <output>{t('common.save')}</output>;
}

afterEach(() => {
  vi.restoreAllMocks();
  window.localStorage.clear();
  document.body.replaceChildren();
});

beforeEach(async () => {
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
    clear: () => values.clear(),
  } as Storage;
  vi.stubGlobal('localStorage', storage);
  Object.defineProperty(window, 'localStorage', { configurable: true, value: storage });
  await initI18n('en');
});

describe('dashboard locale selector', () => {
  it('switches the authenticated dashboard to Indonesian without a reload', async () => {
    vi.spyOn(api, 'status').mockResolvedValue({ initialized: true });
    vi.spyOn(api, 'me').mockResolvedValue(viewer);
    vi.spyOn(api, 'hosts').mockResolvedValue([]);
    vi.spyOn(api, 'certificates').mockResolvedValue([]);
    vi.spyOn(api, 'updateLocalePreference').mockResolvedValue(viewer);

    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    await act(async () => {
      root.render(<I18nextProvider i18n={i18n}><ThemeProvider><App /><TranslationProbe /></ThemeProvider></I18nextProvider>);
    });

    const menuTrigger = container.querySelector<HTMLButtonElement>('button[aria-haspopup="menu"]');
    await act(async () => {
      menuTrigger!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });

    const select = container.querySelector<HTMLSelectElement>('select[aria-label="Language"]');
    expect(select).toBeTruthy();
    expect(select?.value).toBe('en');

    await act(async () => {
      select!.value = 'id';
      select!.dispatchEvent(new Event('change', { bubbles: true }));
    });

    expect(select?.selectedOptions[0]?.textContent).toBe('Bahasa Indonesia');
    expect(container.querySelector('output')?.textContent).toBe('Simpan');
    root.unmount();
  });

  it('uses the authenticated account locale ahead of a stored browser locale', async () => {
    window.localStorage.setItem('bearust.locale.v1', 'id');
    vi.spyOn(api, 'status').mockResolvedValue({ initialized: true });
    vi.spyOn(api, 'me').mockResolvedValue({ ...viewer, preferred_locale: 'ja' });
    vi.spyOn(api, 'hosts').mockResolvedValue([]);
    vi.spyOn(api, 'certificates').mockResolvedValue([]);

    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);
    await act(async () => {
      root.render(<I18nextProvider i18n={i18n}><ThemeProvider><App /><TranslationProbe /></ThemeProvider></I18nextProvider>);
    });

    const menuTrigger = container.querySelector<HTMLButtonElement>('header button[aria-haspopup="menu"]');
    await act(async () => {
      menuTrigger!.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });

    const select = container.querySelector<HTMLSelectElement>('header select[aria-label="言語"]');
    expect(select?.value).toBe('ja');
    expect(select?.getAttribute('aria-label')).toBe('言語');
    expect(select?.selectedOptions[0]?.textContent).toBe('日本語');
    expect(container.querySelector('output')?.textContent).toBe('保存');
    root.unmount();
  });
});
