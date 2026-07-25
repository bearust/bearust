// @vitest-environment jsdom
import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
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
  document.body.replaceChildren();
});

describe('dashboard locale selector', () => {
  it('switches the authenticated dashboard to Indonesian without a reload', async () => {
    await initI18n('en');
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
});
