// @vitest-environment jsdom
import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api } from './api';
import { LocalePreferenceProvider, useLocalePreference } from './i18n';

const KEY = 'bearust.locale.v1';

function Probe() {
  const { locale, setLocale } = useLocalePreference();
  return <button data-locale={locale} onClick={() => void setLocale('ja')} />;
}

beforeEach(() => {
  const values = new Map<string, string>();
  const storage = {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => { values.set(key, value); },
    removeItem: (key: string) => { values.delete(key); },
    clear: () => values.clear(),
  } as Storage;
  vi.stubGlobal('localStorage', storage);
  Object.defineProperty(window, 'localStorage', { configurable: true, value: storage });
  storage.clear();
});

afterEach(() => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  document.body.replaceChildren();
});

describe('locale account preference', () => {
  it('sends the supported locale to the authenticated preference endpoint', async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      new Response(JSON.stringify({ id: 1, email: 'user@example.test', role: 'viewer', disabled: false, preferred_locale: 'ja' }), { status: 200 }),
    );
    vi.stubGlobal('fetch', fetchMock);

    await api.updateLocalePreference('ja');

    expect(fetchMock).toHaveBeenCalledWith('/api/auth/me/preferences', expect.objectContaining({
      method: 'PATCH',
      credentials: 'include',
      body: JSON.stringify({ preferred_locale: 'ja' }),
    }));
  });

  it('keeps the local locale when account persistence fails', async () => {
    vi.spyOn(api, 'updateLocalePreference').mockRejectedValue(new Error('offline'));
    const container = document.createElement('div');
    document.body.append(container);
    const root = createRoot(container);

    await act(async () => {
      root.render(<LocalePreferenceProvider><Probe /></LocalePreferenceProvider>);
    });
    const probe = container.querySelector('button')!;
    await act(async () => {
      probe.dispatchEvent(new MouseEvent('click', { bubbles: true }));
    });

    expect(probe.dataset.locale).toBe('ja');
    expect(localStorage.getItem(KEY)).toBe('ja');
    root.unmount();
  });
});
