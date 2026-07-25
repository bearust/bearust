// @vitest-environment jsdom
import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeAll, describe, expect, it, vi } from 'vitest';
import App, { RolesSection, sanitizeError } from './App';
import { api, type RoleRecord, type User } from './api';
import { i18n, initI18n } from './i18n';
import { ThemeProvider } from './theme';

const admin: User = { id: 1, email: 'admin@example.com', role: 'admin', disabled: false };
const builtinRole: RoleRecord = {
  id: 1,
  slug: 'admin',
  name: 'Administrator',
  description: '',
  system_managed: true,
  permissions: [],
  scopes: [],
};
const customRole: RoleRecord = {
  id: 2,
  slug: 'deploy-owner',
  name: 'Deploy Owner',
  description: '',
  system_managed: false,
  permissions: [],
  scopes: [],
};

beforeAll(async () => {
  await initI18n('en');
});

afterEach(async () => {
  await i18n.changeLanguage('en');
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  document.body.replaceChildren();
});

describe('localized API errors', () => {
  it('preserves a server error code and translates only allowlisted payloads', async () => {
    const fetchMock = vi.fn().mockResolvedValue(new Response(JSON.stringify({
      code: 'invalid_credentials',
      message: 'Invalid email or password',
    }), { status: 401 }));
    vi.stubGlobal('fetch', fetchMock);

    const error = await api.users().catch((reason) => reason);

    expect(error).toMatchObject({ code: 'invalid_credentials', status: 401 });
    await i18n.changeLanguage('id');
    expect(sanitizeError(error)).toBe('Email atau kata sandi tidak valid.');
    expect(sanitizeError(new Error('English upstream diagnostic'))).toBe(
      'Permintaan tidak dapat diselesaikan. Silakan coba lagi.',
    );
  });
});

describe('localized built-in values', () => {
  it('translates built-in roles but keeps custom names as data', async () => {
    await i18n.changeLanguage('ja');
    const element = document.createElement('div');
    const root = createRoot(element);

    await act(async () => {
      root.render(<RolesSection user={admin} roles={[builtinRole, customRole]} onChanged={vi.fn()} />);
    });

    expect(element.textContent).toContain('管理者');
    expect(element.textContent).toContain('Deploy Owner');
    expect(element.textContent).not.toContain('Administrator');
    root.unmount();
  });

  it('translates realtime statuses rather than interpolating the protocol value', async () => {
    vi.spyOn(api, 'status').mockResolvedValue({ initialized: true });
    vi.spyOn(api, 'me').mockResolvedValue({ ...admin, preferred_locale: 'ja' });
    vi.spyOn(api, 'hosts').mockResolvedValue([]);
    vi.spyOn(api, 'certificates').mockResolvedValue([]);
    const element = document.createElement('div');
    const root = createRoot(element);

    await act(async () => {
      root.render(<ThemeProvider><App /></ThemeProvider>);
    });

    expect(element.textContent).toContain('リアルタイム: 切断');
    expect(element.textContent).not.toContain('リアルタイム: disconnected');
    root.unmount();
  });
});

describe('safe missing translations', () => {
  it('falls back to localized generic text instead of rendering a missing key', async () => {
    await i18n.changeLanguage('ja');
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);

    expect(i18n.t('missing.translation.key')).toBe('リクエストを完了できませんでした。もう一度お試しください。');
    expect(warn).toHaveBeenCalledWith(expect.stringContaining('missing.translation.key'));
  });
});
