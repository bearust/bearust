// @vitest-environment jsdom
import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App, { UsersSection } from './App';
import { api, type User } from './api';
import { i18n, initI18n } from './i18n';

const admin: User = { id: 1, email: 'admin@example.com', role: 'admin', disabled: false };

function setViewport(width: number) {
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: width });
}

afterEach(async () => {
  await i18n.changeLanguage('en');
  vi.restoreAllMocks();
  document.body.innerHTML = '';
});

describe('responsive smoke fixtures', () => {
  it.each([1280, 768, 390])('renders setup/login shell without horizontal layout hooks at %ipx', async (width) => {
    setViewport(width);
    vi.spyOn(api, 'status').mockResolvedValue({ initialized: false });
    const host = document.createElement('div');
    document.body.append(host);
    const root = createRoot(host);
    await act(async () => root.render(<App />));
    expect(host.querySelector('main')).toBeTruthy();
    expect(host.querySelector('form')).toBeTruthy();
    expect(host.querySelector('main')?.className).toContain('min-h-screen');
    root.unmount();
  });

  it.each([1280, 768, 390])('renders authenticated management actions in scroll containers at %ipx', async (width) => {
    setViewport(width);
    const host = document.createElement('div');
    document.body.append(host);
    const root = createRoot(host);
    await act(async () => root.render(<UsersSection user={admin} users={[admin, { ...admin, id: 2, email: 'operator@example.com', role: 'operator' }]} roles={[]} onChanged={vi.fn()} />));
    expect(host.querySelector('[data-testid="users-section"]')).toBeTruthy();
    expect(host.querySelector('.overflow-x-auto')).toBeTruthy();
    expect(host.querySelector('[data-testid="users-refresh"]')).toBeTruthy();
    expect(host.textContent).toContain('Create user');
    root.unmount();
  });

  it.each([
    ['id', 'Buat pengguna', 390],
    ['id', 'Buat pengguna', 768],
    ['id', 'Buat pengguna', 1280],
    ['ja', 'ユーザーを作成', 390],
    ['ja', 'ユーザーを作成', 768],
    ['ja', 'ユーザーを作成', 1280],
  ] as const)('keeps long %s management content inside the document at %ipx', async (locale, expectedCopy, width) => {
    setViewport(width);
    await initI18n(locale);
    const longEmail = 'administrator-for-a-very-long-localized-management-workflow@example.com';
    const host = document.createElement('div');
    document.body.append(host);
    const root = createRoot(host);
    await act(async () => root.render(<UsersSection user={admin} users={[admin, { ...admin, id: 2, email: longEmail, role: 'operator' }]} roles={[]} onChanged={vi.fn()} />));

    const section = host.querySelector('[data-testid="users-section"]') as HTMLElement;
    expect(section.textContent).toContain(longEmail);
    expect(section.textContent).toContain(expectedCopy);
    expect(section.className).toContain('min-w-0');
    expect(section.className).toContain('max-w-full');
    expect(section.querySelector('.overflow-x-auto')).toBeTruthy();
    // JSDOM intentionally reports zero layout dimensions; this is the
    // document-level no-overflow contract available without a browser engine.
    expect(document.documentElement.scrollWidth).toBe(0);
    expect(document.documentElement.clientWidth).toBe(0);
    root.unmount();
  });
});
