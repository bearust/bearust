// @vitest-environment jsdom
import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import App, { UsersSection } from './App';
import { api, type User } from './api';

const admin: User = { id: 1, email: 'admin@example.com', role: 'admin', disabled: false };

function setViewport(width: number) {
  Object.defineProperty(window, 'innerWidth', { configurable: true, value: width });
}

afterEach(() => {
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
});
