// @vitest-environment jsdom
// @vitest-environment-options {"url":"http://localhost/"}
import React from 'react';
import { act } from 'react';
import { createRoot } from 'react-dom/client';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { ThemeProvider, bootstrapTheme, readStoredTheme, useTheme } from './theme';

const KEY = 'bearust.theme.v1';

function Probe() {
  const theme = useTheme();
  return <output data-mode={theme.mode} data-resolved={theme.resolved} onClick={() => theme.setMode('dark')} />;
}

function installMediaQuery(matches: boolean) {
  let listener: ((event: MediaQueryListEvent) => void) | undefined;
  const query = {
    matches,
    media: '(prefers-color-scheme: dark)',
    addEventListener: vi.fn((_type: string, cb: (event: MediaQueryListEvent) => void) => { listener = cb; }),
    removeEventListener: vi.fn(),
    addListener: vi.fn(),
    removeListener: vi.fn(),
    dispatch(value: boolean) { (this as unknown as { matches: boolean }).matches = value; listener?.({ matches: value } as MediaQueryListEvent); },
  } as unknown as MediaQueryList & { dispatch: (value: boolean) => void };
  vi.stubGlobal('matchMedia', vi.fn(() => query));
  return query;
}

afterEach(() => {
  vi.unstubAllGlobals();
  document.documentElement.removeAttribute('data-theme');
});

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
});

describe('theme persistence and resolution', () => {
  it('defaults to system and resolves against the OS preference', () => {
    const query = installMediaQuery(true);
    expect(readStoredTheme()).toBe('system');
    bootstrapTheme();
    expect(document.documentElement.dataset.theme).toBe('dark');
    expect(query.matches).toBe(true);
  });

  it('accepts valid persisted values and falls back for invalid values', () => {
    localStorage.setItem(KEY, 'light');
    expect(readStoredTheme()).toBe('light');
    localStorage.setItem(KEY, 'neon');
    expect(readStoredTheme()).toBe('system');
  });

  it('persists mode changes and updates the document', () => {
    installMediaQuery(false);
    const container = document.createElement('div'); document.body.append(container);
    const root = createRoot(container);
    act(() => root.render(<ThemeProvider><Probe /></ThemeProvider>));
    const probe = document.querySelector('output')!;
    expect(probe.dataset.mode).toBe('system');
    expect(probe.dataset.resolved).toBe('light');
    act(() => probe.dispatchEvent(new MouseEvent('click', { bubbles: true })));
    expect(localStorage.getItem(KEY)).toBe('dark');
    expect(document.documentElement.dataset.theme).toBe('dark');
    root.unmount();
  });

  it('reacts to OS preference changes while in system mode', () => {
    const query = installMediaQuery(false);
    const container = document.createElement('div'); document.body.append(container);
    const root = createRoot(container);
    act(() => root.render(<ThemeProvider><Probe /></ThemeProvider>));
    expect(document.documentElement.dataset.theme).toBe('light');
    act(() => query.dispatch(true));
    expect(document.documentElement.dataset.theme).toBe('dark');
    root.unmount();
  });

  it('does not throw when storage is unavailable', () => {
    vi.spyOn(Storage.prototype, 'getItem').mockImplementation(() => { throw new Error('denied'); });
    vi.spyOn(Storage.prototype, 'setItem').mockImplementation(() => { throw new Error('denied'); });
    installMediaQuery(false);
    expect(() => bootstrapTheme()).not.toThrow();
    const container = document.createElement('div'); document.body.append(container);
    const root = createRoot(container);
    expect(() => act(() => root.render(<ThemeProvider><Probe /></ThemeProvider>))).not.toThrow();
    root.unmount();
  });
});
