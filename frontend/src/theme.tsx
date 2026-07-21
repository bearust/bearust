import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';

export type ThemeMode = 'system' | 'light' | 'dark';
export type ResolvedTheme = 'light' | 'dark';
export type ThemeContextValue = { mode: ThemeMode; resolved: ResolvedTheme; setMode: (mode: ThemeMode) => void };

export const THEME_STORAGE_KEY = 'bearust.theme.v1';
const MEDIA_QUERY = '(prefers-color-scheme: dark)';

function validMode(value: string | null): value is ThemeMode {
  return value === 'system' || value === 'light' || value === 'dark';
}

export function readStoredTheme(): ThemeMode {
  try {
    const value = window.localStorage.getItem(THEME_STORAGE_KEY);
    return validMode(value) ? value : 'system';
  } catch {
    return 'system';
  }
}

function prefersDark(): boolean {
  return typeof window !== 'undefined' && typeof window.matchMedia === 'function' && window.matchMedia(MEDIA_QUERY).matches;
}

function resolve(mode: ThemeMode): ResolvedTheme {
  return mode === 'system' ? (prefersDark() ? 'dark' : 'light') : mode;
}

export function bootstrapTheme(): ResolvedTheme {
  const resolved = resolve(readStoredTheme());
  if (typeof document !== 'undefined') document.documentElement.dataset.theme = resolved;
  return resolved;
}

const ThemeContext = createContext<ThemeContextValue | null>(null);

export function ThemeProvider({ children }: { children: ReactNode }) {
  const [mode, setModeState] = useState<ThemeMode>(() => readStoredTheme());
  const [resolved, setResolved] = useState<ResolvedTheme>(() => resolve(mode));

  useEffect(() => {
    const update = () => setResolved(resolve(mode));
    update();
    if (typeof document !== 'undefined') document.documentElement.dataset.theme = resolve(mode);
    if (mode !== 'system' || typeof window.matchMedia !== 'function') return;
    const query = window.matchMedia(MEDIA_QUERY);
    const onChange = (event: MediaQueryListEvent) => {
      const next = event.matches ? 'dark' : 'light';
      setResolved(next);
      document.documentElement.dataset.theme = next;
    };
    query.addEventListener?.('change', onChange);
    return () => query.removeEventListener?.('change', onChange);
  }, [mode]);

  const setMode = (next: ThemeMode) => {
    setModeState(next);
    try { window.localStorage.setItem(THEME_STORAGE_KEY, next); } catch { /* storage is optional */ }
  };
  const value = useMemo(() => ({ mode, resolved, setMode }), [mode, resolved]);
  return <ThemeContext.Provider value={value}>{children}</ThemeContext.Provider>;
}

export function useTheme(): ThemeContextValue {
  const value = useContext(ThemeContext);
  if (!value) throw new Error('useTheme must be used within ThemeProvider');
  return value;
}
