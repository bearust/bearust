import { createContext, createElement, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import i18next from 'i18next';
import { initReactI18next } from 'react-i18next';
import { api } from './api';
import en from './locales/en.json';
import id from './locales/id.json';
import ja from './locales/ja.json';

export type Locale = 'en' | 'id' | 'ja';

export const SUPPORTED_LOCALES: readonly Locale[] = ['en', 'id', 'ja'];
export const LOCALE_STORAGE_KEY = 'bearust.locale.v1';

export const i18n = i18next.createInstance();

function missingTranslationFallback() {
  return i18n.t('errors.generic', { defaultValue: en.errors.generic });
}

function reportMissingTranslation(languages: readonly string[], namespace: string, key: string) {
  if (import.meta.env.DEV || import.meta.env.MODE === 'test') {
    console.warn(`Missing translation: ${languages.join(',')}:${namespace}:${key}`);
  }
}

const LOCALE_TAGS: Record<Locale, string> = {
  en: 'en-US',
  id: 'id-ID',
  ja: 'ja-JP',
};

function supportedLocale(value: unknown): Locale | undefined {
  if (typeof value !== 'string') return undefined;

  try {
    const [tag] = Intl.getCanonicalLocales(value.trim().replaceAll('_', '-'));
    const language = tag.split('-', 1)[0].toLowerCase();
    return SUPPORTED_LOCALES.find((locale) => locale === language);
  } catch {
    return undefined;
  }
}

function preferenceLocale(value: unknown): Locale | undefined {
  if (Array.isArray(value)) {
    for (const candidate of value) {
      const locale = preferenceLocale(candidate);
      if (locale) return locale;
    }
    return undefined;
  }

  const direct = supportedLocale(value);
  if (direct) return direct;

  if (value && typeof value === 'object' && 'locale' in value) {
    return supportedLocale(value.locale);
  }

  if (value && typeof value === 'object' && 'languages' in value) {
    return preferenceLocale(value.languages);
  }

  return undefined;
}

export function normalizeLocale(value: unknown): Locale {
  return supportedLocale(value) ?? 'en';
}

export function localeFromPreferences(account: unknown, stored: unknown, browser: unknown): Locale {
  return preferenceLocale(account) ?? preferenceLocale(stored) ?? preferenceLocale(browser) ?? 'en';
}

export function readStoredLocale(): Locale | undefined {
  try {
    const value = window.localStorage.getItem(LOCALE_STORAGE_KEY);
    return value === null ? undefined : normalizeLocale(value);
  } catch {
    return undefined;
  }
}

export function preferredBrowserLocale(): Locale {
  return localeFromPreferences(
    null,
    readStoredLocale(),
    typeof navigator === 'undefined' ? null : navigator.languages,
  );
}

export function preferredLocale(account: unknown): Locale {
  return localeFromPreferences(
    account,
    readStoredLocale(),
    typeof navigator === 'undefined' ? null : navigator.languages,
  );
}

export function initI18n(locale = preferredBrowserLocale()) {
  const language = normalizeLocale(locale);
  if (i18n.isInitialized) return i18n.changeLanguage(language);
  return i18n.use(initReactI18next).init({
    resources: { en: { translation: en }, id: { translation: id }, ja: { translation: ja } },
    lng: language,
    fallbackLng: 'en',
    returnNull: false,
    returnEmptyString: false,
    saveMissing: true,
    missingKeyHandler: reportMissingTranslation,
    parseMissingKeyHandler: missingTranslationFallback,
    interpolation: { escapeValue: false },
  });
}

async function changeI18nLocale(locale: Locale) {
  try {
    await i18n.changeLanguage(locale);
  } catch {
    // The static catalogs can still fall back when initialization is unavailable.
  }
}

type LocalePreferenceValue = { locale: Locale; setLocale: (locale: Locale) => Promise<void> };
const LocalePreferenceContext = createContext<LocalePreferenceValue | null>(null);

export function LocalePreferenceProvider({ accountLocale, children }: { accountLocale?: unknown; children: ReactNode }) {
  const [locale, setLocaleState] = useState<Locale>(() => preferredLocale(accountLocale));
  useEffect(() => {
    const nextLocale = preferredLocale(accountLocale);
    setLocaleState(nextLocale);
    void changeI18nLocale(nextLocale);
  }, [accountLocale]);
  const setLocale = async (next: Locale) => {
    const normalized = normalizeLocale(next);
    setLocaleState(normalized);
    await changeI18nLocale(normalized);
    try { window.localStorage.setItem(LOCALE_STORAGE_KEY, normalized); } catch { /* storage is optional */ }
    try { await api.updateLocalePreference(normalized); } catch { /* local preference remains available offline */ }
  };
  const value = useMemo(() => ({ locale, setLocale }), [locale]);
  return createElement(LocalePreferenceContext.Provider, { value }, children);
}

export function useLocalePreference(): LocalePreferenceValue {
  const value = useContext(LocalePreferenceContext);
  if (!value) throw new Error('useLocalePreference must be used within LocalePreferenceProvider');
  return value;
}

export const displayDateTimeOptions = {
  dateStyle: 'medium',
  timeStyle: 'short',
} satisfies Intl.DateTimeFormatOptions;

export function formatLocaleDate(
  value: string | number | Date,
  locale: Locale,
  options?: Intl.DateTimeFormatOptions,
): string {
  return new Intl.DateTimeFormat(LOCALE_TAGS[locale], options).format(new Date(value));
}

export function formatLocaleNumber(
  value: number,
  locale: Locale,
  options?: Intl.NumberFormatOptions,
): string {
  return new Intl.NumberFormat(LOCALE_TAGS[locale], options).format(value);
}

export function useLocaleFormatters() {
  const preference = useContext(LocalePreferenceContext);
  const locale = preference?.locale ?? normalizeLocale(i18n.resolvedLanguage ?? i18n.language);
  return useMemo(() => ({
    locale,
    formatDate: (value: string | number | Date, options = displayDateTimeOptions) =>
      formatLocaleDate(value, locale, options),
    formatNumber: (value: number, options?: Intl.NumberFormatOptions) =>
      formatLocaleNumber(value, locale, options),
  }), [locale]);
}
