export type Locale = 'en' | 'id' | 'ja';

export const SUPPORTED_LOCALES: readonly Locale[] = ['en', 'id', 'ja'];

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
