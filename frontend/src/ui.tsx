import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from 'react';
import { useId } from 'react';
import { useTranslation } from 'react-i18next';
import { normalizeLocale, type Locale } from './i18n';
import { useTheme, type ThemeMode } from './theme';

type ButtonVariant = 'primary' | 'secondary' | 'danger';

const focusRing = 'focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-surface';

export function Button({ variant = 'primary', className = '', children, ...props }: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  const variants: Record<ButtonVariant, string> = {
    primary: 'bg-action text-action-foreground hover:bg-action-hover',
    secondary: 'border border-border bg-surface text-foreground hover:bg-surface-muted',
    danger: 'bg-danger text-danger-foreground hover:bg-danger-hover',
  };
  return <button type="button" className={`inline-flex min-h-11 min-w-11 items-center justify-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${focusRing} ${variants[variant]} ${className}`} {...props}>{children}</button>;
}

export function Card({ className = '', children, ...props }: React.HTMLAttributes<HTMLElement> & { children: ReactNode }) {
  return <section className={`rounded-lg border border-border bg-surface p-6 text-foreground shadow-sm ${className}`} {...props}>{children}</section>;
}

type FieldProps = Omit<InputHTMLAttributes<HTMLInputElement>, 'id'> & { label: ReactNode; id?: string; error?: ReactNode; hint?: ReactNode };

export function Field({ label, id, error, hint, className = '', ...props }: FieldProps) {
  const generatedId = useId();
  const inputId = id ?? `field-${generatedId.replace(/:/g, '')}`;
  const hintId = hint ? `${inputId}-hint` : undefined;
  const errorId = error ? `${inputId}-error` : undefined;
  const describedBy = [hintId, errorId, props['aria-describedby']].filter(Boolean).join(' ') || undefined;
  return <div className="space-y-2">
    <label htmlFor={inputId} className="block text-sm font-medium text-foreground">{label}</label>
    <input {...props} id={inputId} aria-invalid={error ? true : props['aria-invalid']} aria-describedby={describedBy} className={`min-h-11 w-full rounded-md border border-border bg-surface px-3 py-2 text-foreground placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus ${className}`} />
    {hint && <p id={hintId} className="text-sm text-muted">{hint}</p>}
    {error && <p id={errorId} className="text-sm text-danger-foreground" role="alert">{error}</p>}
  </div>;
}

type SelectFieldProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, 'id'> & { label: ReactNode; id?: string; hint?: ReactNode };

export function SelectField({ label, id, hint, className = '', children, ...props }: SelectFieldProps) {
  const generatedId = useId();
  const selectId = id ?? `select-${generatedId.replace(/:/g, '')}`;
  const hintId = hint ? `${selectId}-hint` : undefined;
  return <div className="space-y-2">
    <label htmlFor={selectId} className="block text-sm font-medium text-foreground">{label}</label>
    <select {...props} id={selectId} aria-describedby={hintId} className={`min-h-11 w-full rounded-md border border-border bg-surface px-3 py-2 text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus ${className}`}>
      {children}
    </select>
    {hint && <p id={hintId} className="text-sm text-muted">{hint}</p>}
  </div>;
}

type TextareaFieldProps = Omit<TextareaHTMLAttributes<HTMLTextAreaElement>, 'id'> & { label: ReactNode; id?: string };

export function TextareaField({ label, id, className = '', ...props }: TextareaFieldProps) {
  const generatedId = useId();
  const textareaId = id ?? `textarea-${generatedId.replace(/:/g, '')}`;
  return <div className="space-y-2">
    <label htmlFor={textareaId} className="block text-sm font-medium text-foreground">{label}</label>
    <textarea {...props} id={textareaId} className={`min-h-11 w-full rounded-md border border-border bg-surface px-3 py-2 text-foreground placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus ${className}`} />
  </div>;
}

type AlertVariant = 'info' | 'success' | 'warning' | 'danger';

export function Alert({ variant = 'info', title, children, className = '', ...props }: React.HTMLAttributes<HTMLDivElement> & { variant?: AlertVariant; title?: ReactNode; children: ReactNode }) {
  const variants: Record<AlertVariant, string> = {
    info: 'border-info-border bg-info-surface text-info-foreground',
    success: 'border-success-border bg-success-surface text-success-foreground',
    warning: 'border-warning-border bg-warning-surface text-warning-foreground',
    danger: 'border-danger-border bg-danger-surface text-danger-foreground',
  };
  return <div role={variant === 'danger' ? 'alert' : 'status'} aria-live={variant === 'danger' ? 'assertive' : 'polite'} className={`rounded-md border p-4 ${variants[variant]} ${className}`} {...props}>
    {title && <p className="mb-1 font-semibold">{title}</p>}
    <div>{children}</div>
  </div>;
}

export function ThemeSelect({ className = '', ...props }: SelectHTMLAttributes<HTMLSelectElement>) {
  const { mode, setMode } = useTheme();
  const handleChange: SelectHTMLAttributes<HTMLSelectElement>['onChange'] = (event) => {
    setMode(event.target.value as ThemeMode);
    props.onChange?.(event);
  };
  return <label className="inline-flex min-h-11 items-center gap-2 text-sm text-foreground">
    <span>Theme</span>
    <select {...props} aria-label={props['aria-label'] ?? 'Theme'} value={mode} onChange={handleChange} className={`min-h-11 rounded-md border border-border bg-surface px-3 py-2 text-foreground ${focusRing} ${className}`}>
      <option value="system">System</option>
      <option value="light">Light</option>
      <option value="dark">Dark</option>
    </select>
  </label>;
}

export function LanguageSelect({ value, onChange }: { value: Locale; onChange: (locale: Locale) => void }) {
  const { t } = useTranslation();
  const label = t('language.label');
  return <label className="inline-flex min-h-11 items-center gap-2 text-sm text-foreground">
    <span>{label}</span>
    <select aria-label={label} value={value} onChange={(event) => onChange(normalizeLocale(event.currentTarget.value))} className={`min-h-11 rounded-md border border-border bg-surface px-3 py-2 text-foreground ${focusRing}`}>
      <option value="en">{t('language.options.en')}</option>
      <option value="id">{t('language.options.id')}</option>
      <option value="ja">{t('language.options.ja')}</option>
    </select>
  </label>;
}
