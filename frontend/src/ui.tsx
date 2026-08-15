import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";
import { useEffect, useId, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { normalizeLocale, type Locale } from "./i18n";
import { useTheme, type ThemeMode } from "./theme";

type ButtonVariant = "primary" | "secondary" | "danger";

const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-page";

/**
 * Material's three button kinds: `primary` is contained (filled amber,
 * elevated), `secondary` is outlined, `danger` is an outlined error
 * button so a destructive action reads as available, not alarming,
 * until pressed. Elevation rises on hover and settles on press --
 * Material's own affordance in place of a ripple.
 */
export function Button({
  variant = "primary",
  className = "",
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  const variants: Record<ButtonVariant, string> = {
    primary:
      "border border-action bg-action text-action-foreground shadow-[var(--shadow-1)] hover:bg-action-hover hover:border-action-hover hover:shadow-[var(--shadow-2)]",
    secondary:
      "border border-border-strong bg-transparent text-foreground hover:bg-surface-muted hover:border-legacy-muted",
    danger:
      "border border-danger bg-transparent text-danger hover:bg-danger-surface",
  };
  return (
    <button
      type="button"
      className={`inline-flex min-h-11 min-w-11 items-center justify-center gap-2 rounded-[var(--radius-control)] px-4 py-2 font-body text-sm font-medium transition-[background-color,border-color,box-shadow,transform] active:scale-[0.98] disabled:cursor-not-allowed disabled:opacity-40 disabled:active:scale-100 ${focusRing} ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

/**
 * A Material elevated card: a tonal paper surface raised off the page
 * with a soft shadow and rounded corners -- never a flat hairline
 * bezel. `label` renders as a card-header title (sentence case, medium
 * weight) with `actions` (a status chip, a refresh button) right-
 * aligned in the same strip.
 */
export function Panel({
  label,
  actions,
  className = "",
  children,
  ...props
}: React.HTMLAttributes<HTMLElement> & {
  label?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section
      className={`min-w-0 max-w-full rounded-[var(--radius-card)] border border-border bg-surface text-foreground shadow-[var(--shadow-1)] ${className}`}
      {...props}
    >
      {label && (
        <div className="flex items-center justify-between gap-3 border-b border-border px-5 py-4">
          <h2 className="text-sm font-medium text-foreground">{label}</h2>
          {actions && <div className="flex items-center gap-2">{actions}</div>}
        </div>
      )}
      <div className="p-5">{children}</div>
    </section>
  );
}

/** @deprecated use {@link Panel} -- kept as an alias during the redesign migration. */
export const Card = Panel;

type StatusTone = "success" | "warning" | "danger" | "info" | "neutral";

/**
 * A small flat status dot -- never a glowing halo (a zero-offset
 * colored glow is decoration, not depth). Always paired with a label
 * so color is never the only signal; see {@link StatusBadge}.
 */
export function StatusLamp({
  tone,
  className = "",
}: {
  tone: StatusTone;
  className?: string;
}) {
  const tones: Record<StatusTone, string> = {
    success: "bg-success",
    warning: "bg-warning",
    danger: "bg-danger",
    info: "bg-info",
    neutral: "bg-legacy-muted",
  };
  return (
    <span
      aria-hidden="true"
      className={`inline-block h-2 w-2 shrink-0 rounded-full ${tones[tone]} ${className}`}
    />
  );
}

/** A Material filled tonal chip: a status lamp plus its own label. */
export function StatusBadge({
  tone,
  children,
}: {
  tone: StatusTone;
  children: ReactNode;
}) {
  const chip: Record<StatusTone, string> = {
    success: "bg-success-surface text-success-foreground",
    warning: "bg-warning-surface text-warning-foreground",
    danger: "bg-danger-surface text-danger-foreground",
    info: "bg-info-surface text-info-foreground",
    neutral: "bg-surface-muted text-legacy-muted",
  };
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-full px-2.5 py-1 text-xs font-medium ${chip[tone]}`}
    >
      <StatusLamp tone={tone} />
      {children}
    </span>
  );
}

type FieldProps = Omit<InputHTMLAttributes<HTMLInputElement>, "id"> & {
  label: ReactNode;
  id?: string;
  error?: ReactNode;
  hint?: ReactNode;
};

export function Field({
  label,
  id,
  error,
  hint,
  className = "",
  ...props
}: FieldProps) {
  const generatedId = useId();
  const inputId = id ?? `field-${generatedId.replace(/:/g, "")}`;
  const hintId = hint ? `${inputId}-hint` : undefined;
  const errorId = error ? `${inputId}-error` : undefined;
  const describedBy =
    [hintId, errorId, props["aria-describedby"]].filter(Boolean).join(" ") ||
    undefined;
  return (
    <div className="space-y-1.5">
      <label htmlFor={inputId} className="block text-xs font-medium text-legacy-muted">
        {label}
      </label>
      <input
        {...props}
        id={inputId}
        aria-invalid={error ? true : props["aria-invalid"]}
        aria-describedby={describedBy}
        className={`min-h-11 w-full rounded-[var(--radius-control)] border border-border-strong bg-page px-3 py-2 text-foreground placeholder:text-legacy-muted transition-colors hover:border-legacy-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:border-focus ${className}`}
      />
      {hint && (
        <p id={hintId} className="text-sm text-legacy-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} className="text-sm text-danger" role="alert">
          {error}
        </p>
      )}
    </div>
  );
}

type SelectFieldProps = Omit<SelectHTMLAttributes<HTMLSelectElement>, "id"> & {
  label: ReactNode;
  id?: string;
  hint?: ReactNode;
};

export function SelectField({
  label,
  id,
  hint,
  className = "",
  children,
  ...props
}: SelectFieldProps) {
  const generatedId = useId();
  const selectId = id ?? `select-${generatedId.replace(/:/g, "")}`;
  const hintId = hint ? `${selectId}-hint` : undefined;
  return (
    <div className="space-y-1.5">
      <label htmlFor={selectId} className="block text-xs font-medium text-legacy-muted">
        {label}
      </label>
      <select
        {...props}
        id={selectId}
        aria-describedby={hintId}
        className={`min-h-11 w-full rounded-[var(--radius-control)] border border-border-strong bg-page px-3 py-2 text-foreground transition-colors hover:border-legacy-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:border-focus ${className}`}
      >
        {children}
      </select>
      {hint && (
        <p id={hintId} className="text-sm text-legacy-muted">
          {hint}
        </p>
      )}
    </div>
  );
}

type TextareaFieldProps = Omit<
  TextareaHTMLAttributes<HTMLTextAreaElement>,
  "id"
> & { label: ReactNode; id?: string };

export function TextareaField({
  label,
  id,
  className = "",
  ...props
}: TextareaFieldProps) {
  const generatedId = useId();
  const textareaId = id ?? `textarea-${generatedId.replace(/:/g, "")}`;
  return (
    <div className="space-y-1.5">
      <label
        htmlFor={textareaId}
        className="block text-xs font-medium text-legacy-muted"
      >
        {label}
      </label>
      <textarea
        {...props}
        id={textareaId}
        className={`min-h-11 w-full rounded-[var(--radius-control)] border border-border-strong bg-page px-3 py-2 font-mono text-foreground placeholder:text-legacy-muted transition-colors hover:border-legacy-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:border-focus ${className}`}
      />
    </div>
  );
}

type AlertVariant = "info" | "success" | "warning" | "danger";

export function Alert({
  variant = "info",
  title,
  children,
  className = "",
  ...props
}: React.HTMLAttributes<HTMLDivElement> & {
  variant?: AlertVariant;
  title?: ReactNode;
  children: ReactNode;
}) {
  const variants: Record<AlertVariant, string> = {
    info: "border-info-border bg-info-surface text-info-foreground",
    success: "border-success-border bg-success-surface text-success-foreground",
    warning: "border-warning-border bg-warning-surface text-warning-foreground",
    danger: "border-danger-border bg-danger-surface text-danger-foreground",
  };
  const tones: Record<AlertVariant, StatusTone> = {
    info: "info",
    success: "success",
    warning: "warning",
    danger: "danger",
  };
  return (
    <div
      role={variant === "danger" ? "alert" : "status"}
      aria-live={variant === "danger" ? "assertive" : "polite"}
      className={`rounded-[var(--radius-card)] border p-4 ${variants[variant]} ${className}`}
      {...props}
    >
      {title && (
        <p className="mb-1 flex items-center gap-2 text-sm font-medium">
          <StatusLamp tone={tones[variant]} />
          {title}
        </p>
      )}
      <div className="text-sm">{children}</div>
    </div>
  );
}

/**
 * A trigger button that opens an anchored flyout panel -- the navbar's
 * account menu, and any future action menu. Closes on outside click,
 * Escape, or an item selection; the trigger owns `aria-haspopup`/
 * `aria-expanded`, the panel carries `role="menu"`.
 */
export function Menu({
  trigger,
  align = "end",
  children,
}: {
  trigger: (props: {
    onClick: () => void;
    "aria-haspopup": "menu";
    "aria-expanded": boolean;
  }) => ReactNode;
  align?: "start" | "end";
  children: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const rootRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onPointerDown = (event: MouseEvent) => {
      if (!rootRef.current?.contains(event.target as Node)) setOpen(false);
    };
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onPointerDown);
    document.addEventListener("keydown", onKeyDown);
    return () => {
      document.removeEventListener("mousedown", onPointerDown);
      document.removeEventListener("keydown", onKeyDown);
    };
  }, [open]);

  return (
    <div className="relative inline-block" ref={rootRef}>
      {trigger({
        onClick: () => setOpen((value) => !value),
        "aria-haspopup": "menu",
        "aria-expanded": open,
      })}
      {open && (
        <div
          role="menu"
          onClick={() => setOpen(false)}
          className={`absolute top-full z-30 mt-2 min-w-56 rounded-[var(--radius-card)] border border-border bg-surface py-1.5 shadow-[var(--shadow-2)] ${align === "end" ? "right-0" : "left-0"}`}
        >
          {children}
        </div>
      )}
    </div>
  );
}

export function MenuItem({
  className = "",
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement>) {
  return (
    <button
      type="button"
      role="menuitem"
      className={`flex min-h-10 w-full items-center gap-2.5 px-4 py-2 text-left text-sm text-foreground hover:bg-surface-muted focus-visible:outline-none focus-visible:bg-surface-muted ${className}`}
      {...props}
    />
  );
}

export function ThemeSelect({
  className = "",
  ...props
}: SelectHTMLAttributes<HTMLSelectElement>) {
  const { mode, setMode } = useTheme();
  const { t } = useTranslation();
  const handleChange: SelectHTMLAttributes<HTMLSelectElement>["onChange"] = (
    event,
  ) => {
    setMode(event.target.value as ThemeMode);
    props.onChange?.(event);
  };
  return (
    <label className="inline-flex min-h-11 items-center gap-2 text-xs text-legacy-muted">
      <span>{t("theme.label")}</span>
      <select
        {...props}
        aria-label={props["aria-label"] ?? t("theme.label")}
        value={mode}
        onChange={handleChange}
        className={`min-h-11 rounded-[var(--radius-control)] border border-border-strong bg-page px-3 py-2 text-foreground ${focusRing} ${className}`}
      >
        <option value="system">{t("theme.system")}</option>
        <option value="light">{t("theme.light")}</option>
        <option value="dark">{t("theme.dark")}</option>
      </select>
    </label>
  );
}

export function LanguageSelect({
  value,
  onChange,
}: {
  value: Locale;
  onChange: (locale: Locale) => void;
}) {
  const { t } = useTranslation();
  const label = t("language.label");
  return (
    <label className="inline-flex min-h-11 items-center gap-2 text-xs text-legacy-muted">
      <span>{label}</span>
      <select
        aria-label={label}
        value={value}
        onChange={(event) =>
          onChange(normalizeLocale(event.currentTarget.value))
        }
        className={`min-h-11 rounded-[var(--radius-control)] border border-border-strong bg-page px-3 py-2 text-foreground ${focusRing}`}
      >
        <option value="en">{t("language.options.en")}</option>
        <option value="id">{t("language.options.id")}</option>
        <option value="ja">{t("language.options.ja")}</option>
      </select>
    </label>
  );
}
