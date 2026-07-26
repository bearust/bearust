import type {
  ButtonHTMLAttributes,
  InputHTMLAttributes,
  ReactNode,
  SelectHTMLAttributes,
  TextareaHTMLAttributes,
} from "react";
import { useId } from "react";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { normalizeLocale, type Locale } from "./i18n";
import { useTheme, type ThemeMode } from "./theme";
import { api, type AdvisorInsight, type AdvisorWorkflow, type User } from "./api";

type ButtonVariant = "primary" | "secondary" | "danger";

const focusRing =
  "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus focus-visible:ring-offset-2 focus-visible:ring-offset-surface";

export function Button({
  variant = "primary",
  className = "",
  children,
  ...props
}: ButtonHTMLAttributes<HTMLButtonElement> & { variant?: ButtonVariant }) {
  const variants: Record<ButtonVariant, string> = {
    primary: "bg-action text-action-foreground hover:bg-action-hover",
    secondary:
      "border border-border bg-surface text-foreground hover:bg-surface-muted",
    danger: "bg-danger text-danger-foreground hover:bg-danger-hover",
  };
  return (
    <button
      type="button"
      className={`inline-flex min-h-11 min-w-11 items-center justify-center gap-2 rounded-md px-4 py-2 text-sm font-medium transition-colors disabled:cursor-not-allowed disabled:opacity-50 ${focusRing} ${variants[variant]} ${className}`}
      {...props}
    >
      {children}
    </button>
  );
}

export function Card({
  className = "",
  children,
  ...props
}: React.HTMLAttributes<HTMLElement> & { children: ReactNode }) {
  return (
    <section
      className={`min-w-0 max-w-full rounded-lg border border-border bg-surface p-6 text-foreground shadow-sm ${className}`}
      {...props}
    >
      {children}
    </section>
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
    <div className="space-y-2">
      <label
        htmlFor={inputId}
        className="block text-sm font-medium text-foreground"
      >
        {label}
      </label>
      <input
        {...props}
        id={inputId}
        aria-invalid={error ? true : props["aria-invalid"]}
        aria-describedby={describedBy}
        className={`min-h-11 w-full rounded-md border border-border bg-surface px-3 py-2 text-foreground placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus ${className}`}
      />
      {hint && (
        <p id={hintId} className="text-sm text-muted">
          {hint}
        </p>
      )}
      {error && (
        <p id={errorId} className="text-sm text-danger-foreground" role="alert">
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
    <div className="space-y-2">
      <label
        htmlFor={selectId}
        className="block text-sm font-medium text-foreground"
      >
        {label}
      </label>
      <select
        {...props}
        id={selectId}
        aria-describedby={hintId}
        className={`min-h-11 w-full rounded-md border border-border bg-surface px-3 py-2 text-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus ${className}`}
      >
        {children}
      </select>
      {hint && (
        <p id={hintId} className="text-sm text-muted">
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
    <div className="space-y-2">
      <label
        htmlFor={textareaId}
        className="block text-sm font-medium text-foreground"
      >
        {label}
      </label>
      <textarea
        {...props}
        id={textareaId}
        className={`min-h-11 w-full rounded-md border border-border bg-surface px-3 py-2 text-foreground placeholder:text-muted focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-focus ${className}`}
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
  return (
    <div
      role={variant === "danger" ? "alert" : "status"}
      aria-live={variant === "danger" ? "assertive" : "polite"}
      className={`rounded-md border p-4 ${variants[variant]} ${className}`}
      {...props}
    >
      {title && <p className="mb-1 font-semibold">{title}</p>}
      <div>{children}</div>
    </div>
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
    <label className="inline-flex min-h-11 items-center gap-2 text-sm text-foreground">
      <span>{t("theme.label")}</span>
      <select
        {...props}
        aria-label={props["aria-label"] ?? t("theme.label")}
        value={mode}
        onChange={handleChange}
        className={`min-h-11 rounded-md border border-border bg-surface px-3 py-2 text-foreground ${focusRing} ${className}`}
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
    <label className="inline-flex min-h-11 items-center gap-2 text-sm text-foreground">
      <span>{label}</span>
      <select
        aria-label={label}
        value={value}
        onChange={(event) =>
          onChange(normalizeLocale(event.currentTarget.value))
        }
        className={`min-h-11 rounded-md border border-border bg-surface px-3 py-2 text-foreground ${focusRing}`}
      >
        <option value="en">{t("language.options.en")}</option>
        <option value="id">{t("language.options.id")}</option>
        <option value="ja">{t("language.options.ja")}</option>
      </select>
    </label>
  );
}

export function AiAdvisorSection({ user, onChanged }: { user: User; onChanged?: () => void }) {
  const { t } = useTranslation();
  const [enabled, setEnabled] = useState<boolean | null>(null);
  const [items, setItems] = useState<AdvisorInsight[]>([]);
  const [workflow, setWorkflow] = useState<AdvisorWorkflow>("incident_explanation");
  const [command, setCommand] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const load = async () => {
    try {
      const page = await api.listAiInsights({ page: 1, page_size: 20 });
      setItems(page.items);
    } catch (e) {
      setError((e as { code?: string }).code ?? "advisorError");
    }
  };
  useEffect(() => {
    let active = true;
    api.aiAdvisorStatus().then((status) => { if (active) { setEnabled(status.enabled); if (status.enabled) void load(); } }).catch(() => { if (active) setEnabled(false); });
    return () => { active = false; };
  }, []);
  if (enabled !== true) return null;
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setLoading(true); setError("");
    try { await api.startAiAnalysis({ workflow, ...(command ? { command } : {}) }); await load(); onChanged?.(); }
    catch (e) { setError((e as { code?: string }).code ?? "advisorError"); }
    finally { setLoading(false); }
  };
  const decide = async (item: AdvisorInsight, decision: "approve" | "reject") => {
    setLoading(true); setError("");
    try { if (decision === "approve") await api.approveAiDraft(item.job_id); else await api.rejectAiDraft(item.job_id); await load(); onChanged?.(); }
    catch (e) { setError((e as { code?: string }).code ?? "advisorError"); }
    finally { setLoading(false); }
  };
  return <Card data-testid="ai-advisor-section">
    <div className="mb-4 flex flex-wrap items-center justify-between gap-3"><h2 className="text-xl font-semibold">{t("advisor.title")}</h2>{user.role === "admin" && <Button variant="secondary" onClick={() => void load()} disabled={loading}>{t("advisor.refresh")}</Button>}</div>
    <form className="mb-6 grid gap-4 sm:grid-cols-[1fr_2fr_auto] sm:items-end" onSubmit={submit}>
      <SelectField label={t("advisor.workflow")} value={workflow} onChange={(e) => setWorkflow(e.target.value as AdvisorWorkflow)}><option value="incident_explanation">{t("advisor.workflows.incident_explanation")}</option><option value="security_summary">{t("advisor.workflows.security_summary")}</option><option value="rule_tuning">{t("advisor.workflows.rule_tuning")}</option><option value="configuration_draft">{t("advisor.workflows.configuration_draft")}</option></SelectField>
      <TextareaField label={t("advisor.command")} value={command} onChange={(e) => setCommand(e.target.value)} rows={2} />
      <Button type="submit" disabled={loading}>{loading ? t("advisor.loading") : t("advisor.start")}</Button>
    </form>
    {error && <Alert variant="danger">{t(`advisor.errors.${error}`, { defaultValue: t("advisor.errors.generic") })}</Alert>}
    {items.length === 0 ? <p className="text-muted">{t("advisor.empty")}</p> : <div className="space-y-3">{items.map((item) => <article className="rounded-md border border-border p-4" key={item.job_id}><div className="flex flex-wrap justify-between gap-2"><strong>{t(`advisor.workflows.${item.workflow}`, { defaultValue: item.workflow })}</strong><span>{t(`advisor.status.${item.status}`, { defaultValue: item.status })}</span></div>{item.redacted_result?.summary && <p className="mt-2">{item.redacted_result.summary}</p>}{item.redacted_result && <pre className="mt-2 max-w-full overflow-auto text-xs text-muted">{JSON.stringify(item.redacted_result, null, 2)}</pre>}{user.role === "admin" && item.workflow === "configuration_draft" && item.status === "completed" && <div className="mt-3 flex gap-2"><Button onClick={() => void decide(item, "approve")} disabled={loading}>{t("advisor.approve")}</Button><Button variant="danger" onClick={() => void decide(item, "reject")} disabled={loading}>{t("advisor.reject")}</Button></div>}</article>)}</div>}
  </Card>;
}
