import { useCallback, useEffect, useRef, useState, type FormEvent } from "react";
import { useTranslation } from "react-i18next";
import { api, type AdvisorInsight, type AdvisorJobStatus, type AdvisorResult, type AdvisorWorkflow, type User } from "./api";
import { Alert, Button, Panel, SelectField, StatusBadge, TextareaField } from "./ui";

const TERMINAL = new Set<AdvisorJobStatus>(["completed", "failed", "approved", "rejected", "expired"]);
const SAFE_ERRORS = new Set(["advisor_disabled", "advisor_busy", "advisor_timeout", "advisor_provider_unavailable", "advisor_invalid_response", "advisor_response_too_large", "advisor_circuit_open", "advisor_invalid_request", "advisor_stale_draft", "advisor_expired"]);
const POLL_INTERVAL_MS = 1000;
const MAX_POLLS = 360;
function safeError(error: unknown) { const code = error && typeof error === "object" && "code" in error ? (error as { code?: unknown }).code : undefined; return typeof code === "string" && SAFE_ERRORS.has(code) ? code : "generic"; }
function isInsight(result: AdvisorResult | null): result is Exclude<AdvisorResult, { workflow: "configuration_draft" }> { return !!result && result.workflow !== "configuration_draft" && typeof result.summary === "string" && Array.isArray(result.signals) && Array.isArray(result.reason_ids) && typeof result.score === "number"; }
function isDraft(result: AdvisorResult | null): result is Extract<AdvisorResult, { workflow: "configuration_draft" }> { return !!result && result.workflow === "configuration_draft" && result.action === "set_waf_mode" && (result.mode === "monitor-only" || result.mode === "block") && typeof result.summary === "string"; }

function ResultView({ item }: { item: AdvisorInsight }) {
  const { t } = useTranslation(); const result = item.redacted_result;
  if (isDraft(result)) return <div className="mt-2 space-y-1"><p>{result.summary}</p><dl className="grid grid-cols-2 gap-x-3 text-sm"><dt>{t("advisor.diff.from")}</dt><dd>{t("advisor.diff.redacted")}</dd><dt>{t("advisor.diff.to")}</dt><dd>{t("advisor.diff.modes." + result.mode)}</dd></dl></div>;
  if (isInsight(result)) return <div className="mt-2 space-y-1"><p>{result.summary}</p><p className="text-sm">{t("advisor.result.severity")}: {t("advisor.severities." + result.severity)} · {t("advisor.result.score")}: {result.score}</p><p className="text-sm">{t("advisor.result.signals")}: {result.signals.join(", ")}</p></div>;
  return <p className="mt-2 text-sm text-muted">{t("advisor.result.unavailable")}</p>;
}

export function AiAdvisorSection({ user, onChanged, refreshToken = 0 }: { user: User; onChanged?: () => void; refreshToken?: number }) {
  const { t } = useTranslation(); const [enabled, setEnabled] = useState<boolean | null>(null); const [items, setItems] = useState<AdvisorInsight[]>([]); const [workflow, setWorkflow] = useState<AdvisorWorkflow>("incident_explanation"); const [command, setCommand] = useState(""); const [loading, setLoading] = useState(false); const [error, setError] = useState(""); const pollBudget = useRef({ jobs: "", count: 0 }); const blockedDrafts = useRef(new Set<string>());
  const load = useCallback(async () => { try { const page = await api.listAiInsights({ page: 1, page_size: 20 }); const visible = page.items.filter((item) => !blockedDrafts.current.has(item.job_id)); setItems(visible as AdvisorInsight[]); setError(""); return visible; } catch (e) { setError(safeError(e)); return []; } }, []);
  useEffect(() => { let active = true; api.aiAdvisorStatus().then((status) => { if (active) { setEnabled(status.enabled); if (status.enabled) void load(); } }).catch((e) => { if (active) { setEnabled(null); setError(safeError(e)); } }); return () => { active = false; }; }, [load]);
  useEffect(() => { if (enabled) void load(); }, [refreshToken, enabled, load]);
  useEffect(() => { const jobs = items.filter((item) => !TERMINAL.has(item.status)).map((item) => item.job_id).sort().join(","); if (!jobs) { pollBudget.current = { jobs: "", count: 0 }; return; } if (pollBudget.current.jobs !== jobs) pollBudget.current = { jobs, count: 0 }; if (pollBudget.current.count >= MAX_POLLS) return; const timer = setTimeout(async () => { pollBudget.current.count += 1; await load(); }, POLL_INTERVAL_MS); return () => clearTimeout(timer); }, [items, load]);
  if (enabled === false) return null; if (enabled !== true) return error ? <Alert variant="danger">{t("advisor.errors." + error, { defaultValue: t("advisor.errors.generic") })}</Alert> : null;
  const canRequest = user.role === "admin" || user.role === "operator";
  const submit = async (event: FormEvent) => { event.preventDefault(); setLoading(true); setError(""); try { await api.startAiAnalysis({ workflow, ...(command ? { command } : {}) }); await load(); onChanged?.(); } catch (e) { setError(safeError(e)); } finally { setLoading(false); } };
  const decide = async (item: AdvisorInsight, decision: "approve" | "reject") => { setLoading(true); setError(""); try { if (decision === "approve") await api.approveAiDraft(item.job_id); else await api.rejectAiDraft(item.job_id); await load(); onChanged?.(); } catch (e) { const code = safeError(e); if (code === "advisor_stale_draft" || code === "advisor_expired") { blockedDrafts.current.add(item.job_id); setItems((current) => current.filter((entry) => entry.job_id !== item.job_id)); } setError(code); } finally { setLoading(false); } };
  const statusTone = (status: AdvisorInsight["status"]) =>
    status === "completed" || status === "approved"
      ? "success"
      : status === "failed" || status === "rejected" || status === "expired"
        ? "danger"
        : "warning";
  return (
    <Panel
      data-testid="ai-advisor-section"
      label={t("advisor.title")}
      actions={
        <Button
          aria-label={t("advisor.accessibility.refresh")}
          variant="secondary"
          onClick={() => void load()}
          disabled={loading}
        >
          {t("advisor.refresh")}
        </Button>
      }
    >
      <p className="mb-4 text-sm text-muted">{t("advisor.redactionNotice")}</p>
      {canRequest && (
        <form
          className="mb-6 grid gap-4 sm:grid-cols-[1fr_2fr_auto] sm:items-end"
          onSubmit={submit}
        >
          <SelectField
            label={t("advisor.workflow")}
            value={workflow}
            onChange={(e) => setWorkflow(e.target.value as AdvisorWorkflow)}
          >
            <option value="incident_explanation">
              {t("advisor.workflows.incident_explanation")}
            </option>
            <option value="security_summary">
              {t("advisor.workflows.security_summary")}
            </option>
            <option value="rule_tuning">
              {t("advisor.workflows.rule_tuning")}
            </option>
            <option value="configuration_draft">
              {t("advisor.workflows.configuration_draft")}
            </option>
          </SelectField>
          <TextareaField
            label={t("advisor.command")}
            value={command}
            onChange={(e) => setCommand(e.target.value)}
            rows={2}
          />
          <Button type="submit" disabled={loading}>
            {loading ? t("advisor.loading") : t("advisor.start")}
          </Button>
        </form>
      )}
      {error && (
        <Alert variant="danger">
          {t("advisor.errors." + error, {
            defaultValue: t("advisor.errors.generic"),
          })}
        </Alert>
      )}
      {items.length === 0 ? (
        <p className="text-sm text-muted">{t("advisor.empty")}</p>
      ) : (
        <ul className="divide-y divide-border">
          {items.map((item) => (
            <li
              aria-label={t("advisor.accessibility.result")}
              className="py-3"
              key={item.job_id}
            >
              <div className="flex flex-wrap items-center justify-between gap-2">
                <strong className="font-medium">
                  {t("advisor.workflows." + item.workflow, {
                    defaultValue: item.workflow,
                  })}
                </strong>
                <StatusBadge tone={statusTone(item.status)}>
                  {t("advisor.status." + item.status, {
                    defaultValue: item.status,
                  })}
                </StatusBadge>
              </div>
              <ResultView item={item} />
              {user.role === "admin" &&
                item.workflow === "configuration_draft" &&
                item.status === "completed" && (
                  <div className="mt-3 flex gap-2">
                    <Button
                      onClick={() => void decide(item, "approve")}
                      disabled={loading}
                    >
                      {t("advisor.approve")}
                    </Button>
                    <Button
                      variant="danger"
                      onClick={() => void decide(item, "reject")}
                      disabled={loading}
                    >
                      {t("advisor.reject")}
                    </Button>
                  </div>
                )}
            </li>
          ))}
        </ul>
      )}
    </Panel>
  );
}
