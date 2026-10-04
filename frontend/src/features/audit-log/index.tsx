import { useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { ChevronLeft, ChevronRight, Download, FileClock, RefreshCw, Search } from "lucide-react";
import { api, type AuditLogItem, type AuditLogPage } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { sanitizeError } from "@/lib/errors";
import { useRealtimeRefresh } from "@/hooks/use-realtime-refresh";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";

const demoEntries: AuditLogItem[] = [
  { id: 1, created_at: "2026-08-16T09:42:00Z", actor: "Rizalord", event: "waf_config_updated", details: "mode=block", },
  { id: 2, created_at: "2026-08-16T09:18:00Z", actor: "Maya Chen", event: "proxy_host_created", details: "api.bearust.local", },
  { id: 3, created_at: "2026-08-16T08:56:00Z", actor: "Rizalord", event: "user_sessions_revoked", details: "staging@bearust.local", },
  { id: 4, created_at: "2026-08-16T08:31:00Z", actor: "Unknown", event: "login_denied", details: "admin@bearust.local", },
  { id: 5, created_at: "2026-08-15T22:04:00Z", actor: "System", event: "certificate_renewed", details: "api.bearust.local", },
];

export function AuditLog() {
  const { t } = useTranslation();
  const [page, setPage] = useState<AuditLogPage>({ items: DEMO_MODE ? demoEntries : [], page: 1, page_size: 25, total: 0 });
  const [query, setQuery] = useState("");
  const [event, setEvent] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [error, setError] = useState("");
  const requestVersion = useRef(0);

  const refresh = async (nextPage = page.page) => {
    if (DEMO_MODE) return;
    const version = ++requestVersion.current;
    setLoading(true); setError("");
    try {
      const result = await api.auditLogs({ q: query, event, from: toIso(from), to: toIso(to), page: nextPage, page_size: 25 });
      if (version === requestVersion.current) setPage(result);
    } catch (exception) {
      if (version === requestVersion.current) setError(sanitizeError(exception));
    } finally {
      if (version === requestVersion.current) setLoading(false);
    }
  };
  useEffect(() => {
    void refresh(1);
    return () => { requestVersion.current++; };
  }, [query, event, from, to]);
  useRealtimeRefresh(["audit"], () => refresh(1));

  const visible = useMemo(() => DEMO_MODE ? page.items.filter((entry) => `${entry.actor} ${entry.event} ${entry.details}`.toLowerCase().includes(query.toLowerCase()) && (!event || entry.event.includes(event))) : page.items, [page.items, query, event]);
  const totalPages = Math.max(1, Math.ceil(page.total / page.page_size));

  const exportCsv = () => {
    const rows = [["timestamp", "actor", "event", "details"], ...visible.map((entry) => [entry.created_at, entry.actor, entry.event, entry.details])];
    const csv = rows.map((row) => row.map(csvCell).join(",")).join("\r\n");
    const url = URL.createObjectURL(new Blob([csv], { type: "text/csv;charset=utf-8" }));
    const anchor = document.createElement("a"); anchor.href = url; anchor.download = `bearust-audit-page-${page.page}.csv`; anchor.click(); URL.revokeObjectURL(url);
    toast.success(t("shell.auditCsvDownloaded"), { description: t("shell.auditExportDescription") });
  };

  return <Main><PageHeader title={t("shell.auditTitle")} description={t("shell.auditDescription")} action={<><Badge variant="outline" className="hidden gap-1.5 rounded-full sm:inline-flex"><span className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : "bg-emerald-500"}`} />{DEMO_MODE ? t("shell.demoData") : t("shell.apiConnected")}</Badge><Button variant="outline" onClick={exportCsv} disabled={loading || visible.length === 0}><Download />{t("shell.exportCsv")}</Button></>} />
    {error && <div role="alert" className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>}
    <Card><CardHeader className="gap-4"><div><CardTitle>{t("shell.activityHistory")}</CardTitle><CardDescription>{DEMO_MODE ? t("shell.previewEventsLocal") : t("shell.matchingEvents", { count: page.total.toLocaleString() })}</CardDescription></div><div className="grid gap-2 md:grid-cols-[minmax(0,1fr)_180px_auto_auto]"><div className="relative"><Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" /><Input aria-label={t("shell.searchAudit")} placeholder={t("shell.searchActorDetails")} value={query} onChange={(event) => setQuery(event.target.value)} className="h-9 pl-8" /></div><Input aria-label={t("shell.filterEventType")} placeholder={t("shell.eventType")} value={event} onChange={(input) => setEvent(input.target.value)} className="h-9" /><Input aria-label={t("shell.auditFrom")} type="datetime-local" value={from} onChange={(input) => setFrom(input.target.value)} className="h-9" /><Input aria-label={t("shell.auditTo")} type="datetime-local" value={to} onChange={(input) => setTo(input.target.value)} className="h-9" /></div></CardHeader><CardContent>{loading ? <div className="space-y-3 py-2">{[1, 2, 3, 4].map((item) => <div className="h-12 animate-pulse rounded-md bg-muted" key={item} />)}</div> : <><div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="pb-3 font-medium">{t("shell.timestamp")}</th><th className="pb-3 font-medium">{t("shell.actor")}</th><th className="pb-3 font-medium">{t("shell.event")}</th><th className="pb-3 font-medium">{t("shell.details")}</th><th className="pb-3 font-medium">{t("shell.result")}</th></tr></thead><tbody>{visible.map((entry) => { const failed = /denied|failed|error/i.test(`${entry.event} ${entry.details}`); return <tr className="border-b last:border-0" key={entry.id}><td className="whitespace-nowrap py-4 text-xs text-muted-foreground">{formatDate(entry.created_at)}</td><td className="py-4 font-medium">{entry.actor}</td><td className="py-4 font-mono text-xs">{entry.event}</td><td className="max-w-96 truncate py-4 text-muted-foreground">{entry.details || "—"}</td><td className="py-4"><Badge variant={failed ? "destructive" : "secondary"}>{failed ? t("shell.denied") : t("shell.success")}</Badge></td></tr>; })}</tbody></table></div>{visible.length === 0 && <div className="py-12 text-center text-sm text-muted-foreground"><FileClock className="mx-auto mb-2 size-6" />{t("shell.noEventsMatch")}</div>}</>}</CardContent><div className="flex items-center justify-between border-t px-6 py-4"><Button variant="outline" size="sm" onClick={() => void refresh(page.page - 1)} disabled={DEMO_MODE || loading || page.page <= 1}><ChevronLeft />{t("shell.previous")}</Button><span className="text-xs text-muted-foreground">{t("shell.pageOf", { page: page.page, total: totalPages })}</span><Button variant="outline" size="sm" onClick={() => void refresh(page.page + 1)} disabled={DEMO_MODE || loading || page.page >= totalPages}><ChevronRight />{t("shell.next")}</Button></div></Card>
    {!DEMO_MODE && <Button variant="ghost" className="mt-3" onClick={() => void refresh()} disabled={loading}><RefreshCw className={loading ? "animate-spin" : ""} />{t("shell.refreshEvents")}</Button>}
  </Main>;
}

function toIso(value: string) { return value ? new Date(value).toISOString() : undefined; }
function formatDate(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date); }
function csvCell(value: string) {
  // CSV quoting alone does not prevent spreadsheet formula evaluation.
  const text = /^[\s\uFEFF]*[=+\-@]|^[\t\r\n]/.test(value) ? `'${value}` : value;
  return `"${text.replaceAll('"', '""')}"`;
}
