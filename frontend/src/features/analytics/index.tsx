import { useEffect, useMemo, useState, type FormEvent } from "react";
import { Link } from "@tanstack/react-router";
import { toast } from "sonner";
import { ArrowDown, ArrowUp, Check, Download, Gauge, Globe2, RefreshCw, Server, ShieldAlert, SlidersHorizontal, Zap } from "lucide-react";
import { api, type AnalyticsBucket, type AnalyticsSummary, type AnomalyRecord, type BaselineSnapshot, type Host, type PolicyRecommendation, type TuningMode, type TuningPolicy } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { sanitizeError } from "@/lib/errors";
import { useRealtimeRefresh } from "@/hooks/use-realtime-refresh";
import { useAuthStore } from "@/stores/auth-store";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { TrafficChart } from "@/features/dashboard/components/traffic-chart";

const demoHosts: Host[] = [{ id: 1, name: "Public API", domain: "api.bearust.local", upstream_host: "api-pool", upstream_port: 8080, tls_mode: "letsencrypt", certificate_id: 1, enabled: true }, { id: 2, name: "Admin Console", domain: "console.bearust.local", upstream_host: "console", upstream_port: 3000, tls_mode: "letsencrypt", certificate_id: 1, enabled: true }];
const demoSummary: AnalyticsSummary = { requests: 148200, status_2xx: 139800, status_3xx: 2100, status_4xx: 4200, status_5xx: 2100, waf_blocks: 4291, bot_blocks: 412, bot_challenges: 806, rate_limited: 183, p50_ms: 38, p95_ms: 182, p99_ms: 421 };
const demoBaseline: BaselineSnapshot = { host_id: 1, status: "ready", window: "5m", sample_count: 60, metrics: { req_per_sec: 28.4, total_requests: 8520, status_2xx: 8270, status_3xx: 90, status_4xx: 120, status_5xx: 40, error_rate_percent: 1.9, p50_ms: 38, p95_ms: 182, p99_ms: 421, waf_blocks: 248, bot_blocks: 21, bot_challenges: 64, rate_limited: 8 }, calculated_at: "2026-08-16T09:42:00Z" };
const demoAnomalies: AnomalyRecord[] = [{ id: 1, host_id: 1, rule: "request_rate", severity: "warning", score: 2.4, summary: "Request rate is above the learned baseline.", observed_at: "2026-08-16T09:37:00Z", acknowledged: false }];
const demoPolicy: TuningPolicy = { mode: "recommend", max_delta_percent: 50, cooldown_seconds: 300, min_confidence: 0.8 };
const emptyPolicy: TuningPolicy = { mode: "monitor", max_delta_percent: 0, cooldown_seconds: 0, min_confidence: 0 };
const demoRecommendations: PolicyRecommendation[] = [{ id: 1, host_id: 1, patch: { capacity: 1200, refill_per_second: 12 }, confidence: 0.91, reason: "Sustained traffic is above the baseline without a matching error spike.", created_at: "2026-08-16T09:40:00Z", applied: false }];

export function Analytics() {
  const user = useAuthStore((state) => state.user);
  const canWrite = user?.role === "admin";
  const [range, setRange] = useState("7d");
  const [hosts, setHosts] = useState<Host[]>(DEMO_MODE ? demoHosts : []);
  const [hostId, setHostId] = useState(DEMO_MODE ? "1" : "");
  const [summary, setSummary] = useState<AnalyticsSummary | null>(DEMO_MODE ? demoSummary : null);
  const [rows, setRows] = useState<AnalyticsBucket[]>([]);
  const [baseline, setBaseline] = useState<BaselineSnapshot | null>(DEMO_MODE ? demoBaseline : null);
  const [anomalies, setAnomalies] = useState<AnomalyRecord[]>(DEMO_MODE ? demoAnomalies : []);
  const [policy, setPolicy] = useState<TuningPolicy>(DEMO_MODE ? demoPolicy : emptyPolicy);
  const [policyLoaded, setPolicyLoaded] = useState(DEMO_MODE);
  const [recommendations, setRecommendations] = useState<PolicyRecommendation[]>(DEMO_MODE ? demoRecommendations : []);
  const [emergencyDisabled, setEmergencyDisabled] = useState(false);
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    if (DEMO_MODE) return;
    void api.hosts().then((nextHosts) => { setHosts(nextHosts); if (!hostId && nextHosts[0]) setHostId(String(nextHosts[0].id)); }).catch((exception) => setError(sanitizeError(exception)));
  }, []);

  const from = useMemo(() => new Date(Date.now() - (range === "24h" ? 86_400_000 : range === "30d" ? 30 * 86_400_000 : 7 * 86_400_000)).toISOString(), [range]);
  const refresh = async () => {
    if (DEMO_MODE || !hostId && hosts.length === 0) return;
    setLoading(true); setError("");
    setPolicyLoaded(false);
    setPolicy(emptyPolicy);
    const selected = hostId ? Number(hostId) : undefined;
    const results = await Promise.allSettled([
      api.getAnalyticsSummary({ ...(selected ? { proxy_host_id: selected } : {}), from, limit: 1440 }),
      api.getAnalyticsTimeseries({ ...(selected ? { proxy_host_id: selected } : {}), from, limit: 1440 }),
      api.getBaseline({ ...(selected ? { proxy_host_id: selected } : {}), window: "5m" }),
      api.getAnomalies(selected ? { host_id: selected } : {}),
      api.getRecommendations(),
      selected ? api.getTuningPolicy(selected) : Promise.resolve(null),
    ]);
    const [summaryResult, rowsResult, baselineResult, anomaliesResult, recommendationResult, policyResult] = results;
    if (summaryResult.status === "fulfilled") setSummary(summaryResult.value);
    if (rowsResult.status === "fulfilled") setRows(rowsResult.value);
    if (baselineResult.status === "fulfilled") setBaseline(baselineResult.value);
    if (anomaliesResult.status === "fulfilled") setAnomalies(anomaliesResult.value);
    if (recommendationResult.status === "fulfilled") setRecommendations(recommendationResult.value);
    if (policyResult.status === "fulfilled" && policyResult.value) {
      setPolicy(policyResult.value);
      setPolicyLoaded(true);
    }
    const rejected = results.find((result) => result.status === "rejected");
    if (rejected?.status === "rejected") setError(sanitizeError(rejected.reason));
    setLoading(false);
  };
  useEffect(() => { void refresh(); }, [hostId, range, hosts.length]);
  useRealtimeRefresh(["analytics.changed", "baseline.changed", "anomaly.changed", "adaptive_tuning.changed"], refresh);

  const chartData = useMemo(() => rows.slice(-24).map((row) => ({ name: new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(new Date(row.timestamp)), requests: row.requests, blocked: row.waf_blocks + row.bot_blocks + row.bot_challenges + row.rate_limited })), [rows]);
  const blocked = summary ? summary.waf_blocks + summary.bot_blocks + summary.bot_challenges + summary.rate_limited : 0;
  const selectedHostName = hosts.find((host) => String(host.id) === hostId)?.name ?? "All hosts";

  const acknowledge = async (id: number) => {
    setBusy(true);
    try { if (DEMO_MODE) setAnomalies((current) => current.map((item) => item.id === id ? { ...item, acknowledged: true } : item)); else { await api.ackAnomaly(id); await refresh(); } toast.success("Anomaly acknowledged"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };
  const savePolicy = async (event: FormEvent) => {
    event.preventDefault(); if (!hostId || !canWrite || !policyLoaded) return;
    setBusy(true);
    try { if (DEMO_MODE) toast.success("Tuning policy saved"); else setPolicy(await api.updateTuningPolicy(Number(hostId), policy)); toast.success("Tuning policy saved"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };
  const applyRecommendation = async (recommendation: PolicyRecommendation) => {
    setBusy(true);
    try { if (DEMO_MODE) setRecommendations((current) => current.map((item) => item.id === recommendation.id ? { ...item, applied: true } : item)); else { await api.applyRecommendation(recommendation.id); await refresh(); } toast.success("Recommendation applied"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };
  const rollbackRecommendation = async (recommendation: PolicyRecommendation) => {
    setBusy(true);
    try { if (!DEMO_MODE) { await api.rollbackRecommendation(recommendation.id); await refresh(); } else setRecommendations((current) => current.map((item) => item.id === recommendation.id ? { ...item, applied: false } : item)); toast.success("Recommendation rolled back"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };
  const toggleEmergency = async () => {
    setBusy(true);
    try { const next = DEMO_MODE ? !emergencyDisabled : (await api.emergencyDisableTuning()).emergency_disabled; setEmergencyDisabled(next); toast.success(next ? "Adaptive tuning disabled" : "Adaptive tuning enabled"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };
  const exportAnalytics = () => { const value = JSON.stringify({ summary, rows, baseline, anomalies, recommendations }, null, 2); const url = URL.createObjectURL(new Blob([value], { type: "application/json" })); const anchor = document.createElement("a"); anchor.href = url; anchor.download = `bearust-analytics-${new Date().toISOString().slice(0, 10)}.json`; anchor.click(); URL.revokeObjectURL(url); toast.success("Analytics export downloaded"); };

  return <Main><PageHeader title="Analytics" description="Understand traffic, latency, security events, and adaptive policy decisions." action={<><Badge variant="outline" className="hidden gap-1.5 rounded-full sm:inline-flex"><span className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : "bg-emerald-500"}`} />{DEMO_MODE ? "Demo data" : "API connected"}</Badge><select aria-label="Analytics range" value={range} onChange={(event) => setRange(event.target.value)} className="h-9 rounded-md border border-input bg-background px-3 text-sm"><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option></select><Button variant="outline" onClick={exportAnalytics} disabled={loading}><Download />Export</Button></>} />
    {error && <div role="alert" className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>}
    <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4"><MetricCard title="Total requests" value={formatCompact(summary?.requests ?? 0)} detail={`${formatCompact(summary?.status_2xx ?? 0)} successful`} trend="up" icon={Globe2} /><MetricCard title="P95 latency" value={summary?.p95_ms == null ? "—" : `${summary.p95_ms}ms`} detail={summary?.p99_ms == null ? "No p99 sample" : `p99 ${summary.p99_ms}ms`} trend="down" icon={Gauge} /><MetricCard title="Security events" value={formatCompact(blocked)} detail={`${formatCompact(summary?.waf_blocks ?? 0)} WAF blocks`} trend="up" icon={ShieldAlert} /><MetricCard title="Origin errors" value={formatCompact((summary?.status_4xx ?? 0) + (summary?.status_5xx ?? 0))} detail="HTTP 4xx + 5xx" trend="neutral" icon={Server} /></div>
    <Card className="mb-6"><CardContent className="grid gap-4 pt-6 sm:grid-cols-[minmax(0,1fr)_220px]"><div><p className="text-sm font-medium">Proxy host scope</p><p className="mt-1 text-xs text-muted-foreground">Filter analytics and learning data by host.</p></div><select aria-label="Analytics proxy host" value={hostId} onChange={(event) => setHostId(event.target.value)} className="h-9 rounded-md border border-input bg-background px-3 text-sm"><option value="">All hosts</option>{hosts.map((host) => <option value={host.id} key={host.id}>{host.name} · {host.domain}</option>)}</select></CardContent></Card>
    <Tabs defaultValue="traffic" className="space-y-6"><TabsList><TabsTrigger value="traffic">Traffic</TabsTrigger><TabsTrigger value="learning">Baseline & anomalies</TabsTrigger><TabsTrigger value="tuning">Adaptive tuning</TabsTrigger></TabsList>
      <TabsContent value="traffic" className="space-y-6"><Card><CardHeader><CardTitle>Traffic overview</CardTitle><CardDescription>{selectedHostName} · {range === "24h" ? "last 24 hours" : range === "30d" ? "last 30 days" : "last 7 days"}</CardDescription></CardHeader><CardContent className="ps-2">{loading ? <Loading /> : <TrafficChart data={chartData} />}</CardContent></Card><div className="grid gap-4 lg:grid-cols-5"><Card className="lg:col-span-3"><CardHeader><CardTitle>Telemetry buckets</CardTitle><CardDescription>Raw analytics buckets returned by the API.</CardDescription></CardHeader><CardContent><div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="pb-3">Time</th><th className="pb-3">Requests</th><th className="pb-3">P95</th><th className="pb-3">Errors</th><th className="pb-3">Blocked</th></tr></thead><tbody>{rows.slice(-12).map((row) => <tr className="border-b last:border-0" key={`${row.timestamp}-${row.proxy_host_id}`}><td className="whitespace-nowrap py-3 text-xs text-muted-foreground">{formatDate(row.timestamp)}</td><td className="py-3 font-mono text-xs">{row.requests.toLocaleString()}</td><td className="py-3 font-mono text-xs">{row.p95_ms == null ? "—" : `${row.p95_ms}ms`}</td><td className="py-3 font-mono text-xs">{(row.status_4xx + row.status_5xx).toLocaleString()}</td><td className="py-3 font-mono text-xs">{(row.waf_blocks + row.bot_blocks + row.bot_challenges + row.rate_limited).toLocaleString()}</td></tr>)}</tbody></table></div>{!loading && rows.length === 0 && <p className="py-8 text-center text-sm text-muted-foreground">No telemetry buckets for this scope yet.</p>}</CardContent></Card><Card className="lg:col-span-2"><CardHeader><CardTitle>Latency percentiles</CardTitle><CardDescription>Current scope summary.</CardDescription></CardHeader><CardContent className="space-y-4">{[["p50", summary?.p50_ms], ["p95", summary?.p95_ms], ["p99", summary?.p99_ms]].map(([label, value]) => <LatencyBar key={label as string} label={label as string} value={value as number | null} max={summary?.p99_ms ?? 1} />)}<Button variant="outline" className="w-full" asChild><Link to="/audit-log">Inspect security audit events</Link></Button></CardContent></Card></div></TabsContent>
      <TabsContent value="learning" className="space-y-6"><Card><CardHeader className="flex flex-row items-start justify-between"><div><CardTitle>Learned baseline</CardTitle><CardDescription>Rolling baseline for {selectedHostName}. The API reports when the window is ready.</CardDescription></div><StatusBadge status={baseline?.status === "ready" ? "healthy" : "warning"}>{baseline?.status === "ready" ? "Ready" : "Warming up"}</StatusBadge></CardHeader><CardContent>{baseline ? <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4"><MiniMetric label="Requests / sec" value={baseline.metrics.req_per_sec.toFixed(2)} /><MiniMetric label="Error rate" value={`${baseline.metrics.error_rate_percent.toFixed(2)}%`} /><MiniMetric label="P95 latency" value={baseline.metrics.p95_ms == null ? "—" : `${baseline.metrics.p95_ms}ms`} /><MiniMetric label="Samples" value={baseline.sample_count.toLocaleString()} /></div> : <p className="text-sm text-muted-foreground">No baseline is available for this scope.</p>}</CardContent></Card><Card><CardHeader><CardTitle>Anomalies</CardTitle><CardDescription>Review detected deviations and acknowledge handled events.</CardDescription></CardHeader><CardContent><div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="pb-3">Observed</th><th className="pb-3">Rule</th><th className="pb-3">Severity</th><th className="pb-3">Score</th><th className="pb-3">Summary</th><th className="pb-3 text-right">Action</th></tr></thead><tbody>{anomalies.map((anomaly) => <tr className="border-b last:border-0" key={anomaly.id}><td className="whitespace-nowrap py-3 text-xs text-muted-foreground">{formatDate(anomaly.observed_at)}</td><td className="py-3 font-mono text-xs">{anomaly.rule}</td><td className="py-3"><StatusBadge status={anomaly.severity === "critical" ? "danger" : anomaly.severity === "warning" ? "warning" : "info"}>{anomaly.severity}</StatusBadge></td><td className="py-3 font-mono text-xs">{anomaly.score.toFixed(2)}</td><td className="max-w-80 truncate py-3">{anomaly.summary}</td><td className="py-3 text-right">{anomaly.acknowledged ? <Badge variant="secondary">Acknowledged</Badge> : <Button size="sm" variant="outline" onClick={() => void acknowledge(anomaly.id)} disabled={busy || !canWrite}><Check />Acknowledge</Button>}</td></tr>)}</tbody></table></div>{anomalies.length === 0 && <p className="py-8 text-center text-sm text-muted-foreground">No anomalies detected for this scope.</p>}</CardContent></Card></TabsContent>
      <TabsContent value="tuning" className="space-y-6"><Card><CardHeader className="flex flex-row items-start justify-between"><div><CardTitle>Adaptive tuning policy</CardTitle><CardDescription>Recommendations remain approval-gated; enforcement is never implicit.</CardDescription></div><StatusBadge status={emergencyDisabled ? "danger" : !policyLoaded ? "info" : policy.mode === "enforce" ? "healthy" : policy.mode === "recommend" ? "info" : "warning"}>{emergencyDisabled ? "Emergency disabled" : !policyLoaded ? "Not configured" : policy.mode}</StatusBadge></CardHeader><CardContent>{policyLoaded ? <form className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4" onSubmit={(event) => void savePolicy(event)}><div className="space-y-2"><label htmlFor="tuning-mode" className="text-sm font-medium">Mode</label><select id="tuning-mode" value={policy.mode} onChange={(event) => setPolicy({ ...policy, mode: event.target.value as TuningMode })} disabled={!canWrite || busy} className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"><option value="monitor">Monitor</option><option value="recommend">Recommend</option><option value="enforce">Enforce</option></select></div><NumberField label="Max delta (%)" value={policy.max_delta_percent} onChange={(value) => setPolicy({ ...policy, max_delta_percent: value })} disabled={!canWrite || busy} /><NumberField label="Cooldown (seconds)" value={policy.cooldown_seconds} onChange={(value) => setPolicy({ ...policy, cooldown_seconds: value })} disabled={!canWrite || busy} /><NumberField label="Min confidence" value={policy.min_confidence} step="0.05" onChange={(value) => setPolicy({ ...policy, min_confidence: value })} disabled={!canWrite || busy} />{canWrite && <div className="flex flex-wrap gap-2 sm:col-span-2 lg:col-span-4"><Button type="submit" disabled={busy || !hostId || !policyLoaded}><SlidersHorizontal />Save policy</Button><Button type="button" variant={emergencyDisabled ? "outline" : "destructive"} onClick={() => void toggleEmergency()} disabled={busy}>{emergencyDisabled ? "Enable tuning" : "Emergency disable"}</Button></div>}</form> : <p role="status" className="py-6 text-sm text-muted-foreground">{loading ? "Loading the tuning policy…" : hostId ? "No adaptive tuning policy is configured for this host." : "Select a proxy host to manage its tuning policy."}</p>}</CardContent></Card><Card><CardHeader><CardTitle>Recommendations</CardTitle><CardDescription>Review, apply, or roll back changes produced by the learning service.</CardDescription></CardHeader><CardContent><div className="space-y-3">{recommendations.map((recommendation) => <div className="rounded-lg border p-4" key={recommendation.id}><div className="flex flex-col gap-3 md:flex-row md:items-start md:justify-between"><div className="min-w-0"><div className="flex items-center gap-2"><Badge variant="outline">{Math.round(recommendation.confidence * 100)}% confidence</Badge><span className="text-xs text-muted-foreground">Host #{recommendation.host_id}</span></div><p className="mt-2 text-sm font-medium">{recommendation.reason}</p><p className="mt-1 font-mono text-xs text-muted-foreground">{Object.entries(recommendation.patch).map(([key, value]) => `${key}=${value}`).join(" · ")}</p></div><div className="flex shrink-0 gap-2">{recommendation.applied ? <Button variant="destructive" size="sm" onClick={() => void rollbackRecommendation(recommendation)} disabled={busy || !canWrite}>Roll back</Button> : <Button variant="outline" size="sm" onClick={() => void applyRecommendation(recommendation)} disabled={busy || !canWrite || emergencyDisabled}>Apply</Button>}</div></div></div>)}</div>{recommendations.length === 0 && <p className="py-8 text-center text-sm text-muted-foreground">No tuning recommendations are waiting.</p>}</CardContent></Card></TabsContent>
    </Tabs>
  </Main>;
}

function Loading() { return <div className="h-[300px] animate-pulse rounded-md bg-muted" role="status" aria-label="Loading analytics" />; }
function LatencyBar({ label, value, max }: { label: string; value: number | null; max: number }) { const width = value == null ? 0 : Math.max(4, Math.round((value / Math.max(max, 1)) * 100)); return <div className="space-y-2"><div className="flex justify-between text-sm"><span className="uppercase text-muted-foreground">{label}</span><span className="font-mono text-xs">{value == null ? "—" : `${value}ms`}</span></div><div className="h-2 rounded-full bg-muted"><div className="h-2 rounded-full bg-primary" style={{ width: `${width}%` }} /></div></div>; }
function MiniMetric({ label, value }: { label: string; value: string }) { return <div className="rounded-lg border bg-muted/30 p-4"><p className="text-xs text-muted-foreground">{label}</p><p className="mt-1 text-xl font-semibold tabular-nums">{value}</p></div>; }
function NumberField({ label, value, onChange, disabled, step = "1" }: { label: string; value: number; onChange: (value: number) => void; disabled: boolean; step?: string }) { return <div className="space-y-2"><label className="text-sm font-medium">{label}</label><input type="number" value={value} step={step} onChange={(event) => onChange(Number(event.target.value))} disabled={disabled} className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm" /></div>; }
function formatCompact(value: number) { return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(value); }
function formatDate(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date); }
