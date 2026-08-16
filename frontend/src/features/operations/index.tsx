import { useEffect, useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { Activity, ArrowRight, BarChart3, CheckCircle2, Database, Download, Gauge, Globe2, Network, RefreshCw, Server, ShieldAlert, ShieldCheck, TriangleAlert } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { api, type AnalyticsBucket, type AnalyticsSummary, type BotConfig, type Certificate, type ClusterSnapshot, type Host, type LoadBalancerSnapshot, type PluginStatus, type RateLimitConfig, type WafConfig } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { sanitizeError } from "@/lib/errors";
import { formatLocaleNumber, useLocaleFormatters } from "@/i18n";
import { useRealtimeRefresh } from "@/hooks/use-realtime-refresh";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";

const demoSummary: AnalyticsSummary = { requests: 148200, status_2xx: 139800, status_3xx: 2100, status_4xx: 4200, status_5xx: 2100, waf_blocks: 4291, bot_blocks: 412, bot_challenges: 806, rate_limited: 183, p50_ms: 38, p95_ms: 182, p99_ms: 421 };
const demoHosts: Host[] = [{ id: 1, name: "Public API", domain: "api.bearust.local", upstream_host: "api-pool", upstream_port: 8080, tls_mode: "letsencrypt", certificate_id: 1, enabled: true }];
const demoRows: AnalyticsBucket[] = Array.from({ length: 6 }, (_, index) => ({ timestamp: new Date(Date.now() - (5 - index) * 60_000).toISOString(), proxy_host_id: 1, requests: 240 + index * 18, status_2xx: 225 + index * 16, status_3xx: 4, status_4xx: 8, status_5xx: 3, waf_blocks: 6, bot_blocks: 2, bot_challenges: 4, rate_limited: 1, p50_ms: 36 + index, p95_ms: 168 + index * 3, p99_ms: 340 + index * 8 }));
const demoCluster: ClusterSnapshot = { local_node_id: "edge-jakarta-01", cluster_enabled: true, total_peers: 3, healthy_peers: 3, peers: [{ node_id: "edge-jakarta-02", status: "healthy", latency_ms: 4, error: null }, { node_id: "edge-jakarta-03", status: "healthy", latency_ms: 7, error: null }], timestamp: new Date().toISOString(), raft_role: "leader", raft_leader_id: "edge-jakarta-01", raft_term: 24, raft_last_log_index: 1284, raft_commit_index: 1284, raft_quorum_available: true, raft_sync_state: "leader_ready" };
const demoLoadBalancer: LoadBalancerSnapshot = { generation: 12, pools: [{ name: "api-pool", algorithm: "round_robin", connect_timeout_seconds: 3, request_timeout_seconds: 30, backends: [{ id: 0, address: "10.20.0.11:8080", health_check: "http", health_path: "/health", healthy: true, inflight: 8 }, { id: 1, address: "10.20.0.12:8080", health_check: "http", health_path: "/health", healthy: true, inflight: 5 }] }], routes: [{ name: "public-api", host: "api.bearust.local", path_prefix: "/", upstream_pool: "api-pool" }], capabilities: { algorithms: ["round_robin", "least_connections", "plugin"], health_checks: ["tcp", "http"], passive_health: false, adaptive_weighting: false } };
const demoCertificates: Certificate[] = [{ id: 1, name: "Public wildcard", source: "Let's Encrypt", covered_hostnames: ["api.bearust.local"], expiry: "2026-11-14T00:00:00Z", active: true }];
const demoWaf: WafConfig = { mode: "block", updated_at: new Date().toISOString() };
const demoBot: BotConfig = { mode: "challenge", threshold: 60, ttl_seconds: 900, updated_at: new Date().toISOString() };
const demoRate: RateLimitConfig = { enabled: true, action: "block", capacity: 1000, refill_per_second: 10, key_scope: "proxy_host_ip", updated_at: new Date().toISOString() };
const demoPlugins: PluginStatus[] = [{ id: "notify-sink-v2", display_name: "Notification sink", abi_version: 2, digest: "sha256:demo", enabled: true, loaded: true, last_error_code: null, created_at: new Date().toISOString(), updated_at: new Date().toISOString(), trust_status: "trusted" }];

export function Operations() {
  const { t } = useTranslation();
  const { locale, formatDate } = useLocaleFormatters();
  const [summary, setSummary] = useState<AnalyticsSummary | null>(DEMO_MODE ? demoSummary : null);
  const [rows, setRows] = useState<AnalyticsBucket[]>(DEMO_MODE ? demoRows : []);
  const [hosts, setHosts] = useState<Host[]>(DEMO_MODE ? demoHosts : []);
  const [cluster, setCluster] = useState<ClusterSnapshot | null>(DEMO_MODE ? demoCluster : null);
  const [loadBalancer, setLoadBalancer] = useState<LoadBalancerSnapshot | null>(DEMO_MODE ? demoLoadBalancer : null);
  const [certificates, setCertificates] = useState<Certificate[]>(DEMO_MODE ? demoCertificates : []);
  const [waf, setWaf] = useState<WafConfig | null>(DEMO_MODE ? demoWaf : null);
  const [bot, setBot] = useState<BotConfig | null>(DEMO_MODE ? demoBot : null);
  const [rateLimit, setRateLimit] = useState<RateLimitConfig | null>(DEMO_MODE ? demoRate : null);
  const [plugins, setPlugins] = useState<PluginStatus[]>(DEMO_MODE ? demoPlugins : []);
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [error, setError] = useState("");

  const refresh = async () => {
    if (DEMO_MODE) return;
    setLoading(true);
    setError("");
    const from = new Date(Date.now() - 86_400_000).toISOString();
    const results = await Promise.allSettled([
      api.getAnalyticsSummary({ from, limit: 1440 }),
      api.getAnalyticsTimeseries({ from, limit: 1440 }),
      api.hosts(),
      api.clusterStatus(),
      api.loadBalancer(),
      api.certificates(),
      api.wafConfig(),
      api.botConfig(),
      api.rateLimitConfig(),
      api.plugins(),
    ]);
    const [summaryResult, rowsResult, hostsResult, clusterResult, loadBalancerResult, certificatesResult, wafResult, botResult, rateResult, pluginsResult] = results;
    if (summaryResult.status === "fulfilled") setSummary(summaryResult.value);
    if (rowsResult.status === "fulfilled") setRows(rowsResult.value);
    if (hostsResult.status === "fulfilled") setHosts(hostsResult.value);
    if (clusterResult.status === "fulfilled") setCluster(clusterResult.value);
    if (loadBalancerResult.status === "fulfilled") setLoadBalancer(loadBalancerResult.value);
    if (certificatesResult.status === "fulfilled") setCertificates(certificatesResult.value);
    if (wafResult.status === "fulfilled") setWaf(wafResult.value);
    if (botResult.status === "fulfilled") setBot(botResult.value);
    if (rateResult.status === "fulfilled") setRateLimit(rateResult.value);
    if (pluginsResult.status === "fulfilled") setPlugins(pluginsResult.value);
    const rejected = results.slice(0, 5).find((result) => result.status === "rejected");
    if (rejected?.status === "rejected") setError(sanitizeError(rejected.reason));
    setLoading(false);
  };

  useEffect(() => { void refresh(); }, []);
  useRealtimeRefresh(["analytics.changed", "cluster.changed", "load_balancer.changed", "certificates.changed", "waf.changed", "bot.changed", "rate_limit.changed", "plugins.changed"], refresh);

  const requestsPerSecond = useMemo(() => rateFromRows(rows), [rows]);
  const errorRate = summary && summary.requests > 0 ? ((summary.status_4xx + summary.status_5xx) / summary.requests) * 100 : null;
  const backends = loadBalancer?.pools.flatMap((pool) => pool.backends) ?? [];
  const healthyBackends = backends.filter((backend) => backend.healthy).length;
  const healthyNodes = cluster ? (cluster.cluster_enabled ? `${cluster.healthy_peers}/${Math.max(cluster.total_peers, cluster.healthy_peers)}` : "1/1") : "—";
  const exportReport = () => {
    const payload = JSON.stringify({ generated_at: new Date().toISOString(), summary, rows, cluster, load_balancer: loadBalancer, certificates, protection: { waf, bot, rate_limit: rateLimit }, plugins }, null, 2);
    const url = URL.createObjectURL(new Blob([payload], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `bearust-operations-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    toast.success(t("operations.exported"));
  };

  return <Main>
    <PageHeader title={t("operations.title")} description={t("operations.description")} action={<div className="flex flex-wrap items-center justify-end gap-2"><Badge variant="outline" className="hidden gap-1.5 rounded-full sm:inline-flex"><span className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : loading ? "bg-amber-500" : "bg-emerald-500"}`} />{DEMO_MODE ? t("operations.demo") : loading ? t("operations.loading") : t("operations.connected")}</Badge><Button variant="outline" onClick={() => void refresh()} disabled={loading}><RefreshCw className={loading ? "animate-spin" : ""} />{t("common.refresh")}</Button><Button variant="outline" onClick={exportReport} disabled={loading}><Download />{t("operations.export")}</Button></div>} />
    {error && <div role="alert" className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>}

    <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
      <MetricCard title={t("operations.requestsPerSecond")} value={requestsPerSecond == null ? "—" : `${formatLocaleNumber(requestsPerSecond, locale, { maximumFractionDigits: 1 })}/s`} detail={t("operations.fromTelemetry")} trend="up" icon={Gauge} />
      <MetricCard title={t("operations.errorRate")} value={errorRate == null ? "—" : `${formatLocaleNumber(errorRate, locale, { maximumFractionDigits: 2 })}%`} detail={t("operations.httpErrors")} trend={errorRate != null && errorRate > 5 ? "up" : "neutral"} icon={TriangleAlert} />
      <MetricCard title={t("operations.healthyNodes")} value={healthyNodes} detail={cluster?.raft_sync_state ?? t("operations.statusUnavailable")} trend="neutral" icon={Network} />
      <MetricCard title={t("operations.healthyBackends")} value={`${healthyBackends}/${backends.length || "—"}`} detail={t("operations.activeHealthChecks")} trend={backends.length > 0 && healthyBackends < backends.length ? "up" : "neutral"} icon={Server} />
      <MetricCard title={t("operations.activeCertificates")} value={String(certificates.filter((certificate) => certificate.active).length)} detail={t("operations.tlsAndAcme")} trend="neutral" icon={ShieldCheck} />
    </div>

    <div className="grid gap-6 xl:grid-cols-[minmax(0,1.35fr)_minmax(320px,1fr)]">
      <Card>
        <CardHeader><CardTitle>{t("operations.hostHealth")}</CardTitle><CardDescription>{t("operations.hostHealthDescription")}</CardDescription></CardHeader>
        <CardContent><HostHealth rows={rows} hosts={hosts} formatDate={formatDate} locale={locale} /></CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>{t("operations.edgeHealth")}</CardTitle><CardDescription>{cluster ? `${cluster.local_node_id} · ${cluster.raft_role}` : t("operations.statusUnavailable")}</CardDescription></CardHeader>
        <CardContent className="space-y-3"><HealthRow label={t("operations.protectionEngine")} value={summary ? t("operations.operational") : t("operations.statusUnavailable")} status={summary ? "healthy" : "info"} /><HealthRow label={t("operations.quorum")} value={cluster?.raft_quorum_available ? t("operations.available") : t("operations.unavailable")} status={cluster?.raft_quorum_available ? "healthy" : "warning"} /><HealthRow label={t("operations.realtime")} value={t("operations.sseInvalidation")} status="healthy" />{cluster?.peers.slice(0, 3).map((peer) => <HealthRow key={peer.node_id} label={peer.node_id} value={peer.status} status={peer.status === "healthy" ? "healthy" : "warning"} />)}<Button variant="outline" className="mt-2 w-full" asChild><Link to="/cluster">{t("operations.openCluster")}<ArrowRight /></Link></Button></CardContent>
      </Card>
    </div>

    <div className="mt-6 grid gap-6 lg:grid-cols-2">
      <Card>
        <CardHeader><CardTitle>{t("operations.upstreamHealth")}</CardTitle><CardDescription>{t("operations.upstreamHealthDescription")}</CardDescription></CardHeader>
        <CardContent className="space-y-3">{loadBalancer?.pools.map((pool) => <div className="rounded-lg border p-4" key={pool.name}><div className="flex flex-wrap items-center justify-between gap-2"><div><p className="font-medium">{pool.name}</p><p className="text-xs text-muted-foreground">{formatAlgorithm(pool.algorithm)} · {pool.backends.length} {t("operations.backends")}</p></div><StatusBadge status={pool.backends.every((backend) => backend.healthy) ? "healthy" : "warning"}>{pool.backends.filter((backend) => backend.healthy).length}/{pool.backends.length} {t("operations.healthy")}</StatusBadge></div><div className="mt-3 grid gap-2 sm:grid-cols-2">{pool.backends.map((backend) => <div className="flex items-center justify-between gap-3 rounded-md bg-muted/30 px-3 py-2 text-xs" key={backend.id}><span className="truncate font-mono">{backend.address}</span><span className="shrink-0 text-muted-foreground">{backend.inflight} {t("operations.inFlight")}</span></div>)}</div></div>)}{!loadBalancer?.pools.length && <EmptyState icon={Server} text={t("operations.noPools")} />}{loadBalancer && <div className="flex flex-wrap items-center justify-between gap-2 rounded-lg border border-dashed p-3 text-xs text-muted-foreground"><span>{t("operations.generation", { generation: loadBalancer.generation })}</span><Link className="inline-flex items-center gap-1 font-medium text-primary hover:underline" to="/load-balancer">{t("operations.manageLoadBalancer")}<ArrowRight className="size-3" /></Link></div>}</CardContent>
      </Card>
      <Card>
        <CardHeader><CardTitle>{t("operations.protectionStatus")}</CardTitle><CardDescription>{t("operations.protectionDescription")}</CardDescription></CardHeader>
        <CardContent className="space-y-3"><ProtectionRow icon={ShieldCheck} label="WAF" value={waf?.mode === "block" ? t("operations.enforcing") : t("operations.monitorOnly")} status={waf?.mode === "block" ? "healthy" : "warning"} /><ProtectionRow icon={Activity} label={t("operations.botProtection")} value={bot?.mode ?? "—"} status={bot?.mode === "monitor" ? "warning" : "healthy"} /><ProtectionRow icon={Gauge} label={t("operations.rateLimiting")} value={rateLimit?.enabled ? t("operations.enabled") : t("operations.disabled")} status={rateLimit?.enabled ? "healthy" : "warning"} /><ProtectionRow icon={Database} label={t("operations.plugins")} value={`${plugins.filter((plugin) => plugin.enabled && plugin.loaded).length}/${plugins.length} ${t("operations.active")}`} status="info" /><Button variant="outline" className="mt-2 w-full" asChild><Link to="/security">{t("operations.openSecurity")}<ArrowRight /></Link></Button></CardContent>
      </Card>
    </div>

    <Card className="mt-6">
      <CardHeader><CardTitle>{t("operations.telemetryBoundaries")}</CardTitle><CardDescription>{t("operations.telemetryDescription")}</CardDescription></CardHeader>
      <CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-4"><Boundary icon={CheckCircle2} title={t("operations.collectedTitle")} detail={t("operations.collectedDetail")} status="healthy" /><Boundary icon={ShieldAlert} title={t("operations.redactedTitle")} detail={t("operations.redactedDetail")} status="healthy" /><Boundary icon={TriangleAlert} title={t("operations.notCollectedTitle")} detail={t("operations.notCollectedDetail")} status="warning" /><Boundary icon={BarChart3} title={t("operations.prometheusTitle")} detail={t("operations.prometheusDetail")} status="info" action={<a className="mt-2 inline-flex text-xs font-medium text-primary hover:underline" href="/metrics" target="_blank" rel="noreferrer">{t("operations.openMetrics")}<ArrowRight className="ms-1 size-3" /></a>} /></CardContent>
    </Card>
  </Main>;
}

function HostHealth({ rows, hosts, formatDate, locale }: { rows: AnalyticsBucket[]; hosts: Host[]; formatDate: (value: string) => string; locale: "en" | "id" | "ja" }) {
  const grouped = new Map<number, { requests: number; errors: number; p95: number[]; latest: string }>();
  for (const row of rows) { const current = grouped.get(row.proxy_host_id) ?? { requests: 0, errors: 0, p95: [], latest: row.timestamp }; current.requests += row.requests; current.errors += row.status_4xx + row.status_5xx; if (row.p95_ms != null) current.p95.push(row.p95_ms); if (row.timestamp > current.latest) current.latest = row.timestamp; grouped.set(row.proxy_host_id, current); }
  if (grouped.size === 0) return <EmptyState icon={Globe2} text="No host telemetry is available yet." />;
  return <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="pb-3">Host</th><th className="pb-3">Requests</th><th className="pb-3">Error rate</th><th className="pb-3">P95</th><th className="pb-3">Last bucket</th></tr></thead><tbody>{[...grouped.entries()].sort(([, left], [, right]) => right.requests - left.requests).map(([hostId, value]) => { const host = hosts.find((item) => item.id === hostId); return <tr className="border-b last:border-0" key={hostId}><td className="py-3"><p className="font-medium">{host?.name ?? `Host #${hostId}`}</p><p className="font-mono text-xs text-muted-foreground">{host?.domain ?? `ID ${hostId}`}</p></td><td className="py-3 font-mono text-xs">{formatLocaleNumber(value.requests, locale)}</td><td className="py-3"><StatusBadge status={value.errors / Math.max(value.requests, 1) > 0.05 ? "warning" : "healthy"}>{formatLocaleNumber((value.errors / Math.max(value.requests, 1)) * 100, locale, { maximumFractionDigits: 2 })}%</StatusBadge></td><td className="py-3 font-mono text-xs">{value.p95.length ? `${Math.round(value.p95.reduce((sum, item) => sum + item, 0) / value.p95.length)}ms` : "—"}</td><td className="whitespace-nowrap py-3 text-xs text-muted-foreground">{formatDate(value.latest)}</td></tr>; })}</tbody></table></div>;
}

function HealthRow({ label, value, status }: { label: string; value: string; status: "healthy" | "warning" | "info" }) { return <div className="flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-sm"><span className="truncate text-muted-foreground">{label}</span><StatusBadge status={status}>{value}</StatusBadge></div>; }
function ProtectionRow({ icon: Icon, label, value, status }: { icon: typeof ShieldCheck; label: string; value: string; status: "healthy" | "warning" | "info" }) { return <div className="flex items-center justify-between gap-3 rounded-md border px-3 py-3"><div className="flex min-w-0 items-center gap-2"><Icon className="size-4 shrink-0 text-primary" /><span className="truncate text-sm font-medium">{label}</span></div><StatusBadge status={status}>{value}</StatusBadge></div>; }
function Boundary({ icon: Icon, title, detail, status, action }: { icon: typeof CheckCircle2; title: string; detail: string; status: "healthy" | "warning" | "info"; action?: React.ReactNode }) { return <div className="rounded-lg border p-4"><div className="flex items-center gap-2"><Icon className={`size-4 ${status === "healthy" ? "text-emerald-600" : status === "warning" ? "text-amber-600" : "text-primary"}`} /><p className="text-sm font-medium">{title}</p></div><p className="mt-2 text-xs leading-5 text-muted-foreground">{detail}</p>{action}</div>; }
function EmptyState({ icon: Icon, text }: { icon: typeof Server; text: string }) { return <div className="flex flex-col items-center justify-center rounded-lg border border-dashed px-6 py-10 text-center"><Icon className="size-5 text-muted-foreground" /><p className="mt-3 text-sm text-muted-foreground">{text}</p></div>; }
function rateFromRows(rows: AnalyticsBucket[]) { if (rows.length === 0) return null; const recent = rows.slice(-5); const requests = recent.reduce((sum, row) => sum + row.requests, 0); const span = Math.max(60, (new Date(recent[recent.length - 1].timestamp).getTime() - new Date(recent[0].timestamp).getTime()) / 1000 + 60); return requests / span; }
function formatAlgorithm(value: string) { return value.split("_").map((part) => part.charAt(0).toUpperCase() + part.slice(1)).join(" "); }
