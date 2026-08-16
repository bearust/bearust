import { useEffect, useMemo, useState } from "react";
import { Link } from "@tanstack/react-router";
import { toast } from "sonner";
import {
  Activity,
  ArrowUpRight,
  Ban,
  Download,
  Gauge,
  Globe2,
  Server,
  ShieldCheck,
  Users,
} from "lucide-react";
import { api, type AnalyticsBucket, type AnalyticsDimensions, type AnalyticsSummary, type AuditLogItem, type ClusterSnapshot, type Host } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { sanitizeError } from "@/lib/errors";
import { useRealtimeRefresh } from "@/hooks/use-realtime-refresh";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import { TrafficChart, type TrafficPoint } from "./components/traffic-chart";

const demoSummary: AnalyticsSummary = { requests: 148200, status_2xx: 139800, status_3xx: 2100, status_4xx: 4200, status_5xx: 2100, waf_blocks: 4291, bot_blocks: 412, bot_challenges: 806, rate_limited: 183, bandwidth_bytes: 482_000_000, p50_ms: 38, p95_ms: 182, p99_ms: 421 };
const demoCluster: ClusterSnapshot = { local_node_id: "edge-jakarta-01", cluster_enabled: true, total_peers: 3, healthy_peers: 3, peers: [], timestamp: "2026-08-16T09:42:00Z", raft_role: "leader", raft_leader_id: "edge-jakarta-01", raft_term: 24, raft_last_log_index: 1284, raft_commit_index: 1284, raft_quorum_available: true, raft_sync_state: "leader_ready" };
const demoTraffic: TrafficPoint[] = [
  { name: "Mon", requests: 18200, blocked: 920 },
  { name: "Tue", requests: 22400, blocked: 1100 },
  { name: "Wed", requests: 19800, blocked: 870 },
  { name: "Thu", requests: 26400, blocked: 1420 },
  { name: "Fri", requests: 31200, blocked: 1640 },
  { name: "Sat", requests: 27600, blocked: 1180 },
  { name: "Sun", requests: 35400, blocked: 1910 },
];
const demoDimensions: AnalyticsDimensions = { bandwidth_bytes: 482_000_000, top_endpoints: [], top_upstreams: [], top_attacker_ips: [], attack_types: [] };
const demoEvents = [
  { time: "2 min ago", title: "WAF rule blocked a suspicious request", detail: "203.0.113.42 · SQL injection signature", status: "danger" as const },
  { time: "8 min ago", title: "Certificate renewed successfully", detail: "api.bearust.local · valid for 90 days", status: "healthy" as const },
  { time: "14 min ago", title: "New node joined the cluster", detail: "edge-jakarta-03 · 10.20.0.18", status: "info" as const },
  { time: "31 min ago", title: "Rate limit policy switched to adaptive", detail: "public-api · 1,000 requests/minute", status: "warning" as const },
];
const demoHosts: Host[] = [
  { id: 1, name: "Public API", domain: "api.bearust.local", upstream_host: "api-pool", upstream_port: 8080, tls_mode: "letsencrypt", certificate_id: 1, enabled: true },
  { id: 2, name: "Admin Console", domain: "console.bearust.local", upstream_host: "console", upstream_port: 3000, tls_mode: "letsencrypt", certificate_id: 1, enabled: true },
  { id: 3, name: "Documentation", domain: "docs.bearust.local", upstream_host: "docs", upstream_port: 8080, tls_mode: "internal", certificate_id: null, enabled: true },
];

export function Dashboard() {
  const [range, setRange] = useState("configured");
  const [retentionMinutes, setRetentionMinutes] = useState(DEMO_MODE ? 7 * 1440 : 1440);
  const [summary, setSummary] = useState<AnalyticsSummary | null>(DEMO_MODE ? demoSummary : null);
  const [dimensions, setDimensions] = useState<AnalyticsDimensions | null>(DEMO_MODE ? demoDimensions : null);
  const [timeseries, setTimeseries] = useState<AnalyticsBucket[]>([]);
  const [hosts, setHosts] = useState<Host[]>(DEMO_MODE ? demoHosts : []);
  const [cluster, setCluster] = useState<ClusterSnapshot | null>(DEMO_MODE ? demoCluster : null);
  const [events, setEvents] = useState(DEMO_MODE ? demoEvents : []);
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [error, setError] = useState("");
  const [refreshToken, setRefreshToken] = useState(0);

  useRealtimeRefresh(["proxy_hosts.changed", "certificates.changed", "analytics.changed", "audit", "cluster.changed"], () => setRefreshToken((value) => value + 1));

  useEffect(() => {
    if (DEMO_MODE) return;
    let cancelled = false;
    const windowMinutes = range === "24h" ? Math.min(retentionMinutes, 1_440) : retentionMinutes;
    const from = new Date(Date.now() - windowMinutes * 60_000).toISOString();
    setLoading(true);
    setError("");
    void Promise.allSettled([
      api.hosts(),
      api.getAnalyticsRetention(),
      api.getAnalyticsSummary({ from, limit: 10080 }),
      api.getAnalyticsTimeseries({ from, limit: 10080 }),
      api.getAnalyticsDimensions({ from, limit: 10080 }),
      api.clusterStatus(),
      api.auditLogs({ page: 1, page_size: 5 }),
    ]).then((results) => {
      if (cancelled) return;
      const [hostResult, retentionResult, summaryResult, timeseriesResult, dimensionsResult, clusterResult, auditResult] = results;
      if (hostResult.status === "fulfilled") setHosts(hostResult.value);
      if (retentionResult.status === "fulfilled") setRetentionMinutes(retentionResult.value.retention_minutes);
      if (summaryResult.status === "fulfilled") setSummary(summaryResult.value);
      if (timeseriesResult.status === "fulfilled") setTimeseries(timeseriesResult.value);
      if (dimensionsResult.status === "fulfilled") setDimensions(dimensionsResult.value);
      if (clusterResult.status === "fulfilled") setCluster(clusterResult.value);
      if (auditResult.status === "fulfilled") setEvents(auditResult.value.items.map(toEvent));
      const rejected = results.find((result) => result.status === "rejected");
      if (rejected?.status === "rejected") setError(sanitizeError(rejected.reason));
    }).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => { cancelled = true; };
  }, [range, refreshToken, retentionMinutes]);

  const chartData = useMemo(() => {
    if (DEMO_MODE) return demoTraffic;
    return timeseries.slice(-24).map((bucket) => ({
      name: new Intl.DateTimeFormat(undefined, { hour: "2-digit", minute: "2-digit" }).format(new Date(bucket.timestamp)),
      requests: bucket.requests,
      blocked: bucket.waf_blocks + bucket.bot_blocks + bucket.bot_challenges + bucket.rate_limited,
    }));
  }, [timeseries]);

  const topHosts = useMemo(() => {
    if (DEMO_MODE) return demoHosts.map((host, index) => ({ host: host.domain, requests: [12400, 9800, 6200][index] ?? 0, latency: [38, 44, 51][index] ?? 0, status: index === 2 ? "warning" as const : "healthy" as const }));
    const totals = new Map<number, { requests: number; latency: number; samples: number }>();
    for (const bucket of timeseries) {
      const current = totals.get(bucket.proxy_host_id) ?? { requests: 0, latency: 0, samples: 0 };
      current.requests += bucket.requests;
      if (bucket.p95_ms != null) { current.latency += bucket.p95_ms; current.samples += 1; }
      totals.set(bucket.proxy_host_id, current);
    }
    return [...totals.entries()].sort(([, left], [, right]) => right.requests - left.requests).slice(0, 5).map(([hostId, total]) => ({
      host: hosts.find((host) => host.id === hostId)?.domain ?? `Host #${hostId}`,
      requests: total.requests,
      latency: total.samples ? Math.round(total.latency / total.samples) : null,
      status: hosts.find((host) => host.id === hostId)?.enabled === false ? "warning" as const : "healthy" as const,
    }));
  }, [hosts, timeseries]);

  const exportReport = () => {
    const payload = JSON.stringify({ generated_at: new Date().toISOString(), summary, timeseries }, null, 2);
    const url = URL.createObjectURL(new Blob([payload], { type: "application/json" }));
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = `bearust-report-${new Date().toISOString().slice(0, 10)}.json`;
    anchor.click();
    URL.revokeObjectURL(url);
    toast.success("Report downloaded");
  };

  const requests = summary?.requests ?? 0;
  const blocked = summary ? summary.waf_blocks + summary.bot_blocks + summary.bot_challenges + summary.rate_limited : 0;
  const healthyNodes = cluster ? (cluster.cluster_enabled ? `${cluster.healthy_peers} / ${Math.max(cluster.total_peers, cluster.healthy_peers)}` : "1 / 1") : "—";

  return (
    <Main>
      <PageHeader title="Dashboard" description={DEMO_MODE ? "A preview of your BeaRust edge infrastructure." : "Live telemetry from your BeaRust control plane."} action={<><Badge variant="outline" className="hidden gap-1.5 rounded-full sm:inline-flex"><span className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : loading ? "bg-amber-500" : "bg-emerald-500"}`} />{DEMO_MODE ? "Demo data" : loading ? "Loading telemetry" : "API connected"}</Badge><Button variant="outline" onClick={exportReport} disabled={loading}><Download />Export report</Button></>} />
      {error && <div role="alert" className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>}

      <Tabs defaultValue="overview" className="space-y-6">
        <div className="flex items-center justify-between gap-4 overflow-x-auto pb-1"><TabsList><TabsTrigger value="overview">Overview</TabsTrigger><TabsTrigger value="analytics">Analytics</TabsTrigger></TabsList><select aria-label="Dashboard date range" value={range} onChange={(event) => setRange(event.target.value)} className="hidden h-9 rounded-md border border-input bg-background px-3 text-sm shadow-xs outline-none focus:ring-2 focus:ring-ring/50 sm:block"><option value="configured">Configured retention ({formatDuration(retentionMinutes)})</option><option value="24h">Last 24 hours</option></select></div>
        <TabsContent value="overview" className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-5"><MetricCard title="Protected hosts" value={String(hosts.length)} detail={DEMO_MODE ? "3 added this month" : `${hosts.filter((host) => host.enabled).length} currently enabled`} trend="up" icon={Globe2} /><MetricCard title="Requests processed" value={formatCompact(requests)} detail={summary ? `${formatCompact(summary.status_2xx)} successful responses` : "Waiting for telemetry"} trend="up" icon={Activity} /><MetricCard title="Bandwidth" value={formatBytes(dimensions?.bandwidth_bytes ?? summary?.bandwidth_bytes ?? 0)} detail={`Configured window · ${formatDuration(retentionMinutes)}`} trend="neutral" icon={Gauge} /><MetricCard title="Threats blocked" value={formatCompact(blocked)} detail={summary ? `${formatCompact(summary.waf_blocks)} WAF blocks` : "Waiting for telemetry"} trend="up" icon={Ban} /><MetricCard title="Healthy nodes" value={healthyNodes} detail={cluster?.raft_sync_state ?? "Cluster status unavailable"} trend="neutral" icon={Server} /></div>
          <div className="grid gap-4 lg:grid-cols-7"><Card className="lg:col-span-4"><CardHeader><CardTitle>Traffic overview</CardTitle><CardDescription>{DEMO_MODE ? "Preview traffic for the selected period." : "Requests and security events reported by the analytics service."}</CardDescription></CardHeader><CardContent className="ps-2"><TrafficChart data={chartData} /></CardContent></Card><Card className="lg:col-span-3"><CardHeader><CardTitle>Edge health</CardTitle><CardDescription>{cluster ? `${cluster.local_node_id} · ${cluster.raft_role}` : "Cluster status at a glance."}</CardDescription></CardHeader><CardContent className="space-y-5"><div className="flex items-center justify-between"><div className="flex items-center gap-3"><div className="rounded-lg bg-emerald-500/10 p-2 text-emerald-600"><ShieldCheck className="size-5" /></div><div><p className="text-sm font-medium">Protection engine</p><p className="text-xs text-muted-foreground">WAF and edge policy telemetry</p></div></div><StatusBadge status={!summary ? "info" : summary.status_5xx > 0 ? "warning" : "healthy"}>{!summary ? "Unavailable" : summary.status_5xx > 0 ? "Review" : "Operational"}</StatusBadge></div>{cluster ? <div className="space-y-3">{cluster.peers.length === 0 ? <div className="rounded-lg border bg-muted/30 p-3 text-sm text-muted-foreground">{cluster.cluster_enabled ? "No remote peer details reported." : "Standalone node mode."}</div> : cluster.peers.slice(0, 4).map((peer) => <div className="flex items-center justify-between text-sm" key={peer.node_id}><span className="truncate">{peer.node_id}</span><StatusBadge status={peer.status === "healthy" ? "healthy" : "warning"}>{peer.status}{peer.latency_ms == null ? "" : ` · ${peer.latency_ms}ms`}</StatusBadge></div>)}</div> : <div className="space-y-2"><div className="flex items-center justify-between text-sm"><span className="text-muted-foreground">Cluster status</span><span className="font-medium">Unavailable</span></div><div className="h-2 rounded-full bg-muted"><div className="h-2 w-1/2 rounded-full bg-amber-500" /></div></div>}<Button variant="outline" className="w-full" asChild><Link to="/operations">View operations <ArrowUpRight /></Link></Button></CardContent></Card></div>
          <div className="grid gap-4 lg:grid-cols-7"><Card className="lg:col-span-4"><CardHeader className="flex flex-row items-center justify-between space-y-0"><div><CardTitle>Recent security events</CardTitle><CardDescription>{DEMO_MODE ? "Preview activity from the edge." : "Recent audit events from the control plane."}</CardDescription></div><Button variant="ghost" size="sm" asChild><Link to="/audit-log">View all</Link></Button></CardHeader><CardContent><div className="space-y-5">{events.length === 0 ? <p className="text-sm text-muted-foreground">No recent audit events are available.</p> : events.map((event) => <div key={`${event.title}-${event.time}`} className="flex items-start gap-3"><StatusBadge status={event.status}>{event.status === "danger" ? "Blocked" : event.status === "healthy" ? "Healthy" : event.status === "warning" ? "Review" : "Info"}</StatusBadge><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{event.title}</p><p className="truncate text-xs text-muted-foreground">{event.detail}</p></div><time className="shrink-0 text-xs text-muted-foreground">{event.time}</time></div>)}</div></CardContent></Card><Card className="lg:col-span-3"><CardHeader><CardTitle>Top proxy hosts</CardTitle><CardDescription>Highest request volume in this period.</CardDescription></CardHeader><CardContent><Table><TableHeader><TableRow><TableHead>Host</TableHead><TableHead>Requests</TableHead><TableHead>State</TableHead></TableRow></TableHeader><TableBody>{topHosts.map((host) => <TableRow key={host.host}><TableCell><div className="font-medium">{host.host}</div><div className="text-xs text-muted-foreground">{host.latency == null ? "No latency" : `${host.latency}ms avg p95`}</div></TableCell><TableCell className="font-mono text-xs">{formatCompact(host.requests)}</TableCell><TableCell><StatusBadge status={host.status}>{host.status === "healthy" ? "Live" : "Watch"}</StatusBadge></TableCell></TableRow>)}</TableBody></Table>{topHosts.length === 0 && <p className="py-6 text-center text-sm text-muted-foreground">No traffic by host yet.</p>}</CardContent></Card></div>
        </TabsContent>
        <TabsContent value="analytics" className="space-y-6"><Card><CardHeader><CardTitle>Traffic analytics</CardTitle><CardDescription>Use the Analytics page for host filters, baselines, anomalies, and adaptive tuning.</CardDescription></CardHeader><CardContent><TrafficChart data={chartData} /></CardContent></Card><div className="grid gap-4 sm:grid-cols-3"><MetricCard title="Successful responses" value={formatCompact(summary?.status_2xx ?? 0)} detail="HTTP 2xx" trend="neutral" icon={Users} /><MetricCard title="P95 latency" value={summary?.p95_ms == null ? "—" : `${summary.p95_ms}ms`} detail="Reported by edge telemetry" trend="down" icon={Activity} /><MetricCard title="Origin errors" value={formatCompact((summary?.status_4xx ?? 0) + (summary?.status_5xx ?? 0))} detail="HTTP 4xx + 5xx" trend="neutral" icon={Server} /></div></TabsContent>
      </Tabs>
    </Main>
  );
}

function toEvent(item: AuditLogItem) {
  const denied = /denied|failed|error|blocked/i.test(`${item.event} ${item.details}`);
  return { time: relativeTime(item.created_at), title: item.event.replaceAll("_", " "), detail: item.details || "Control-plane event", status: denied ? "danger" as const : /certificate|health|login/i.test(item.event) ? "healthy" as const : "info" as const };
}

function relativeTime(value: string) {
  const timestamp = new Date(value).getTime();
  if (!Number.isFinite(timestamp)) return value;
  const minutes = Math.max(0, Math.round((Date.now() - timestamp) / 60_000));
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  return `${Math.round(hours / 24)} d ago`;
}

function formatCompact(value: number) {
  return new Intl.NumberFormat(undefined, { notation: "compact", maximumFractionDigits: 1 }).format(value);
}

function formatBytes(value: number) {
  if (value < 1024) return `${value} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let size = value;
  let index = -1;
  do { size /= 1024; index += 1; } while (size >= 1024 && index < units.length - 1);
  return `${size.toFixed(size >= 10 ? 0 : 1)} ${units[index]}`;
}

function formatDuration(minutes: number) {
  if (minutes % 1440 === 0) return `${minutes / 1440}d`;
  if (minutes >= 60) return `${Math.round(minutes / 60)}h`;
  return `${minutes}m`;
}
