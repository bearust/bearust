import { useEffect, useState } from "react";
import { Network, RefreshCw, Server, ShieldCheck } from "lucide-react";
import { api, type ClusterSnapshot } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { sanitizeError } from "@/lib/errors";
import { useRealtimeRefresh } from "@/hooks/use-realtime-refresh";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";

const demoSnapshot: ClusterSnapshot = { local_node_id: "edge-jakarta-01", cluster_enabled: true, total_peers: 3, healthy_peers: 3, peers: [{ node_id: "edge-jakarta-02", status: "healthy", latency_ms: 4, error: null }, { node_id: "edge-jakarta-03", status: "healthy", latency_ms: 7, error: null }], timestamp: "2026-08-16T09:42:00Z", raft_role: "leader", raft_leader_id: "edge-jakarta-01", raft_term: 24, raft_last_log_index: 1284, raft_commit_index: 1284, raft_quorum_available: true, raft_sync_state: "leader_ready" };

export function Cluster() {
  const [snapshot, setSnapshot] = useState<ClusterSnapshot | null>(DEMO_MODE ? demoSnapshot : null);
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [error, setError] = useState("");
  const refresh = async () => {
    if (DEMO_MODE) return;
    setLoading(true); setError("");
    try { setSnapshot(await api.clusterStatus()); } catch (exception) { setError(sanitizeError(exception)); } finally { setLoading(false); }
  };
  useEffect(() => { void refresh(); if (DEMO_MODE) return; const timer = window.setInterval(() => void refresh(), 15_000); return () => window.clearInterval(timer); }, []);
  useRealtimeRefresh(["cluster.changed"], refresh);
  const healthy = snapshot?.cluster_enabled ? snapshot.healthy_peers : 1;
  const total = snapshot?.cluster_enabled ? Math.max(snapshot.total_peers, healthy) : 1;
  return <Main>
    <PageHeader title="Cluster" description="Monitor node health, Raft leadership, and synchronization state." action={<><Badge variant="outline" className="hidden gap-1.5 rounded-full sm:inline-flex"><span className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : "bg-emerald-500"}`} />{DEMO_MODE ? "Demo data" : "API connected"}</Badge><Button variant="outline" size="icon" aria-label="Refresh cluster" onClick={() => void refresh()} disabled={loading}><RefreshCw className={loading ? "animate-spin" : ""} /></Button></>} />
    {error && <div role="alert" className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>}
    <div className="mb-6 grid gap-4 sm:grid-cols-3"><Summary icon={Server} label="Healthy nodes" value={`${healthy} / ${total}`} detail={snapshot?.cluster_enabled ? "Peer health checks" : "Standalone mode"} /><Summary icon={Network} label="Raft role" value={snapshot?.raft_role ?? "—"} detail={snapshot?.raft_leader_id ? `Leader: ${snapshot.raft_leader_id}` : "No leader reported"} /><Summary icon={ShieldCheck} label="Quorum" value={snapshot?.raft_quorum_available ? "Available" : "Unavailable"} detail={snapshot?.raft_sync_state ?? "Waiting for status"} /></div>
    <div className="grid gap-6 lg:grid-cols-5">
      <Card className="lg:col-span-3"><CardHeader><CardTitle>Peer status</CardTitle><CardDescription>{snapshot?.local_node_id ?? "Cluster status is loading."} · last update {snapshot ? formatDate(snapshot.timestamp) : "—"}</CardDescription></CardHeader><CardContent>{loading ? <div className="h-40 animate-pulse rounded-md bg-muted" /> : <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="pb-3">Node</th><th className="pb-3">Status</th><th className="pb-3">Latency</th><th className="pb-3">Error</th></tr></thead><tbody>{snapshot?.peers.map((peer) => <tr className="border-b last:border-0" key={peer.node_id}><td className="py-4 font-medium">{peer.node_id}</td><td className="py-4"><StatusBadge status={peer.status === "healthy" ? "healthy" : "warning"}>{peer.status}</StatusBadge></td><td className="py-4 font-mono text-xs">{peer.latency_ms == null ? "—" : `${peer.latency_ms}ms`}</td><td className="max-w-56 truncate py-4 text-xs text-muted-foreground">{peer.error ?? "—"}</td></tr>)}</tbody></table>{snapshot?.peers.length === 0 && <p className="py-8 text-center text-sm text-muted-foreground">No remote peers are configured.</p>}</div>}</CardContent></Card>
      <Card className="lg:col-span-2"><CardHeader><CardTitle>Consensus state</CardTitle><CardDescription>Read-only status from the cluster service.</CardDescription></CardHeader><CardContent className="space-y-3"><Row label="Term" value={String(snapshot?.raft_term ?? "—")} /><Row label="Last log index" value={String(snapshot?.raft_last_log_index ?? "—")} /><Row label="Commit index" value={String(snapshot?.raft_commit_index ?? "—")} /><Row label="Sync state" value={snapshot?.raft_sync_state ?? "—"} /></CardContent></Card>
    </div>
    <Card className="mt-6"><CardHeader><CardTitle>High-availability checklist</CardTitle><CardDescription>Operational guidance for connecting this status surface to your deployment.</CardDescription></CardHeader><CardContent className="grid gap-3 text-sm text-muted-foreground md:grid-cols-3"><div className="rounded-lg border p-4"><p className="font-medium text-foreground">1. Stable identity</p><p className="mt-1">Give each node a persistent node ID and protect the cluster authentication token.</p></div><div className="rounded-lg border p-4"><p className="font-medium text-foreground">2. Network path</p><p className="mt-1">Allow peer health and Raft traffic between nodes without exposing it publicly.</p></div><div className="rounded-lg border p-4"><p className="font-medium text-foreground">3. Quorum before writes</p><p className="mt-1">Treat an unavailable quorum as an operational incident before applying global changes.</p></div></CardContent></Card>
  </Main>;
}

function Summary({ icon: Icon, label, value, detail }: { icon: typeof Server; label: string; value: string; detail: string }) { return <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle><Icon className="size-4 text-muted-foreground" /></CardHeader><CardContent><p className="text-2xl font-bold capitalize tabular-nums">{value}</p><p className="text-xs text-muted-foreground">{detail}</p></CardContent></Card>; }
function Row({ label, value }: { label: string; value: string }) { return <div className="flex items-center justify-between gap-4 rounded-lg border bg-muted/30 p-3 text-sm"><span className="text-muted-foreground">{label}</span><span className="font-mono text-xs">{value}</span></div>; }
function formatDate(value: string) { const date = new Date(value); return Number.isNaN(date.getTime()) ? value : new Intl.DateTimeFormat(undefined, { dateStyle: "medium", timeStyle: "short" }).format(date); }
