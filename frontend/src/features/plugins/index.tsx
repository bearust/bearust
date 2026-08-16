import { useEffect, useState } from "react";
import { toast } from "sonner";
import { Activity, Blocks, Check, RefreshCw, RotateCw, Trash2 } from "lucide-react";
import { api, type PluginHealthResponse, type PluginStatus } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { sanitizeError } from "@/lib/errors";
import { useRealtimeRefresh } from "@/hooks/use-realtime-refresh";
import { useAuthStore } from "@/stores/auth-store";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";

const demoPlugins: PluginStatus[] = [{ id: "notify-sink-v2", display_name: "Notification sink", abi_version: 2, digest: "sha256:demo", enabled: true, loaded: true, last_error_code: null, created_at: "2026-07-01T00:00:00Z", updated_at: "2026-08-16T09:00:00Z", trust_status: "trusted" }];

export function Plugins() {
  const canManage = useAuthStore((state) => state.user?.role === "admin");
  const [plugins, setPlugins] = useState<PluginStatus[]>(DEMO_MODE ? demoPlugins : []);
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [health, setHealth] = useState<Record<string, PluginHealthResponse>>({});
  const [confirmPlugin, setConfirmPlugin] = useState<PluginStatus | null>(null);
  const refresh = async () => { if (DEMO_MODE) return; setLoading(true); setError(""); try { setPlugins(await api.plugins()); } catch (exception) { setError(sanitizeError(exception)); } finally { setLoading(false); } };
  useEffect(() => { void refresh(); }, []);
  useRealtimeRefresh(["plugins.changed"], refresh);
  const reload = async () => { setBusy("reload"); try { if (DEMO_MODE) toast.success("Plugins reloaded"); else { const result = await api.reloadPlugins(); await refresh(); toast.success("Plugins reloaded", { description: `${result.loaded} loaded, ${result.failed} failed.` }); } } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(null); } };
  const toggle = async (plugin: PluginStatus) => { setBusy(plugin.id); try { if (DEMO_MODE) setPlugins((current) => current.map((item) => item.id === plugin.id ? { ...item, enabled: !item.enabled, loaded: !item.enabled } : item)); else { const next = plugin.enabled ? await api.disablePlugin(plugin.id) : await api.enablePlugin(plugin.id); setPlugins((current) => current.map((item) => item.id === next.id ? next : item)); } toast.success(plugin.enabled ? "Plugin disabled" : "Plugin enabled"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(null); } };
  const unload = (plugin: PluginStatus) => { if (!canManage) return; setConfirmPlugin(plugin); };
  const confirmUnload = async () => { if (!confirmPlugin) return; const plugin = confirmPlugin; setConfirmPlugin(null); setBusy(plugin.id); try { if (DEMO_MODE) setPlugins((current) => current.map((item) => item.id === plugin.id ? { ...item, loaded: false } : item)); else { await api.unloadPlugin(plugin.id); await refresh(); } toast.success("Plugin unloaded"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(null); } };
  const checkHealth = async (plugin: PluginStatus) => { setBusy(`health-${plugin.id}`); try { const result = DEMO_MODE ? { status: 0, elapsed_ms: 2, detail: "ok" } : await api.pluginHealthCheck(plugin.id); setHealth((current) => ({ ...current, [plugin.id]: result })); toast.success("Plugin health check complete"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(null); } };
  return <Main><PageHeader title="Plugins" description="Inspect and operate the sandboxed WASM plugin lifecycle." action={<><Badge variant="outline" className="hidden gap-1.5 rounded-full sm:inline-flex"><span className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : "bg-emerald-500"}`} />{DEMO_MODE ? "Demo data" : "API connected"}</Badge><Button variant="outline" onClick={() => void reload()} disabled={!canManage || busy != null}><RotateCw />Reload from disk</Button><Button variant="outline" size="icon" aria-label="Refresh plugins" onClick={() => void refresh()} disabled={loading}><RefreshCw className={loading ? "animate-spin" : ""} /></Button></>} />
    {error && <div role="alert" className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>}
    <Card><CardHeader><CardTitle>Installed plugins</CardTitle><CardDescription>Only redacted lifecycle metadata crosses the control-plane boundary.</CardDescription></CardHeader><CardContent>{loading ? <div className="h-40 animate-pulse rounded-md bg-muted" /> : <div className="space-y-3">{plugins.map((plugin) => <div className="rounded-lg border p-4" key={plugin.id}><div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between"><div className="flex min-w-0 gap-3"><div className="rounded-lg bg-primary/10 p-2 text-primary"><Blocks className="size-5" /></div><div className="min-w-0"><p className="font-medium">{plugin.display_name}</p><p className="font-mono text-xs text-muted-foreground">{plugin.id} · ABI v{plugin.abi_version}</p><p className="mt-2 text-xs text-muted-foreground">Trust: {plugin.trust_status} · {plugin.digest}</p></div></div><div className="flex flex-wrap gap-2"><StatusBadge status={plugin.loaded ? "healthy" : "warning"}>{plugin.loaded ? "Loaded" : "Unloaded"}</StatusBadge><Badge variant={plugin.enabled ? "secondary" : "outline"}>{plugin.enabled ? "Enabled" : "Disabled"}</Badge></div></div><div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t pt-3"><div className="text-xs text-muted-foreground">{health[plugin.id] ? <span className="flex items-center gap-1 text-emerald-600"><Check className="size-3" />Healthy · {health[plugin.id].elapsed_ms}ms{health[plugin.id].detail ? ` · ${health[plugin.id].detail}` : ""}</span> : plugin.last_error_code ? <span className="text-destructive">Last error: {plugin.last_error_code}</span> : "No health check recorded"}</div><div className="flex gap-2"><Button variant="ghost" size="sm" onClick={() => void checkHealth(plugin)} disabled={busy != null}><Activity />Health check</Button><Button variant="outline" size="sm" onClick={() => void toggle(plugin)} disabled={!canManage || busy != null}>{plugin.enabled ? "Disable" : "Enable"}</Button><Button variant="ghost" size="icon" aria-label={`Unload ${plugin.display_name}`} onClick={() => void unload(plugin)} disabled={!canManage || busy != null}><Trash2 /></Button></div></div></div>)}</div>}{!loading && plugins.length === 0 && <div className="py-12 text-center text-sm text-muted-foreground">No plugins are installed.</div>}</CardContent></Card>
    <Card className="mt-6"><CardHeader><CardTitle>Plugin safety boundary</CardTitle><CardDescription>Operational facts exposed by the runtime.</CardDescription></CardHeader><CardContent className="grid gap-3 text-sm text-muted-foreground md:grid-cols-3"><div className="rounded-lg border p-4"><p className="font-medium text-foreground">Sandboxed execution</p><p className="mt-1">WASM modules are bounded by the runtime's ABI, fuel, memory, and timeout policies.</p></div><div className="rounded-lg border p-4"><p className="font-medium text-foreground">Trust status</p><p className="mt-1">Signature and trust state are shown as metadata; module bytes never enter the UI.</p></div><div className="rounded-lg border p-4"><p className="font-medium text-foreground">Audited changes</p><p className="mt-1">Reload, enable, disable, unload, and health operations are recorded by the control plane.</p></div></CardContent></Card>
    <ConfirmDialog
      open={confirmPlugin != null}
      onOpenChange={(open) => { if (!open && busy == null) setConfirmPlugin(null); }}
      title="Unload plugin?"
      description={confirmPlugin ? `${confirmPlugin.display_name} will be removed from the active runtime snapshot.` : "The selected plugin will be unloaded."}
      pending={busy != null}
      onConfirm={() => void confirmUnload()}
    />
  </Main>;
}
