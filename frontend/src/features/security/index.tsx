import { useEffect, useState, type FormEvent } from "react";
import { Link } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Activity, Bot, Check, Download, FilePlus2, LockKeyhole, Plus, RefreshCw, ShieldCheck, SlidersHorizontal, Trash2, Upload } from "lucide-react";
import { api, type BotConfig, type BotMode, type RateLimitAction, type RateLimitConfig, type TrustedCrawler, type WafAction, type WafConfig, type WafMode, type WafRule } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { sanitizeError } from "@/lib/errors";
import { useRealtimeRefresh } from "@/hooks/use-realtime-refresh";
import { useAuthStore } from "@/stores/auth-store";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

const demoWafConfig: WafConfig = { mode: "block", updated_at: "2026-08-16T09:42:00Z" };
const demoRules: WafRule[] = [
  { id: 1, name: "SQL injection signatures", source: "OWASP CRS", category: "sqli", severity: "high", enabled: true, action: "block", matcher_json: "{}", created_at: "2026-07-01T00:00:00Z", updated_at: "2026-08-16T00:00:00Z" },
  { id: 2, name: "Cross-site scripting", source: "OWASP CRS", category: "xss", severity: "high", enabled: true, action: "block", matcher_json: "{}", created_at: "2026-07-01T00:00:00Z", updated_at: "2026-08-16T00:00:00Z" },
  { id: 3, name: "Path traversal", source: "BeaRust semantic", category: "path_traversal", severity: "medium", enabled: true, action: "log", matcher_json: "{}", created_at: "2026-07-01T00:00:00Z", updated_at: "2026-08-16T00:00:00Z" },
];
const demoBotConfig: BotConfig = { mode: "challenge", threshold: 60, ttl_seconds: 900, updated_at: "2026-08-16T09:42:00Z" };
const demoCrawlers: TrustedCrawler[] = [{ id: 1, category: "trusted_crawler", weight: 10, trusted_user_agent: "Googlebot", trusted_domain: "googlebot.com", enabled: true }];
const demoRateConfig: RateLimitConfig = { enabled: true, action: "block", capacity: 1000, refill_per_second: 10, key_scope: "proxy_host_ip", updated_at: "2026-08-16T09:42:00Z" };
const emptyWafConfig: WafConfig = { mode: "monitor-only", updated_at: "" };
const emptyBotConfig: BotConfig = { mode: "monitor", threshold: 0, ttl_seconds: 0, updated_at: "" };
const emptyRateConfig: RateLimitConfig = { enabled: false, action: "monitor", capacity: 0, refill_per_second: 0, key_scope: "proxy_host_ip", updated_at: "" };

type RuleForm = { name: string; category: string; severity: string; action: WafAction; matcher: string };
const emptyRule: RuleForm = { name: "", category: "custom", severity: "medium", action: "inherit", matcher: '{"path":"/api"}' };

export function Security() {
  const user = useAuthStore((state) => state.user);
  const { t } = useTranslation();
  const isAdmin = user?.role === "admin";
  const initialTab = new URLSearchParams(window.location.search).get("tab");
  const [activeTab, setActiveTab] = useState(initialTab === "bot" ? "bot" : initialTab === "rate" ? "rate" : "waf");
  const [wafConfig, setWafConfig] = useState<WafConfig>(DEMO_MODE ? demoWafConfig : emptyWafConfig);
  const [rules, setRules] = useState<WafRule[]>(DEMO_MODE ? demoRules : []);
  const [botConfig, setBotConfig] = useState<BotConfig>(DEMO_MODE ? demoBotConfig : emptyBotConfig);
  const [crawlers, setCrawlers] = useState<TrustedCrawler[]>(DEMO_MODE ? demoCrawlers : []);
  const [rateConfig, setRateConfig] = useState<RateLimitConfig>(DEMO_MODE ? demoRateConfig : emptyRateConfig);
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [toml, setToml] = useState("");
  const [ruleOpen, setRuleOpen] = useState(false);
  const [confirmRule, setConfirmRule] = useState<WafRule | null>(null);
  const [ruleForm, setRuleForm] = useState<RuleForm>(emptyRule);

  const refresh = async () => {
    if (DEMO_MODE) return;
    setLoading(true);
    setError("");
    const results = await Promise.allSettled([api.wafConfig(), api.wafRules(), api.botConfig(), api.trustedCrawlers(), api.rateLimitConfig()]);
    const [waf, wafRules, bot, crawlerRows, rate] = results;
    if (waf.status === "fulfilled") setWafConfig(waf.value);
    if (wafRules.status === "fulfilled") setRules(wafRules.value);
    if (bot.status === "fulfilled") setBotConfig(bot.value);
    if (crawlerRows.status === "fulfilled") setCrawlers(crawlerRows.value);
    if (rate.status === "fulfilled") setRateConfig(rate.value);
    const rejected = results.find((result) => result.status === "rejected");
    if (rejected?.status === "rejected") setError(sanitizeError(rejected.reason));
    setLoading(false);
  };

  useEffect(() => { void refresh(); }, []);
  useRealtimeRefresh(["waf.changed", "bot.changed", "rate_limit.changed"], refresh);

  const updateWafMode = async () => {
    const mode: WafMode = wafConfig.mode === "block" ? "monitor-only" : "block";
    setBusy(true);
    try {
      if (DEMO_MODE) setWafConfig({ ...wafConfig, mode });
      else setWafConfig(await api.updateWafConfig({ mode }));
      toast.success(`WAF switched to ${mode === "block" ? "blocking" : "monitor-only"} mode`);
    } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };

  const saveRule = async (event: FormEvent) => {
    event.preventDefault();
    let matcher: unknown;
    try { matcher = JSON.parse(ruleForm.matcher); } catch { setError("Matcher must be valid JSON."); return; }
    setBusy(true);
    try {
      if (DEMO_MODE) setRules((current) => [...current, { id: Date.now(), name: ruleForm.name, source: "custom", category: ruleForm.category, severity: ruleForm.severity, enabled: true, action: ruleForm.action, matcher_json: ruleForm.matcher, created_at: new Date().toISOString(), updated_at: new Date().toISOString() }]);
      else await api.createWafRule({ name: ruleForm.name.trim(), category: ruleForm.category.trim(), severity: ruleForm.severity.trim(), action: ruleForm.action, matcher });
      if (!DEMO_MODE) await refresh();
      setRuleOpen(false); setRuleForm(emptyRule); toast.success("WAF rule created");
    } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };

  const toggleRule = async (rule: WafRule) => {
    if (rule.source !== "custom") { toast.info("Built-in rules are managed by the rule pack."); return; }
    setBusy(true);
    try {
      if (DEMO_MODE) setRules((current) => current.map((item) => item.id === rule.id ? { ...item, enabled: !item.enabled } : item));
      else { await api.updateWafRule(rule.id, { enabled: !rule.enabled }); await refresh(); }
    } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };

  const deleteRule = (rule: WafRule) => {
    setConfirmRule(rule);
  };

  const confirmDeleteRule = async () => {
    if (!confirmRule) return;
    const rule = confirmRule;
    setConfirmRule(null);
    setBusy(true);
    try {
      if (DEMO_MODE) setRules((current) => current.filter((item) => item.id !== rule.id));
      else { await api.deleteWafRule(rule.id); await refresh(); }
      toast.success("WAF rule deleted");
    } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };

  const importWaf = async () => {
    setBusy(true);
    try { if (DEMO_MODE) toast.success("Demo WAF configuration imported"); else { await api.importWafRules(toml); await refresh(); } setToml(""); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };
  const exportWaf = async () => {
    try { const value = DEMO_MODE ? "version = 1\nmode = 'block'\n" : await api.exportWafRules(); setToml(value); toast.success("WAF TOML loaded"); } catch (exception) { setError(sanitizeError(exception)); }
  };

  const saveBot = async (next: Pick<BotConfig, "mode" | "threshold" | "ttl_seconds">) => {
    setBusy(true);
    try { if (DEMO_MODE) setBotConfig({ ...botConfig, ...next }); else setBotConfig(await api.updateBotConfig(next)); toast.success("Bot policy saved"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };
  const toggleCrawler = async (crawler: TrustedCrawler) => {
    setBusy(true);
    try { if (DEMO_MODE) setCrawlers((current) => current.map((item) => item.id === crawler.id ? { ...item, enabled: !item.enabled } : item)); else { await api.updateTrustedCrawler(crawler.id, { user_agent: crawler.trusted_user_agent ?? "", domain: crawler.trusted_domain ?? "", enabled: !crawler.enabled }); await refresh(); } } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };
  const addCrawler = async (userAgent: string, domain: string) => {
    setBusy(true);
    try {
      if (DEMO_MODE) setCrawlers((current) => [...current, { id: Date.now(), category: "trusted_crawler", weight: 10, trusted_user_agent: userAgent, trusted_domain: domain, enabled: true }]);
      else { await api.createTrustedCrawler({ user_agent: userAgent, domain, enabled: true }); await refresh(); }
      toast.success("Trusted crawler added");
    } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };
  const deleteCrawler = async (crawler: TrustedCrawler) => {
    setBusy(true);
    try { if (DEMO_MODE) setCrawlers((current) => current.filter((item) => item.id !== crawler.id)); else { await api.deleteTrustedCrawler(crawler.id); await refresh(); } toast.success("Trusted crawler removed"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };
  const importBot = async () => {
    setBusy(true);
    try { if (DEMO_MODE) toast.success("Demo bot configuration imported"); else { await api.importBotConfig(toml); await refresh(); } setToml(""); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };
  const exportBot = async () => {
    try { const value = DEMO_MODE ? "version = 1\nmode = 'challenge'\nthreshold = 60\nttl_seconds = 900\n" : await api.exportBotConfig(); setToml(value); toast.success("Bot TOML loaded"); } catch (exception) { setError(sanitizeError(exception)); }
  };

  const saveRate = async (next: Pick<RateLimitConfig, "enabled" | "action" | "capacity" | "refill_per_second" | "key_scope">) => {
    setBusy(true);
    try { if (DEMO_MODE) setRateConfig({ ...rateConfig, ...next }); else setRateConfig(await api.updateRateLimitConfig(next)); toast.success("Rate-limit policy saved"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };

  return <Main><PageHeader title="Security" description="Tune the protection layers that guard your proxy hosts." action={<><Badge variant="outline" className="hidden gap-1.5 rounded-full sm:inline-flex"><span className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : "bg-emerald-500"}`} />{DEMO_MODE ? "Demo data" : "API connected"}</Badge><Button variant="outline" size="icon" aria-label="Refresh security policies" onClick={() => void refresh()} disabled={loading}><RefreshCw className={loading ? "animate-spin" : ""} /></Button></>} />
    {error && <div role="alert" className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>}
    <div className="mb-6 grid gap-4 sm:grid-cols-3"><SecuritySummary icon={ShieldCheck} label="WAF engine" status={wafConfig.mode === "block" ? "healthy" : "warning"} value={wafConfig.mode === "block" ? "Enforcing" : "Monitor only"} detail={`${rules.length} rules configured`} /><SecuritySummary icon={Bot} label="Bot protection" status={botConfig.mode === "monitor" ? "warning" : "healthy"} value={botConfig.mode === "monitor" ? "Monitoring" : botConfig.mode === "challenge" ? "Challenging" : "Blocking"} detail={`${crawlers.length} trusted crawler${crawlers.length === 1 ? "" : "s"}`} /><SecuritySummary icon={Activity} label="Rate limiting" status={rateConfig.enabled ? "healthy" : "warning"} value={rateConfig.enabled ? "Enabled" : "Paused"} detail={`${rateConfig.capacity.toLocaleString()} burst capacity`} /></div>
    <Card className="mb-6"><CardHeader><CardTitle>{t("security.coverageTitle")}</CardTitle><CardDescription>{t("security.coverageDescription")}</CardDescription></CardHeader><CardContent className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{securityCoverage.map((item) => <SecurityCapability key={item.key} title={t(`security.${item.key}Title`)} detail={t(`security.${item.key}Detail`)} status={item.status === "available" ? "healthy" : item.status === "partial" ? "info" : "warning"} label={t(`security.${item.status}`)} />)}</CardContent></Card>
    <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6"><TabsList><TabsTrigger value="waf">WAF rules</TabsTrigger><TabsTrigger value="bot">Bot protection</TabsTrigger><TabsTrigger value="rate">Rate limiting</TabsTrigger></TabsList>
      <TabsContent value="waf"><WafPanel config={wafConfig} rules={rules} canWrite={isAdmin} busy={busy} onToggle={() => void updateWafMode()} onAdd={() => setRuleOpen(true)} onToggleRule={(rule) => void toggleRule(rule)} onDelete={(rule) => void deleteRule(rule)} toml={toml} setToml={setToml} onImport={() => void importWaf()} onExport={() => void exportWaf()} /></TabsContent>
      <TabsContent value="bot"><BotPanel config={botConfig} crawlers={crawlers} canWrite={isAdmin} busy={busy} onSave={(next) => void saveBot(next)} onToggleCrawler={(crawler) => void toggleCrawler(crawler)} onDeleteCrawler={(crawler) => void deleteCrawler(crawler)} onAddCrawler={(userAgent, domain) => void addCrawler(userAgent, domain)} toml={toml} setToml={setToml} onImport={() => void importBot()} onExport={() => void exportBot()} /></TabsContent>
      <TabsContent value="rate"><RatePanel config={rateConfig} canWrite={isAdmin} busy={busy} onSave={(next) => void saveRate(next)} /></TabsContent>
    </Tabs>
    <Dialog open={ruleOpen} onOpenChange={setRuleOpen}><DialogContent><DialogHeader><DialogTitle>Create custom WAF rule</DialogTitle><DialogDescription>The matcher is validated by the BeaRust WAF compiler before it is persisted.</DialogDescription></DialogHeader><form id="rule-form" className="space-y-4" onSubmit={(event) => void saveRule(event)}><div className="grid gap-4 sm:grid-cols-2"><Field label="Rule name" value={ruleForm.name} onChange={(value) => setRuleForm({ ...ruleForm, name: value })} placeholder="Block suspicious path" /><Field label="Category" value={ruleForm.category} onChange={(value) => setRuleForm({ ...ruleForm, category: value })} placeholder="custom" /><Field label="Severity" value={ruleForm.severity} onChange={(value) => setRuleForm({ ...ruleForm, severity: value })} placeholder="medium" /><div className="space-y-2"><Label htmlFor="rule-action">Action</Label><select id="rule-action" value={ruleForm.action} onChange={(event) => setRuleForm({ ...ruleForm, action: event.target.value as WafAction })} className="h-9 w-full rounded-md border border-input bg-background px-3 py-2 text-sm"><option value="inherit">Inherit</option><option value="allow">Allow</option><option value="log">Log</option><option value="block">Block</option></select></div></div><div className="space-y-2"><Label htmlFor="rule-matcher">Matcher JSON</Label><textarea id="rule-matcher" value={ruleForm.matcher} onChange={(event) => setRuleForm({ ...ruleForm, matcher: event.target.value })} className="min-h-28 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs outline-none focus:ring-2 focus:ring-ring/50" /></div></form><DialogFooter><Button variant="outline" onClick={() => setRuleOpen(false)}>Cancel</Button><Button type="submit" form="rule-form" disabled={busy || !isAdmin}><FilePlus2 />Create rule</Button></DialogFooter></DialogContent></Dialog>
    <ConfirmDialog
      open={confirmRule != null}
      onOpenChange={(open) => { if (!open && !busy) setConfirmRule(null); }}
      title="Delete WAF rule?"
      description={confirmRule ? `The custom rule “${confirmRule.name}” will stop evaluating traffic immediately.` : "The selected custom WAF rule will be removed."}
      pending={busy}
      onConfirm={() => void confirmDeleteRule()}
    />
  </Main>;
}

const securityCoverage = [
  { key: "waf", status: "available" },
  { key: "virtualPatching", status: "available" },
  { key: "botChallenge", status: "partial" },
  { key: "ipGeo", status: "notExposed" },
  { key: "authChallenge", status: "notExposed" },
  { key: "falsePositiveLoop", status: "partial" },
] as const;

function SecurityCapability({ title, detail, status, label }: { title: string; detail: string; status: "healthy" | "warning" | "info"; label: string }) {
  return <div className="rounded-lg border p-4"><div className="flex flex-wrap items-center justify-between gap-2"><p className="text-sm font-medium">{title}</p><StatusBadge status={status}>{label}</StatusBadge></div><p className="mt-2 text-xs leading-5 text-muted-foreground">{detail}</p></div>;
}

function WafPanel({ config, rules, canWrite, busy, onToggle, onAdd, onToggleRule, onDelete, toml, setToml, onImport, onExport }: { config: WafConfig; rules: WafRule[]; canWrite: boolean; busy: boolean; onToggle: () => void; onAdd: () => void; onToggleRule: (rule: WafRule) => void; onDelete: (rule: WafRule) => void; toml: string; setToml: (value: string) => void; onImport: () => void; onExport: () => void }) {
  return <Card><CardHeader className="flex flex-row items-start justify-between gap-4"><div><CardTitle>Web application firewall</CardTitle><CardDescription>Signature and semantic detection rules for every protected host.</CardDescription></div><div className="flex flex-wrap justify-end gap-2"><Button variant="outline" onClick={onAdd} disabled={!canWrite}><Plus />Add rule</Button><Button variant={config.mode === "block" ? "outline" : "secondary"} onClick={onToggle} disabled={!canWrite || busy} aria-pressed={config.mode === "block"}><LockKeyhole />{config.mode === "block" ? "Switch to monitor" : "Enable blocking"}</Button></div></CardHeader><CardContent><div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="pb-3 font-medium">Rule family</th><th className="pb-3 font-medium">Source</th><th className="pb-3 font-medium">Severity</th><th className="pb-3 font-medium">Action</th><th className="pb-3 font-medium">State</th><th className="pb-3 text-right font-medium">Controls</th></tr></thead><tbody>{rules.map((rule) => <tr key={rule.id} className="border-b last:border-0"><td className="py-4 font-medium">{rule.name}</td><td className="py-4 text-muted-foreground">{rule.source}</td><td className="py-4"><Badge variant={rule.severity === "high" || rule.severity === "critical" ? "destructive" : "secondary"}>{rule.severity}</Badge></td><td className="py-4 font-mono text-xs">{rule.action}</td><td className="py-4"><StatusBadge status={rule.enabled ? "healthy" : "warning"}>{rule.enabled ? "Enabled" : "Disabled"}</StatusBadge></td><td className="py-4 text-right"><div className="flex justify-end gap-1"><Button variant="ghost" size="icon" aria-label={`Toggle ${rule.name}`} onClick={() => onToggleRule(rule)} disabled={!canWrite || busy}><Check className={rule.enabled ? "text-emerald-600" : "text-muted-foreground"} /></Button>{rule.source === "custom" && <Button variant="ghost" size="icon" aria-label={`Delete ${rule.name}`} onClick={() => onDelete(rule)} disabled={!canWrite || busy}><Trash2 /></Button>}</div></td></tr>)}</tbody></table></div>{rules.length === 0 && <p className="py-8 text-center text-sm text-muted-foreground">No WAF rules are configured.</p>}<div className="mt-6 space-y-3 border-t pt-5"><div><p className="text-sm font-medium">Rule pack import/export</p><p className="text-xs text-muted-foreground">Use the same TOML format as the control-plane configuration.</p></div><textarea aria-label="WAF TOML" value={toml} onChange={(event) => setToml(event.target.value)} className="min-h-28 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs outline-none focus:ring-2 focus:ring-ring/50" /><div className="flex flex-wrap gap-2"><Button variant="outline" onClick={onImport} disabled={!canWrite || busy || !toml.trim()}><Upload />Import TOML</Button><Button variant="outline" onClick={onExport} disabled={busy}><Download />Load export</Button></div></div></CardContent></Card>;
}

function BotPanel({ config, crawlers, canWrite, busy, onSave, onToggleCrawler, onDeleteCrawler, onAddCrawler, toml, setToml, onImport, onExport }: { config: BotConfig; crawlers: TrustedCrawler[]; canWrite: boolean; busy: boolean; onSave: (next: Pick<BotConfig, "mode" | "threshold" | "ttl_seconds">) => void; onToggleCrawler: (crawler: TrustedCrawler) => void; onDeleteCrawler: (crawler: TrustedCrawler) => void; onAddCrawler: (userAgent: string, domain: string) => void; toml: string; setToml: (value: string) => void; onImport: () => void; onExport: () => void }) {
  const [mode, setMode] = useState<BotMode>(config.mode); const [threshold, setThreshold] = useState(String(config.threshold)); const [ttl, setTtl] = useState(String(config.ttl_seconds)); const [ua, setUa] = useState(""); const [domain, setDomain] = useState("");
  useEffect(() => { setMode(config.mode); setThreshold(String(config.threshold)); setTtl(String(config.ttl_seconds)); }, [config]);
  const submit = (event: FormEvent) => { event.preventDefault(); onSave({ mode, threshold: Number(threshold), ttl_seconds: Number(ttl) }); };
  const addCrawler = (event: FormEvent) => { event.preventDefault(); if (!ua.trim() || !domain.trim()) return; onAddCrawler(ua.trim(), domain.trim()); setUa(""); setDomain(""); };
  return <div className="grid gap-4 lg:grid-cols-5"><Card className="lg:col-span-3"><CardHeader><CardTitle>Bot challenge policy</CardTitle><CardDescription>Control how suspicious fingerprints are monitored, challenged, or blocked.</CardDescription></CardHeader><CardContent><form className="grid gap-4 sm:grid-cols-3" onSubmit={submit}><div className="space-y-2"><Label htmlFor="bot-mode">Mode</Label><select id="bot-mode" value={mode} onChange={(event) => setMode(event.target.value as BotMode)} disabled={!canWrite || busy} className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"><option value="monitor">Monitor</option><option value="challenge">Challenge</option><option value="block">Block</option></select></div><Field label="Risk threshold" type="number" value={threshold} onChange={setThreshold} disabled={!canWrite || busy} /><Field label="Challenge TTL (seconds)" type="number" value={ttl} onChange={setTtl} disabled={!canWrite || busy} /><Button type="submit" disabled={!canWrite || busy} className="sm:col-span-3"><SlidersHorizontal />Save bot policy</Button></form><div className="mt-6 border-t pt-5"><div className="mb-3"><p className="text-sm font-medium">Trusted crawlers</p><p className="text-xs text-muted-foreground">Allow known crawlers without lowering the global challenge policy.</p></div><div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="pb-3">User agent</th><th className="pb-3">Domain</th><th className="pb-3">State</th><th className="pb-3 text-right">Controls</th></tr></thead><tbody>{crawlers.map((crawler) => <tr className="border-b last:border-0" key={crawler.id}><td className="py-3 font-mono text-xs">{crawler.trusted_user_agent ?? "—"}</td><td className="py-3 text-muted-foreground">{crawler.trusted_domain ?? "—"}</td><td className="py-3"><StatusBadge status={crawler.enabled ? "healthy" : "warning"}>{crawler.enabled ? "Enabled" : "Disabled"}</StatusBadge></td><td className="py-3 text-right"><Button variant="ghost" size="sm" onClick={() => onToggleCrawler(crawler)} disabled={!canWrite || busy}>{crawler.enabled ? "Disable" : "Enable"}</Button><Button variant="ghost" size="icon" aria-label={`Delete ${crawler.trusted_user_agent ?? "crawler"}`} onClick={() => onDeleteCrawler(crawler)} disabled={!canWrite || busy}><Trash2 /></Button></td></tr>)}</tbody></table></div><form className="mt-4 grid gap-3 sm:grid-cols-2" onSubmit={addCrawler}><Field label="User agent" value={ua} onChange={setUa} disabled={!canWrite || busy} placeholder="ExampleBot" /><Field label="Trusted domain" value={domain} onChange={setDomain} disabled={!canWrite || busy} placeholder="example.com" /><Button type="submit" disabled={!canWrite || busy || !ua.trim() || !domain.trim()} className="sm:col-span-2"><Plus />Add crawler</Button></form></div></CardContent></Card><Card className="lg:col-span-2"><CardHeader><CardTitle>Bot policy exchange</CardTitle><CardDescription>Export a redacted TOML policy or import a reviewed configuration.</CardDescription></CardHeader><CardContent className="space-y-3"><textarea aria-label="Bot TOML" value={toml} onChange={(event) => setToml(event.target.value)} className="min-h-44 w-full rounded-md border border-input bg-background px-3 py-2 font-mono text-xs outline-none focus:ring-2 focus:ring-ring/50" /><div className="flex flex-wrap gap-2"><Button variant="outline" onClick={onImport} disabled={!canWrite || busy || !toml.trim()}><Upload />Import</Button><Button variant="outline" onClick={onExport} disabled={busy}><Download />Load export</Button></div><Button variant="secondary" className="w-full" asChild><Link to="/bot-challenge" search={{}}>Open browser challenge check</Link></Button></CardContent></Card></div>;
}

function RatePanel({ config, canWrite, busy, onSave }: { config: RateLimitConfig; canWrite: boolean; busy: boolean; onSave: (next: Pick<RateLimitConfig, "enabled" | "action" | "capacity" | "refill_per_second" | "key_scope">) => void }) {
  const [enabled, setEnabled] = useState(config.enabled); const [action, setAction] = useState<RateLimitAction>(config.action); const [capacity, setCapacity] = useState(String(config.capacity)); const [refill, setRefill] = useState(String(config.refill_per_second));
  useEffect(() => { setEnabled(config.enabled); setAction(config.action); setCapacity(String(config.capacity)); setRefill(String(config.refill_per_second)); }, [config]);
  const submit = (event: FormEvent) => { event.preventDefault(); onSave({ enabled, action, capacity: Number(capacity), refill_per_second: Number(refill), key_scope: "proxy_host_ip" }); };
  return <div className="grid gap-4 lg:grid-cols-2"><Card><CardHeader className="flex flex-row items-start justify-between"><div><CardTitle>Adaptive rate limiting</CardTitle><CardDescription>Apply a token-bucket policy per proxy-host IP.</CardDescription></div><StatusBadge status={config.enabled ? "healthy" : "warning"}>{config.enabled ? "Enabled" : "Paused"}</StatusBadge></CardHeader><CardContent><form className="grid gap-4 sm:grid-cols-2" onSubmit={submit}><label className="flex min-h-9 items-center gap-3 text-sm font-medium sm:col-span-2"><input type="checkbox" checked={enabled} onChange={(event) => setEnabled(event.target.checked)} disabled={!canWrite || busy} className="size-4 accent-primary" />Enable rate limiting</label><div className="space-y-2"><Label htmlFor="rate-action">Action</Label><select id="rate-action" value={action} onChange={(event) => setAction(event.target.value as RateLimitAction)} disabled={!canWrite || busy} className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"><option value="monitor">Monitor only</option><option value="block">Block limited requests</option></select></div><Field label="Burst capacity" type="number" value={capacity} onChange={setCapacity} disabled={!canWrite || busy} /><Field label="Refill / second" type="number" value={refill} onChange={setRefill} disabled={!canWrite || busy} /><div className="space-y-2"><Label htmlFor="rate-scope">Key scope</Label><Input id="rate-scope" value="proxy_host_ip" disabled /></div>{canWrite && <Button type="submit" disabled={busy} className="sm:col-span-2"><SlidersHorizontal />Save policy</Button>}</form></CardContent></Card><Card><CardHeader><CardTitle>Current policy</CardTitle><CardDescription>Values returned by the control plane.</CardDescription></CardHeader><CardContent className="space-y-3"><PolicyRow label="Mode" value={config.action === "block" ? "Blocking" : "Monitor only"} /><PolicyRow label="Burst capacity" value={config.capacity.toLocaleString()} /><PolicyRow label="Refill rate" value={`${config.refill_per_second}/second`} /><PolicyRow label="Scope" value={config.key_scope} /><Button variant="outline" className="mt-3 w-full" asChild><Link to="/analytics">Review traffic anomalies</Link></Button></CardContent></Card></div>;
}

function Field({ label, value, onChange, type = "text", placeholder, disabled = false }: { label: string; value: string; onChange: (value: string) => void; type?: string; placeholder?: string; disabled?: boolean }) { return <div className="space-y-2"><Label>{label}</Label><Input type={type} value={value} onChange={(event) => onChange(event.target.value)} placeholder={placeholder} disabled={disabled} required /></div>; }
function PolicyRow({ label, value }: { label: string; value: string }) { return <div className="flex items-center justify-between gap-4 rounded-lg border bg-muted/30 p-4 text-sm"><span className="text-muted-foreground">{label}</span><span className="font-medium">{value}</span></div>; }
function SecuritySummary({ icon: Icon, label, value, detail, status }: { icon: typeof ShieldCheck; label: string; value: string; detail: string; status: "healthy" | "warning" }) { return <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle><Icon className="size-4 text-muted-foreground" /></CardHeader><CardContent><div className="flex items-center gap-2"><span className="text-xl font-semibold">{value}</span><StatusBadge status={status}>{status === "healthy" ? "Healthy" : "Review"}</StatusBadge></div><p className="mt-1 text-xs text-muted-foreground">{detail}</p></CardContent></Card>; }
