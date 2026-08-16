import { useState } from "react";
import { toast } from "sonner";
import { Activity, Bot, Check, LockKeyhole, Plus, ShieldCheck, SlidersHorizontal } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";

const rules = [
  { name: "SQL injection signatures", source: "OWASP CRS", matches: "1,482", state: "Enforced" },
  { name: "Cross-site scripting", source: "OWASP CRS", matches: "734", state: "Enforced" },
  { name: "Path traversal", source: "BeaRust semantic", matches: "126", state: "Monitor" },
  { name: "Command injection", source: "BeaRust semantic", matches: "84", state: "Enforced" },
];

export function Security() {
  const initialTab = new URLSearchParams(window.location.search).get("tab");
  const [activeTab, setActiveTab] = useState(initialTab === "bot" ? "bot" : initialTab === "rate" ? "rate" : "waf");
  const [enabled, setEnabled] = useState({ waf: true, bot: true, rate: true });

  const toggle = (key: keyof typeof enabled) => {
    setEnabled((value) => ({ ...value, [key]: !value[key] }));
    toast.success(`${key === "waf" ? "WAF" : key === "bot" ? "Bot protection" : "Rate limiting"} ${enabled[key] ? "paused" : "enabled"}`);
  };

  return (
    <Main>
      <PageHeader title="Security" description="Tune the layers protecting your proxy hosts." action={<Button onClick={() => toast.success("Rule builder opened", { description: "The rule editor is ready for API wiring." })}><Plus />Add rule</Button>} />
      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        <SecuritySummary icon={ShieldCheck} label="WAF engine" status={enabled.waf ? "healthy" : "warning"} value={enabled.waf ? "Enforcing" : "Paused"} detail="2,426 requests blocked today" />
        <SecuritySummary icon={Bot} label="Bot protection" status={enabled.bot ? "healthy" : "warning"} value={enabled.bot ? "Active" : "Paused"} detail="98.6% challenge pass rate" />
        <SecuritySummary icon={Activity} label="Rate limiting" status={enabled.rate ? "healthy" : "warning"} value={enabled.rate ? "Adaptive" : "Paused"} detail="12 policies configured" />
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-6">
        <TabsList><TabsTrigger value="waf">WAF rules</TabsTrigger><TabsTrigger value="bot">Bot protection</TabsTrigger><TabsTrigger value="rate">Rate limiting</TabsTrigger></TabsList>
        <TabsContent value="waf"><WafPanel active={enabled.waf} onToggle={() => toggle("waf")} /></TabsContent>
        <TabsContent value="bot"><BotPanel active={enabled.bot} onToggle={() => toggle("bot")} /></TabsContent>
        <TabsContent value="rate"><RatePanel active={enabled.rate} onToggle={() => toggle("rate")} /></TabsContent>
      </Tabs>
    </Main>
  );
}

function WafPanel({ active, onToggle }: { active: boolean; onToggle: () => void }) {
  return <Card><CardHeader className="flex flex-row items-start justify-between gap-4"><div><CardTitle>Web application firewall</CardTitle><CardDescription>Signature and semantic detection rules for every protected host.</CardDescription></div><Button variant={active ? "outline" : "secondary"} onClick={onToggle} aria-pressed={active}><LockKeyhole />{active ? "Pause engine" : "Enable engine"}</Button></CardHeader><CardContent><div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr className="border-b text-left text-xs text-muted-foreground"><th className="pb-3 font-medium">Rule family</th><th className="pb-3 font-medium">Source</th><th className="pb-3 font-medium">Matches today</th><th className="pb-3 font-medium">Action</th></tr></thead><tbody>{rules.map((rule) => <tr key={rule.name} className="border-b last:border-0"><td className="py-4 font-medium">{rule.name}</td><td className="py-4 text-muted-foreground">{rule.source}</td><td className="py-4 font-mono text-xs">{rule.matches}</td><td className="py-4"><Badge variant={rule.state === "Enforced" ? "default" : "secondary"}>{rule.state}</Badge></td></tr>)}</tbody></table></div></CardContent></Card>;
}

function BotPanel({ active, onToggle }: { active: boolean; onToggle: () => void }) {
  return <div className="grid gap-4 lg:grid-cols-5"><Card className="lg:col-span-3"><CardHeader><CardTitle>Bot challenge policy</CardTitle><CardDescription>Protect sign-in and public routes from automated abuse.</CardDescription></CardHeader><CardContent className="space-y-4"><PolicyRow label="Challenge suspicious fingerprints" enabled={active} onClick={onToggle} /><PolicyRow label="Require proof-of-work for bursts" enabled={active} onClick={onToggle} /><PolicyRow label="Allow verified crawlers" enabled={true} onClick={() => toast.info("Crawler allowlist opened")} /></CardContent></Card><Card className="lg:col-span-2"><CardHeader><CardTitle>Challenge outcomes</CardTitle><CardDescription>Last 24 hours</CardDescription></CardHeader><CardContent className="space-y-5"><Outcome label="Passed challenges" value="98.6%" width="w-[86%]" color="bg-emerald-500" /><Outcome label="Blocked automation" value="1.1%" width="w-[28%]" color="bg-destructive" /><Outcome label="Still reviewing" value="0.3%" width="w-[12%]" color="bg-amber-500" /></CardContent></Card></div>;
}

function RatePanel({ active, onToggle }: { active: boolean; onToggle: () => void }) {
  return <div className="grid gap-4 lg:grid-cols-2"><Card><CardHeader className="flex flex-row items-start justify-between"><div><CardTitle>Adaptive rate limiting</CardTitle><CardDescription>Automatically respond to traffic anomalies.</CardDescription></div><Button variant={active ? "outline" : "secondary"} onClick={onToggle} aria-pressed={active}><SlidersHorizontal />{active ? "Enabled" : "Paused"}</Button></CardHeader><CardContent className="space-y-3"><div className="rounded-lg border bg-muted/30 p-4"><div className="flex items-center justify-between"><span className="text-sm font-medium">Public API</span><StatusBadge status="healthy">1,000 req/min</StatusBadge></div><p className="mt-2 text-xs text-muted-foreground">Adaptive threshold · 84% capacity used</p></div><div className="rounded-lg border bg-muted/30 p-4"><div className="flex items-center justify-between"><span className="text-sm font-medium">Login endpoints</span><StatusBadge status="warning">Review</StatusBadge></div><p className="mt-2 text-xs text-muted-foreground">Challenge after 10 failed attempts</p></div></CardContent></Card><Card><CardHeader><CardTitle>Policy simulator</CardTitle><CardDescription>Try a sample request against the dummy policy.</CardDescription></CardHeader><CardContent><Button className="w-full" onClick={() => toast.success("Request would be challenged", { description: "Demo policy matched: login burst threshold." })}>Simulate request</Button></CardContent></Card></div>;
}

function PolicyRow({ label, enabled, onClick }: { label: string; enabled: boolean; onClick: () => void }) {
  return <div className="flex items-center justify-between gap-4 rounded-lg border p-4"><span className="text-sm font-medium">{label}</span><Button variant={enabled ? "default" : "secondary"} size="sm" onClick={onClick} aria-pressed={enabled}>{enabled && <Check />}{enabled ? "On" : "Off"}</Button></div>;
}

function Outcome({ label, value, width, color }: { label: string; value: string; width: string; color: string }) {
  return <div className="space-y-2"><div className="flex justify-between text-sm"><span>{label}</span><span className="font-mono text-xs text-muted-foreground">{value}</span></div><div className="h-2 rounded-full bg-muted"><div className={`h-2 rounded-full ${width} ${color}`} /></div></div>;
}

function SecuritySummary({ icon: Icon, label, value, detail, status }: { icon: typeof ShieldCheck; label: string; value: string; detail: string; status: "healthy" | "warning" }) {
  return <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle><Icon className="size-4 text-muted-foreground" /></CardHeader><CardContent><div className="flex items-center gap-2"><span className="text-xl font-semibold">{value}</span><StatusBadge status={status}>{status === "healthy" ? "Healthy" : "Paused"}</StatusBadge></div><p className="mt-1 text-xs text-muted-foreground">{detail}</p></CardContent></Card>;
}
