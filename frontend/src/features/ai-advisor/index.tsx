import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { ArrowRight, Bot, CheckCircle2, Clock3, Send, Sparkles, XCircle } from "lucide-react";
import { api, type AdvisorJob, type AdvisorStatus, type AdvisorWorkflow } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { sanitizeError } from "@/lib/errors";
import { useRealtimeRefresh } from "@/hooks/use-realtime-refresh";
import { useAuthStore } from "@/stores/auth-store";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";

const suggestions = [
  { title: "Why did the WAF block traffic?", text: "Explain the spike in SQL injection detections during the last hour.", workflow: "security_summary" as const },
  { title: "Review an upstream health issue", text: "Summarize the likely causes of elevated latency on the public API.", workflow: "incident_explanation" as const },
  { title: "Tune rate limiting", text: "Recommend a safe threshold for the public API based on this week's traffic.", workflow: "rule_tuning" as const },
];

export function AiAdvisor() {
  const user = useAuthStore((state) => state.user);
  const canApprove = user?.role === "admin";
  const [question, setQuestion] = useState("");
  const [workflow, setWorkflow] = useState<AdvisorWorkflow>("incident_explanation");
  const [answer, setAnswer] = useState("The advisor is ready. Ask a focused question about your edge telemetry.");
  const [status, setStatus] = useState<AdvisorStatus>(DEMO_MODE ? { enabled: true } : { enabled: false });
  const [job, setJob] = useState<AdvisorJob | null>(null);
  const [jobs, setJobs] = useState<AdvisorJob[]>([]);
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const refresh = async () => {
    if (DEMO_MODE) return;
    setLoading(true); setError("");
    const results = await Promise.allSettled([api.aiAdvisorStatus(), api.listAiInsights({ page: 1, page_size: 10 })]);
    if (results[0].status === "fulfilled") setStatus(results[0].value);
    if (results[1].status === "fulfilled") setJobs(results[1].value.items);
    const rejected = results.find((result) => result.status === "rejected");
    if (rejected?.status === "rejected" && results.every((result) => result.status === "rejected")) setError(sanitizeError(rejected.reason));
    setLoading(false);
  };
  useEffect(() => { void refresh(); }, []);
  useRealtimeRefresh(["ai_advisor.changed"], refresh);
  useEffect(() => {
    if (DEMO_MODE || !job || !["queued", "running"].includes(job.status)) return;
    const timer = window.setInterval(() => { void api.listAiInsights({ page: 1, page_size: 10 }).then((result) => { setJobs(result.items); const next = result.items.find((item) => item.job_id === job.job_id); if (next) { setJob(next); if (next.redacted_result) setAnswer(readResult(next)); } }).catch(() => undefined); }, 3000);
    return () => window.clearInterval(timer);
  }, [job]);

  const ask = async (event: FormEvent) => {
    event.preventDefault();
    if (!question.trim()) return;
    setBusy(true); setError("");
    try {
      if (DEMO_MODE) {
        setAnswer(`Based on the synthetic telemetry, ${question.trim().toLowerCase()} is most likely related to a short traffic burst. I would inspect the audit trail, compare the upstream latency baseline, and keep the current protection policy in monitor mode until the pattern is confirmed.`);
        setJob(null);
      } else {
        const next = await api.startAiAnalysis({ workflow, command: question.trim() });
        setJob(next); setJobs((current) => [next, ...current.filter((item) => item.job_id !== next.job_id)]); setAnswer(next.redacted_result ? readResult(next) : `Analysis ${next.status}. The worker will update this brief when the provider responds.`);
      }
      setQuestion(""); toast.success(DEMO_MODE ? "Advisor brief generated" : "Advisor analysis queued");
    } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };

  const decideDraft = async (decision: "approve" | "reject") => {
    if (!job || job.workflow !== "configuration_draft") return;
    setBusy(true);
    try { if (!DEMO_MODE) { const next = decision === "approve" ? await api.approveAiDraft(job.job_id) : await api.rejectAiDraft(job.job_id); setJob(next); setJobs((current) => current.map((item) => item.job_id === next.job_id ? next : item)); } toast.success(decision === "approve" ? "Draft approved" : "Draft rejected"); } catch (exception) { setError(sanitizeError(exception)); } finally { setBusy(false); }
  };

  return <Main><PageHeader title="AI Advisor" description="A redacted, approval-gated assistant for incidents and policy decisions." action={<Badge variant="outline" className="gap-1.5 rounded-full"><span className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : status.enabled ? "bg-emerald-500" : "bg-destructive"}`} />{DEMO_MODE ? "Demo advisor" : status.enabled ? "Advisor online" : "Advisor disabled"}</Badge>} />
    {error && <div role="alert" className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive">{error}</div>}
    <div className="grid gap-6 lg:grid-cols-5"><Card className="lg:col-span-3"><CardHeader><CardTitle className="flex items-center gap-2"><Sparkles className="size-5 text-primary" />Ask about your edge</CardTitle><CardDescription>{DEMO_MODE ? "Responses are illustrative in demo mode." : "Requests are redacted by the backend before they reach the configured provider."}</CardDescription></CardHeader><CardContent className="space-y-5"><form onSubmit={(event) => void ask(event)} className="space-y-3"><label htmlFor="advisor-workflow" className="text-sm font-medium">Workflow</label><select id="advisor-workflow" value={workflow} onChange={(event) => setWorkflow(event.target.value as AdvisorWorkflow)} disabled={!DEMO_MODE && !status.enabled || busy} className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"><option value="incident_explanation">Incident explanation</option><option value="security_summary">Security summary</option><option value="rule_tuning">Rule tuning</option><option value="configuration_draft">Configuration draft</option></select><label htmlFor="advisor-question" className="sr-only">Ask the AI advisor</label><textarea id="advisor-question" value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="What should I investigate first?" className="min-h-28 w-full resize-y rounded-md border border-input bg-background px-3 py-2 text-sm outline-none transition focus:border-ring focus:ring-2 focus:ring-ring/50" /><Button type="submit" disabled={busy || !question.trim() || (!DEMO_MODE && !status.enabled)}><Send />{busy ? "Working…" : "Generate brief"}</Button></form><div className="rounded-lg border bg-muted/30 p-4"><div className="mb-2 flex items-center gap-2 text-sm font-medium"><Bot className="size-4 text-primary" />Advisor response{job && <Badge variant="secondary" className="ml-auto">{job.status}</Badge>}</div><p className="text-sm leading-6 text-muted-foreground">{answer}</p>{job?.redacted_result && <ResultDetails job={job} />}{job?.workflow === "configuration_draft" && job.status === "completed" && !job.draft_decision && <div className="mt-4 flex gap-2"><Button onClick={() => void decideDraft("approve")} disabled={!canApprove || busy}><CheckCircle2 />Approve draft</Button><Button variant="destructive" onClick={() => void decideDraft("reject")} disabled={!canApprove || busy}><XCircle />Reject draft</Button></div>}</div></CardContent></Card><div className="space-y-4 lg:col-span-2"><div><h2 className="text-sm font-semibold">Suggested investigations</h2><p className="mt-1 text-xs text-muted-foreground">Start with a focused question.</p></div>{suggestions.map((suggestion) => <button key={suggestion.title} type="button" className="group w-full rounded-lg border bg-card p-4 text-left transition hover:border-primary/50 hover:bg-accent" onClick={() => { setQuestion(suggestion.text); setWorkflow(suggestion.workflow); }}><div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium">{suggestion.title}</p><p className="mt-1 text-xs leading-5 text-muted-foreground">{suggestion.text}</p></div><ArrowRight className="mt-0.5 size-4 shrink-0 text-muted-foreground transition group-hover:translate-x-0.5 group-hover:text-primary" /></div></button>)}</div></div>
    <Card className="mt-6"><CardHeader><CardTitle>Recent advisor jobs</CardTitle><CardDescription>{DEMO_MODE ? "API jobs will appear here when advisor mode is enabled." : "Completed results and approval state returned by the control plane."}</CardDescription></CardHeader><CardContent><div className="space-y-3">{loading ? <div className="h-16 animate-pulse rounded-md bg-muted" /> : jobs.map((item) => <button type="button" key={item.job_id} className="flex w-full items-center gap-3 rounded-lg border p-4 text-left hover:bg-accent" onClick={() => { setJob(item); setAnswer(item.redacted_result ? readResult(item) : `Analysis ${item.status}.`); }}><JobIcon status={item.status} /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{item.workflow.replaceAll("_", " ")}</p><p className="truncate text-xs text-muted-foreground">{item.status} · {item.provider_model || "configured provider"}</p></div><Clock3 className="size-4 text-muted-foreground" /></button>)}</div>{!loading && jobs.length === 0 && <p className="py-8 text-center text-sm text-muted-foreground">No advisor jobs yet.</p>}</CardContent></Card>
  </Main>;
}

function readResult(job: AdvisorJob) { const result = job.redacted_result; if (!result || typeof result !== "object") return "The advisor returned no readable result."; return "summary" in result && typeof result.summary === "string" ? result.summary : "The advisor produced a configuration draft."; }
function ResultDetails({ job }: { job: AdvisorJob }) { const result = job.redacted_result; if (!result || typeof result !== "object") return null; const signals = "signals" in result && Array.isArray(result.signals) ? result.signals : []; return signals.length ? <ul className="mt-3 list-disc space-y-1 ps-5 text-xs text-muted-foreground">{signals.slice(0, 5).map((signal) => <li key={String(signal)}>{String(signal)}</li>)}</ul> : null; }
function JobIcon({ status }: { status: AdvisorJob["status"] }) { if (["completed", "approved"].includes(status)) return <CheckCircle2 className="size-4 text-emerald-600" />; if (["failed", "rejected", "expired"].includes(status)) return <XCircle className="size-4 text-destructive" />; return <Clock3 className="size-4 text-amber-600" />; }
