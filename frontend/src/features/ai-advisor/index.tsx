import { useState } from "react";
import { toast } from "sonner";
import { ArrowRight, Bot, CheckCircle2, Lightbulb, Send, Sparkles } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";

const suggestions = [
  { title: "Why did the WAF block traffic?", text: "Explain the spike in SQL injection detections during the last hour." },
  { title: "Review an upstream health issue", text: "Summarize the likely causes of elevated latency on api-pool." },
  { title: "Tune rate limiting", text: "Recommend a safe threshold for the public API based on this week's traffic." },
];

export function AiAdvisor() {
  const [question, setQuestion] = useState("");
  const [answer, setAnswer] = useState("The demo advisor is ready. Ask a question to generate a synthetic operator brief.");
  const ask = (event: React.FormEvent) => {
    event.preventDefault();
    if (!question.trim()) return;
    setAnswer(`Based on the synthetic telemetry, ${question.trim().toLowerCase()} is most likely related to a short traffic burst. I would inspect the audit trail, compare the upstream latency baseline, and keep the current protection policy in monitor mode until the pattern is confirmed.`);
    setQuestion("");
    toast.success("Advisor brief generated");
  };
  return <Main><PageHeader title="AI Advisor" description="A calm second pair of eyes for edge incidents and policy decisions." action={<Badge variant="outline" className="gap-1.5 rounded-full"><span className="size-1.5 rounded-full bg-emerald-500" />Demo advisor online</Badge>} /><div className="grid gap-6 lg:grid-cols-5"><Card className="lg:col-span-3"><CardHeader><CardTitle className="flex items-center gap-2"><Sparkles className="size-5 text-primary" />Ask about your edge</CardTitle><CardDescription>These responses are illustrative until the AI provider is connected.</CardDescription></CardHeader><CardContent className="space-y-5"><form onSubmit={ask} className="space-y-3"><label htmlFor="advisor-question" className="sr-only">Ask the AI advisor</label><textarea id="advisor-question" value={question} onChange={(event) => setQuestion(event.target.value)} placeholder="What should I investigate first?" className="min-h-28 w-full resize-y rounded-md border border-input bg-background px-3 py-2 text-sm outline-none transition focus:border-ring focus:ring-2 focus:ring-ring/50" /><Button type="submit" className="w-full sm:w-auto"><Send />Generate brief</Button></form><div className="rounded-lg border bg-muted/30 p-4"><div className="mb-2 flex items-center gap-2 text-sm font-medium"><Bot className="size-4 text-primary" />Advisor response</div><p className="text-sm leading-6 text-muted-foreground">{answer}</p></div></CardContent></Card><div className="space-y-4 lg:col-span-2"><div><h2 className="text-sm font-semibold">Suggested investigations</h2><p className="mt-1 text-xs text-muted-foreground">Start with a focused question.</p></div>{suggestions.map((suggestion) => <button key={suggestion.title} type="button" className="group w-full rounded-lg border bg-card p-4 text-left transition hover:border-primary/50 hover:bg-accent" onClick={() => setQuestion(suggestion.text)}><div className="flex items-start justify-between gap-3"><div><p className="text-sm font-medium">{suggestion.title}</p><p className="mt-1 text-xs leading-5 text-muted-foreground">{suggestion.text}</p></div><ArrowRight className="mt-0.5 size-4 shrink-0 text-muted-foreground transition group-hover:translate-x-0.5 group-hover:text-primary" /></div></button>)}</div></div><Card className="mt-6"><CardHeader><CardTitle>Recent advisor notes</CardTitle><CardDescription>Saved synthetic observations from this workspace.</CardDescription></CardHeader><CardContent className="grid gap-3 md:grid-cols-3"><Note title="Traffic anomaly" text="A brief request spike was contained without origin saturation." /><Note title="Certificate hygiene" text="All public hosts currently have a renewal window greater than 30 days." /><Note title="Policy posture" text="WAF enforcement is healthy; one semantic rule remains in monitor mode." /></CardContent></Card></Main>;
}

function Note({ title, text }: { title: string; text: string }) {
  return <div className="rounded-lg border p-4"><div className="mb-2 flex items-center gap-2"><CheckCircle2 className="size-4 text-emerald-600" /><span className="text-sm font-medium">{title}</span></div><p className="text-xs leading-5 text-muted-foreground">{text}</p></div>;
}
