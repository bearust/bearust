import { toast } from "sonner";
import { ArrowUpRight, LifeBuoy, MessageSquare, Plus } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";

const threads = [
  { title: "Certificate renewal question", detail: "Maya Chen · 18 minutes ago", state: "Open" },
  { title: "Review blocked request", detail: "Security queue · 42 minutes ago", state: "Assigned" },
  { title: "Cluster upgrade checklist", detail: "Rizalord · Yesterday", state: "Resolved" },
];

export function Support() {
  return <Main><PageHeader title="Support inbox" description="Keep operator questions and follow-ups in one place." action={<Button onClick={() => toast.success("New support thread started")}><Plus />New thread</Button>} /><div className="grid gap-4 lg:grid-cols-3"><Card><CardHeader><CardTitle className="flex items-center gap-2"><LifeBuoy className="size-5 text-primary" />Open threads</CardTitle><CardDescription>3 conversations need attention.</CardDescription></CardHeader><CardContent><div className="text-3xl font-bold">3</div></CardContent></Card><Card><CardHeader><CardTitle>Response time</CardTitle><CardDescription>Average this week.</CardDescription></CardHeader><CardContent><div className="text-3xl font-bold">18m</div></CardContent></Card><Card><CardHeader><CardTitle>Resolved</CardTitle><CardDescription>Closed this month.</CardDescription></CardHeader><CardContent><div className="text-3xl font-bold">42</div></CardContent></Card></div><Card className="mt-6"><CardHeader><CardTitle>Recent conversations</CardTitle><CardDescription>Dummy support data for the shell.</CardDescription></CardHeader><CardContent className="space-y-3">{threads.map((thread) => <button type="button" key={thread.title} className="flex w-full items-center gap-3 rounded-lg border p-4 text-left transition hover:border-primary/50 hover:bg-accent" onClick={() => toast.info("Thread preview opened")}><MessageSquare className="size-4 text-primary" /><div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{thread.title}</p><p className="truncate text-xs text-muted-foreground">{thread.detail}</p></div><Badge variant={thread.state === "Resolved" ? "secondary" : "outline"}>{thread.state}</Badge><ArrowUpRight className="size-4 text-muted-foreground" /></button>)}</CardContent></Card></Main>;
}
