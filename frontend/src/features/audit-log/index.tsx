import { useState } from "react";
import { toast } from "sonner";
import { Download, FileClock, Filter, Search } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";

const entries = [
  { id: 1, time: "Aug 16, 2026 · 09:42", actor: "Rizalord", action: "Updated WAF policy", resource: "global / semantic-detection", result: "Success" },
  { id: 2, time: "Aug 16, 2026 · 09:18", actor: "Maya Chen", action: "Created proxy host", resource: "api.bearust.local", result: "Success" },
  { id: 3, time: "Aug 16, 2026 · 08:56", actor: "Rizalord", action: "Revoked user sessions", resource: "staging@bearust.local", result: "Success" },
  { id: 4, time: "Aug 16, 2026 · 08:31", actor: "Unknown", action: "Login attempt", resource: "admin@bearust.local", result: "Denied" },
  { id: 5, time: "Aug 15, 2026 · 22:04", actor: "System", action: "Certificate renewed", resource: "api.bearust.local", result: "Success" },
];

export function AuditLog() {
  const [query, setQuery] = useState("");
  const visible = entries.filter((entry) => `${entry.actor} ${entry.action} ${entry.resource} ${entry.result}`.toLowerCase().includes(query.toLowerCase()));
  return <Main><PageHeader title="Audit Log" description="A searchable record of changes and security events." action={<Button variant="outline" onClick={() => toast.success("Audit log export ready")}><Download />Export CSV</Button>} /><Card><CardHeader className="gap-4 sm:flex-row sm:items-center sm:justify-between"><div><CardTitle>Activity history</CardTitle><CardDescription>Showing synthetic events for the prototype.</CardDescription></div><div className="flex gap-2"><div className="relative w-full sm:w-64"><Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" /><Input aria-label="Search audit log" placeholder="Search events..." value={query} onChange={(event) => setQuery(event.target.value)} className="h-9 pl-8" /></div><Button variant="outline" size="icon" aria-label="Open audit filters" onClick={() => toast.info("Filter drawer opened")}><Filter /></Button></div></CardHeader><CardContent><Table><TableHeader><TableRow><TableHead>Timestamp</TableHead><TableHead>Actor</TableHead><TableHead>Action</TableHead><TableHead>Resource</TableHead><TableHead>Result</TableHead></TableRow></TableHeader><TableBody>{visible.map((entry) => <TableRow key={entry.id}><TableCell className="whitespace-nowrap text-xs text-muted-foreground">{entry.time}</TableCell><TableCell className="font-medium">{entry.actor}</TableCell><TableCell>{entry.action}</TableCell><TableCell className="font-mono text-xs text-muted-foreground">{entry.resource}</TableCell><TableCell><Badge variant={entry.result === "Success" ? "secondary" : "destructive"}>{entry.result}</Badge></TableCell></TableRow>)}</TableBody></Table>{visible.length === 0 && <div className="py-12 text-center text-sm text-muted-foreground"><FileClock className="mx-auto mb-2 size-6" />No events match the current search.</div>}</CardContent></Card></Main>;
}
