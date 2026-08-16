import { useState } from "react";
import { toast } from "sonner";
import { Ellipsis, Plus, Search, Server, ShieldCheck, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { DropdownMenu, DropdownMenuContent, DropdownMenuItem, DropdownMenuSeparator, DropdownMenuTrigger } from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";

type Host = { id: number; name: string; domain: string; upstream: string; tls: string; status: "healthy" | "warning" };

const initialHosts: Host[] = [
  { id: 1, name: "Public API", domain: "api.bearust.local", upstream: "api-pool:8080", tls: "Let's Encrypt", status: "healthy" },
  { id: 2, name: "Admin Console", domain: "console.bearust.local", upstream: "console:3000", tls: "Let's Encrypt", status: "healthy" },
  { id: 3, name: "Documentation", domain: "docs.bearust.local", upstream: "docs:8080", tls: "Internal CA", status: "warning" },
  { id: 4, name: "Metrics endpoint", domain: "metrics.bearust.local", upstream: "prometheus:9090", tls: "Let's Encrypt", status: "healthy" },
];

export function ProxyHosts() {
  const [hosts, setHosts] = useState(initialHosts);
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [form, setForm] = useState({ name: "", domain: "", upstream: "" });
  const visibleHosts = hosts.filter((host) => `${host.name} ${host.domain} ${host.upstream}`.toLowerCase().includes(query.toLowerCase()));

  const addHost = (event: React.FormEvent) => {
    event.preventDefault();
    if (!form.name || !form.domain || !form.upstream) return;
    setHosts((current) => [...current, { id: Date.now(), ...form, tls: "Pending", status: "warning" }]);
    setForm({ name: "", domain: "", upstream: "" });
    setOpen(false);
    toast.success("Proxy host added", { description: `${form.domain} is ready for configuration.` });
  };

  return (
    <Main>
      <PageHeader
        title="Proxy Hosts"
        description="Route traffic to your services and manage certificates."
        action={<Button onClick={() => setOpen(true)}><Plus />Add proxy host</Button>}
      />

      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        <SummaryCard icon={Server} label="Active hosts" value={String(hosts.length)} detail="Across 3 upstream pools" />
        <SummaryCard icon={ShieldCheck} label="TLS coverage" value="100%" detail="All hosts use encryption" />
        <SummaryCard icon={Trash2} label="Needs attention" value={String(hosts.filter((host) => host.status === "warning").length)} detail="Certificate or health checks" />
      </div>

      <Card>
        <CardHeader className="gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div><CardTitle>Configured hosts</CardTitle><CardDescription>Demo records will be replaced by API data later.</CardDescription></div>
          <div className="relative w-full sm:w-64"><Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" /><Input aria-label="Search proxy hosts" placeholder="Search hosts..." value={query} onChange={(event) => setQuery(event.target.value)} className="h-9 pl-8" /></div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader><TableRow><TableHead>Host</TableHead><TableHead>Domain</TableHead><TableHead>Upstream</TableHead><TableHead>TLS</TableHead><TableHead>Status</TableHead><TableHead className="w-10"><span className="sr-only">Actions</span></TableHead></TableRow></TableHeader>
            <TableBody>
              {visibleHosts.map((host) => <TableRow key={host.id}><TableCell><div className="font-medium">{host.name}</div><div className="text-xs text-muted-foreground">Created from demo data</div></TableCell><TableCell className="font-mono text-xs">{host.domain}</TableCell><TableCell className="font-mono text-xs text-muted-foreground">{host.upstream}</TableCell><TableCell><Badge variant="secondary">{host.tls}</Badge></TableCell><TableCell><StatusBadge status={host.status}>{host.status === "healthy" ? "Healthy" : "Review"}</StatusBadge></TableCell><TableCell><DropdownMenu><DropdownMenuTrigger asChild><Button variant="ghost" size="icon" aria-label={`Actions for ${host.name}`}><Ellipsis /></Button></DropdownMenuTrigger><DropdownMenuContent align="end"><DropdownMenuItem onClick={() => toast.info("Edit mode is ready", { description: "Connect this form to the proxy-host API later." })}>Edit host</DropdownMenuItem><DropdownMenuItem onClick={() => toast.info("Certificate manager opened")}>Manage certificate</DropdownMenuItem><DropdownMenuSeparator /><DropdownMenuItem variant="destructive" onClick={() => { setHosts((current) => current.filter((item) => item.id !== host.id)); toast.success("Proxy host removed"); }}><Trash2 />Delete host</DropdownMenuItem></DropdownMenuContent></DropdownMenu></TableCell></TableRow>)}
            </TableBody>
          </Table>
          {visibleHosts.length === 0 && <div className="py-12 text-center text-sm text-muted-foreground">No proxy hosts match your search.</div>}
        </CardContent>
      </Card>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader><DialogTitle>Add proxy host</DialogTitle><DialogDescription>Create a frontend-only host record. API persistence will be connected later.</DialogDescription></DialogHeader>
          <form id="add-host-form" className="space-y-4" onSubmit={addHost}>
            <div className="space-y-2"><Label htmlFor="host-name">Display name</Label><Input id="host-name" value={form.name} onChange={(event) => setForm({ ...form, name: event.target.value })} placeholder="Public API" required /></div>
            <div className="space-y-2"><Label htmlFor="host-domain">Domain</Label><Input id="host-domain" value={form.domain} onChange={(event) => setForm({ ...form, domain: event.target.value })} placeholder="api.example.com" required /></div>
            <div className="space-y-2"><Label htmlFor="host-upstream">Upstream target</Label><Input id="host-upstream" value={form.upstream} onChange={(event) => setForm({ ...form, upstream: event.target.value })} placeholder="api:8080" required /></div>
          </form>
          <DialogFooter><Button type="button" variant="outline" onClick={() => setOpen(false)}>Cancel</Button><Button type="submit" form="add-host-form">Create host</Button></DialogFooter>
        </DialogContent>
      </Dialog>
    </Main>
  );
}

function SummaryCard({ icon: Icon, label, value, detail }: { icon: typeof Server; label: string; value: string; detail: string }) {
  return <Card><CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2"><CardTitle className="text-sm font-medium text-muted-foreground">{label}</CardTitle><Icon className="size-4 text-muted-foreground" /></CardHeader><CardContent><div className="text-2xl font-bold tabular-nums">{value}</div><p className="text-xs text-muted-foreground">{detail}</p></CardContent></Card>;
}
