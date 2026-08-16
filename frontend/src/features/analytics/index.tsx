import { useState } from "react";
import { toast } from "sonner";
import { ArrowDown, ArrowUp, Download, Gauge, Globe2, Server, Zap } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import { TrafficChart } from "@/features/dashboard/components/traffic-chart";

const endpoints = [
  { path: "/api/v1/proxy-hosts", requests: "42,820", latency: "34ms", change: "+12.4%" },
  { path: "/api/v1/certificates", requests: "18,231", latency: "41ms", change: "+4.8%" },
  { path: "/api/v1/events", requests: "12,093", latency: "28ms", change: "-2.1%" },
  { path: "/health", requests: "9,402", latency: "8ms", change: "+0.4%" },
];

export function Analytics() {
  const [range, setRange] = useState("7d");
  return <Main><PageHeader title="Analytics" description="Understand traffic, latency, and edge capacity with synthetic data." action={<><select aria-label="Analytics range" value={range} onChange={(event) => setRange(event.target.value)} className="h-9 rounded-md border border-input bg-background px-3 text-sm"><option value="24h">Last 24 hours</option><option value="7d">Last 7 days</option><option value="30d">Last 30 days</option></select><Button variant="outline" onClick={() => toast.success("Analytics export queued")}><Download />Export</Button></>} /><div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4"><MetricCard title="Total requests" value="148.2k" detail="18.4% from previous period" trend="up" icon={Globe2} /><MetricCard title="P95 latency" value="182ms" detail="12ms faster than target" trend="down" icon={Gauge} /><MetricCard title="Data transferred" value="8.4 GB" detail="6.2% from previous period" trend="up" icon={Zap} /><MetricCard title="Origin availability" value="99.98%" detail="All services within SLO" trend="neutral" icon={Server} /></div><Card className="mb-6"><CardHeader><CardTitle>Traffic overview</CardTitle><CardDescription>Requests and blocked traffic for the {range === "24h" ? "last 24 hours" : range === "30d" ? "last 30 days" : "last 7 days"}.</CardDescription></CardHeader><CardContent className="ps-2"><TrafficChart /></CardContent></Card><div className="grid gap-4 lg:grid-cols-5"><Card className="lg:col-span-3"><CardHeader><CardTitle>Top endpoints</CardTitle><CardDescription>Routes receiving the most traffic.</CardDescription></CardHeader><CardContent><Table><TableHeader><TableRow><TableHead>Endpoint</TableHead><TableHead>Requests</TableHead><TableHead>P95 latency</TableHead><TableHead>Change</TableHead></TableRow></TableHeader><TableBody>{endpoints.map((endpoint) => <TableRow key={endpoint.path}><TableCell className="font-mono text-xs">{endpoint.path}</TableCell><TableCell className="font-mono text-xs">{endpoint.requests}</TableCell><TableCell className="font-mono text-xs">{endpoint.latency}</TableCell><TableCell><span className={endpoint.change.startsWith("-") ? "text-emerald-600" : "text-muted-foreground"}>{endpoint.change.startsWith("-") ? <ArrowDown className="mr-1 inline size-3" /> : <ArrowUp className="mr-1 inline size-3" />}{endpoint.change}</span></TableCell></TableRow>)}</TableBody></Table></CardContent></Card><Card className="lg:col-span-2"><CardHeader><CardTitle>Node capacity</CardTitle><CardDescription>Current synthetic utilization.</CardDescription></CardHeader><CardContent className="space-y-5"><Capacity name="edge-jakarta-01" value={42} status="healthy" /><Capacity name="edge-jakarta-02" value={58} status="healthy" /><Capacity name="edge-jakarta-03" value={76} status="warning" /></CardContent></Card></div></Main>;
}

function Capacity({ name, value, status }: { name: string; value: number; status: "healthy" | "warning" }) {
  return <div className="space-y-2"><div className="flex items-center justify-between gap-2"><span className="truncate text-sm font-medium">{name}</span><StatusBadge status={status}>{value}%</StatusBadge></div><div className="h-2 rounded-full bg-muted"><div className={`h-2 rounded-full ${status === "warning" ? "bg-amber-500" : "bg-primary"}`} style={{ width: `${value}%` }} /></div></div>;
}
