import { useState } from "react";
import { Link } from "@tanstack/react-router";
import { toast } from "sonner";
import {
  Activity,
  ArrowUpRight,
  Ban,
  Download,
  Globe2,
  Server,
  ShieldCheck,
  Users,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { MetricCard } from "@/components/metric-card";
import { StatusBadge } from "@/components/status-badge";
import { TrafficChart } from "./components/traffic-chart";

const recentEvents = [
  { time: "2 min ago", title: "WAF rule blocked a suspicious request", detail: "203.0.113.42 · SQL injection signature", status: "danger" as const },
  { time: "8 min ago", title: "Certificate renewed successfully", detail: "api.bearust.local · valid for 90 days", status: "healthy" as const },
  { time: "14 min ago", title: "New node joined the cluster", detail: "edge-jakarta-03 · 10.20.0.18", status: "info" as const },
  { time: "31 min ago", title: "Rate limit policy switched to adaptive", detail: "public-api · 1,000 requests/minute", status: "warning" as const },
];

const topHosts = [
  { host: "app.bearust.local", requests: "12.4k", latency: "38ms", status: "healthy" as const },
  { host: "api.bearust.local", requests: "9.8k", latency: "44ms", status: "healthy" as const },
  { host: "console.bearust.local", requests: "6.2k", latency: "51ms", status: "warning" as const },
];

export function Dashboard() {
  const [range, setRange] = useState("7d");

  return (
    <Main>
      <PageHeader
        title="Dashboard"
        description="A live-looking view of your BeaRust edge infrastructure."
        action={
          <>
            <Badge variant="outline" className="hidden gap-1.5 rounded-full sm:inline-flex">
              <span className="size-1.5 rounded-full bg-emerald-500" />
              Demo data
            </Badge>
            <Button variant="outline" onClick={() => toast.success("Report prepared", { description: "A dummy export is ready for download." })}>
              <Download />
              Export report
            </Button>
          </>
        }
      />

      <Tabs defaultValue="overview" className="space-y-6">
        <div className="flex items-center justify-between gap-4 overflow-x-auto pb-1">
          <TabsList>
            <TabsTrigger value="overview">Overview</TabsTrigger>
            <TabsTrigger value="analytics">Analytics</TabsTrigger>
            <TabsTrigger value="reports" disabled>Reports</TabsTrigger>
            <TabsTrigger value="notifications" disabled>Notifications</TabsTrigger>
          </TabsList>
          <select
            aria-label="Dashboard date range"
            value={range}
            onChange={(event) => setRange(event.target.value)}
            className="hidden h-9 rounded-md border border-input bg-background px-3 text-sm shadow-xs outline-none focus:ring-2 focus:ring-ring/50 sm:block"
          >
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
          </select>
        </div>

        <TabsContent value="overview" className="space-y-6">
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <MetricCard title="Protected hosts" value="24" detail="3 added this month" trend="up" icon={Globe2} />
            <MetricCard title="Requests processed" value="148.2k" detail="18.4% from last week" trend="up" icon={Activity} />
            <MetricCard title="Threats blocked" value="4,291" detail="12.8% from last week" trend="up" icon={Ban} />
            <MetricCard title="Healthy nodes" value="3 / 3" detail="All cluster members online" trend="neutral" icon={Server} />
          </div>

          <div className="grid gap-4 lg:grid-cols-7">
            <Card className="lg:col-span-4">
              <CardHeader>
                <CardTitle>Traffic overview</CardTitle>
                <CardDescription>Requests and blocked traffic over the last {range === "24h" ? "24 hours" : range === "30d" ? "30 days" : "7 days"}.</CardDescription>
              </CardHeader>
              <CardContent className="ps-2">
                <TrafficChart />
              </CardContent>
            </Card>
            <Card className="lg:col-span-3">
              <CardHeader>
                <CardTitle>Edge health</CardTitle>
                <CardDescription>Cluster status at a glance.</CardDescription>
              </CardHeader>
              <CardContent className="space-y-5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <div className="rounded-lg bg-emerald-500/10 p-2 text-emerald-600"><ShieldCheck className="size-5" /></div>
                    <div><p className="text-sm font-medium">Protection engine</p><p className="text-xs text-muted-foreground">Signature + semantic WAF</p></div>
                  </div>
                  <StatusBadge status="healthy">Operational</StatusBadge>
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm"><span className="text-muted-foreground">CPU utilization</span><span className="font-medium tabular-nums">42%</span></div>
                  <div className="h-2 rounded-full bg-muted"><div className="h-2 w-[42%] rounded-full bg-primary" /></div>
                </div>
                <div className="space-y-2">
                  <div className="flex items-center justify-between text-sm"><span className="text-muted-foreground">Memory utilization</span><span className="font-medium tabular-nums">68%</span></div>
                  <div className="h-2 rounded-full bg-muted"><div className="h-2 w-[68%] rounded-full bg-amber-500" /></div>
                </div>
                <Button variant="outline" className="w-full" asChild><Link to="/analytics">View node metrics <ArrowUpRight /></Link></Button>
              </CardContent>
            </Card>
          </div>

          <div className="grid gap-4 lg:grid-cols-7">
            <Card className="lg:col-span-4">
              <CardHeader className="flex flex-row items-center justify-between space-y-0">
                <div><CardTitle>Recent security events</CardTitle><CardDescription>What your edge has handled recently.</CardDescription></div>
                <Button variant="ghost" size="sm" asChild><Link to="/audit-log">View all</Link></Button>
              </CardHeader>
              <CardContent>
                <div className="space-y-5">
                  {recentEvents.map((event) => (
                    <div key={event.title} className="flex items-start gap-3">
                      <StatusBadge status={event.status}>{event.status === "danger" ? "Blocked" : event.status === "healthy" ? "Healthy" : event.status === "warning" ? "Review" : "Info"}</StatusBadge>
                      <div className="min-w-0 flex-1"><p className="truncate text-sm font-medium">{event.title}</p><p className="truncate text-xs text-muted-foreground">{event.detail}</p></div>
                      <time className="shrink-0 text-xs text-muted-foreground">{event.time}</time>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
            <Card className="lg:col-span-3">
              <CardHeader><CardTitle>Top proxy hosts</CardTitle><CardDescription>Highest request volume today.</CardDescription></CardHeader>
              <CardContent>
                <Table>
                  <TableHeader><TableRow><TableHead>Host</TableHead><TableHead>Requests</TableHead><TableHead>State</TableHead></TableRow></TableHeader>
                  <TableBody>
                    {topHosts.map((host) => <TableRow key={host.host}><TableCell><div className="font-medium">{host.host}</div><div className="text-xs text-muted-foreground">{host.latency} avg</div></TableCell><TableCell className="font-mono text-xs">{host.requests}</TableCell><TableCell><StatusBadge status={host.status}>{host.status === "healthy" ? "Live" : "Watch"}</StatusBadge></TableCell></TableRow>)}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="analytics" className="space-y-6">
          <Card>
            <CardHeader><CardTitle>Traffic analytics</CardTitle><CardDescription>Dummy metrics are ready for the API integration phase.</CardDescription></CardHeader>
            <CardContent><TrafficChart /></CardContent>
          </Card>
          <div className="grid gap-4 sm:grid-cols-3">
            <MetricCard title="Unique visitors" value="38.4k" detail="5.8% from last week" trend="up" icon={Users} />
            <MetricCard title="Average latency" value="46ms" detail="8ms faster than last week" trend="down" icon={Activity} />
            <MetricCard title="Origin availability" value="99.98%" detail="Within SLO target" trend="neutral" icon={Server} />
          </div>
        </TabsContent>
      </Tabs>
    </Main>
  );
}
