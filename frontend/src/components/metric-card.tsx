import type { LucideIcon } from "lucide-react";
import { ArrowDownRight, ArrowUpRight } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function MetricCard({
  title,
  value,
  detail,
  trend,
  icon: Icon,
}: {
  title: string;
  value: string;
  detail: string;
  trend: "up" | "down" | "neutral";
  icon: LucideIcon;
}) {
  return (
    <Card className="relative overflow-hidden">
      <div className="metric-accent absolute inset-x-0 top-0 h-0.5 opacity-80" />
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">{title}</CardTitle>
        <Icon className="size-4 text-muted-foreground" aria-hidden="true" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold tracking-tight tabular-nums">{value}</div>
        <p className="mt-1 flex items-center gap-1 text-xs text-muted-foreground">
          {trend !== "neutral" && (trend === "up" ? <ArrowUpRight className="size-3 text-emerald-600" /> : <ArrowDownRight className="size-3 text-emerald-600" />)}
          <span className={trend !== "neutral" ? "text-emerald-600 dark:text-emerald-400" : undefined}>{detail}</span>
        </p>
      </CardContent>
    </Card>
  );
}
