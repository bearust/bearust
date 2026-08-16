import { CircleCheck, CircleX, Info, TriangleAlert } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const icons = {
  healthy: CircleCheck,
  warning: TriangleAlert,
  danger: CircleX,
  info: Info,
} as const;

const variants = {
  healthy: "border-emerald-500/30 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400",
  warning: "border-amber-500/30 bg-amber-500/10 text-amber-700 dark:text-amber-400",
  danger: "border-destructive/30 bg-destructive/10 text-destructive",
  info: "border-primary/30 bg-primary/10 text-primary",
} as const;

export function StatusBadge({
  status,
  children,
}: {
  status: keyof typeof icons;
  children: React.ReactNode;
}) {
  const Icon = icons[status];
  return (
    <Badge variant="outline" className={cn("gap-1.5 rounded-full px-2.5", variants[status])}>
      <Icon className="size-3" aria-hidden="true" />
      {children}
    </Badge>
  );
}
