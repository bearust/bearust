import { ShieldCheck } from "lucide-react";

export function AuthLayout({ children }: { children: React.ReactNode }) {
  return (
    <div className="relative grid min-h-svh lg:grid-cols-[0.9fr_1.1fr]">
      <aside className="relative hidden overflow-hidden border-e bg-muted/30 p-10 lg:flex lg:flex-col lg:justify-between">
        <div className="pointer-events-none absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-transparent" />
        <div className="relative flex items-center gap-2.5">
          <span className="flex size-9 items-center justify-center rounded-lg bg-primary text-primary-foreground shadow-sm">
            <ShieldCheck className="size-5" />
          </span>
          <div>
            <p className="font-semibold tracking-tight">BeaRust Control Plane</p>
            <p className="text-xs text-muted-foreground">Self-hosted edge security</p>
          </div>
        </div>
        <div className="relative max-w-md space-y-4">
          <p className="text-sm font-medium text-primary">Secure by default</p>
          <h2 className="text-3xl font-semibold tracking-tight xl:text-4xl">
            Protect every service at the edge.
          </h2>
          <p className="text-sm leading-6 text-muted-foreground">
            Manage proxy hosts, threat protection, and cluster health from one
            focused control plane.
          </p>
          <div className="grid grid-cols-3 gap-3 pt-4">
            <AuthStat value="24" label="protected hosts" />
            <AuthStat value="99.9%" label="edge uptime" />
            <AuthStat value="3/3" label="healthy nodes" />
          </div>
        </div>
        <p className="relative text-xs text-muted-foreground">
          BeaRust · Demo shell ready for API integration
        </p>
      </aside>

      <main className="flex min-h-svh items-center justify-center px-4 py-10 sm:px-8">
        <div className="w-full max-w-md">
          <div className="mb-8 flex items-center justify-center gap-2.5 lg:justify-start">
            <span className="flex size-8 items-center justify-center rounded-lg bg-primary text-primary-foreground">
              <ShieldCheck className="size-4" />
            </span>
            <span className="font-semibold tracking-tight">BeaRust</span>
          </div>
          {children}
        </div>
      </main>
    </div>
  );
}

function AuthStat({ value, label }: { value: string; label: string }) {
  return (
    <div className="rounded-lg border bg-background/75 p-3 shadow-xs backdrop-blur-sm">
      <p className="text-lg font-semibold tabular-nums">{value}</p>
      <p className="text-[11px] text-muted-foreground">{label}</p>
    </div>
  );
}
