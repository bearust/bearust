import { useEffect, useState, type FormEvent, type ReactNode } from "react";
import { Link } from "@tanstack/react-router";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import {
  Activity,
  ArrowRight,
  CheckCircle2,
  CircleAlert,
  Clock3,
  GitBranch,
  Pencil,
  Plus,
  RefreshCw,
  Route,
  Server,
  Settings2,
  Trash2,
} from "lucide-react";
import {
  api,
  type LoadBalancerAlgorithm,
  type LoadBalancerBackend,
  type LoadBalancerConfigRequest,
  type LoadBalancerHealthCheck,
  type LoadBalancerPool,
  type LoadBalancerRoute,
  type LoadBalancerSnapshot,
} from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { sanitizeError } from "@/lib/errors";
import { useRealtimeRefresh } from "@/hooks/use-realtime-refresh";
import { useAuthStore } from "@/stores/auth-store";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";

type BackendDraft = {
  address: string;
  health_check: LoadBalancerHealthCheck;
  health_path: string;
  weight: string;
};

type PoolDraft = {
  name: string;
  algorithm: LoadBalancerAlgorithm;
  connect_timeout_seconds: string;
  request_timeout_seconds: string;
  passive_health: boolean;
  backends: BackendDraft[];
};

type RouteDraft = LoadBalancerRoute;
type ConfirmTarget = { kind: "pool" | "route"; name: string } | null;

const emptyPool: PoolDraft = {
  name: "",
  algorithm: "round_robin",
  connect_timeout_seconds: "3",
  request_timeout_seconds: "30",
  passive_health: false,
  backends: [
    { address: "", health_check: "tcp", health_path: "", weight: "1" },
  ],
};

const emptyRoute: RouteDraft = {
  name: "",
  host: "",
  path_prefix: "/",
  upstream_pool: "",
};

const algorithmRequirements = [
  {
    key: "round_robin",
    label: "Round robin",
    detail: "Deterministic rotation across healthy backends.",
  },
  {
    key: "least_connections",
    label: "Least connections",
    detail: "Prefers the backend with the fewest active requests.",
  },
  {
    key: "weighted",
    label: "Weighted",
    detail:
      "Distributes traffic according to each backend's configured weight.",
  },
  {
    key: "ip_hash",
    label: "IP hash",
    detail: "Keeps a client on a stable healthy backend when possible.",
  },
  {
    key: "adaptive_weight",
    label: "Adaptive weight",
    detail: "Combines static weights with observed response-time EWMA.",
  },
  {
    key: "plugin",
    label: "Plugin",
    detail: "Delegates selection to the sandboxed balance.select hook.",
  },
] as const;

const demoSnapshot: LoadBalancerSnapshot = {
  generation: 18,
  pools: [
    {
      name: "api-pool",
      algorithm: "least_connections",
      connect_timeout_seconds: 3,
      request_timeout_seconds: 30,
      passive_health: true,
      backends: [
        {
          id: 0,
          address: "10.20.1.11:8080",
          health_check: "http",
          health_path: "/health",
          weight: 2,
          healthy: true,
          inflight: 8,
          response_time_ewma_ms: 42,
          passive_failures: 0,
        },
        {
          id: 1,
          address: "10.20.1.12:8080",
          health_check: "http",
          health_path: "/health",
          weight: 1,
          healthy: true,
          inflight: 4,
          response_time_ewma_ms: 58,
          passive_failures: 0,
        },
        {
          id: 2,
          address: "10.20.1.13:8080",
          health_check: "http",
          health_path: "/health",
          weight: 1,
          healthy: false,
          inflight: 0,
          response_time_ewma_ms: null,
          passive_failures: 3,
        },
      ],
    },
    {
      name: "console-pool",
      algorithm: "round_robin",
      connect_timeout_seconds: 3,
      request_timeout_seconds: 30,
      passive_health: false,
      backends: [
        {
          id: 0,
          address: "10.20.2.21:3000",
          health_check: "tcp",
          health_path: null,
          weight: 1,
          healthy: true,
          inflight: 2,
          response_time_ewma_ms: 19,
          passive_failures: 0,
        },
        {
          id: 1,
          address: "10.20.2.22:3000",
          health_check: "tcp",
          health_path: null,
          weight: 1,
          healthy: true,
          inflight: 1,
          response_time_ewma_ms: 21,
          passive_failures: 0,
        },
      ],
    },
  ],
  routes: [
    {
      name: "public-api",
      host: "api.bearust.local",
      path_prefix: "/",
      upstream_pool: "api-pool",
    },
    {
      name: "admin-console",
      host: "console.bearust.local",
      path_prefix: "/",
      upstream_pool: "console-pool",
    },
  ],
  capabilities: {
    algorithms: [
      "round_robin",
      "least_connections",
      "weighted",
      "ip_hash",
      "adaptive_weight",
      "plugin",
    ],
    health_checks: ["tcp", "http"],
    passive_health: true,
    adaptive_weighting: true,
  },
};

export function LoadBalancer() {
  const { t } = useTranslation();
  const canWrite = useAuthStore((state) => state.user?.role !== "viewer");
  const [snapshot, setSnapshot] = useState<LoadBalancerSnapshot | null>(
    DEMO_MODE ? demoSnapshot : null,
  );
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [poolDialogOpen, setPoolDialogOpen] = useState(false);
  const [routeDialogOpen, setRouteDialogOpen] = useState(false);
  const [editingPoolName, setEditingPoolName] = useState<string | null>(null);
  const [editingRouteName, setEditingRouteName] = useState<string | null>(null);
  const [poolDraft, setPoolDraft] = useState<PoolDraft>(emptyPool);
  const [routeDraft, setRouteDraft] = useState<RouteDraft>(emptyRoute);
  const [confirmTarget, setConfirmTarget] = useState<ConfirmTarget>(null);

  const refresh = async () => {
    if (DEMO_MODE) return;
    setLoading(true);
    setError("");
    try {
      setSnapshot(await api.loadBalancer());
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);
  useRealtimeRefresh(["load_balancer.changed"], refresh);

  const pools = snapshot?.pools ?? [];
  const routes = snapshot?.routes ?? [];
  const backendCount = pools.reduce(
    (total, pool) => total + pool.backends.length,
    0,
  );
  const healthyBackends = pools.reduce(
    (total, pool) =>
      total + pool.backends.filter((backend) => backend.healthy).length,
    0,
  );
  const degradedPools = pools.filter(
    (pool) =>
      pool.backends.length === 0 ||
      pool.backends.some((backend) => !backend.healthy),
  ).length;
  const algorithmOptions = snapshot?.capabilities.algorithms ?? [
    "round_robin",
    "least_connections",
    "weighted",
    "ip_hash",
    "adaptive_weight",
    "plugin",
  ];

  const openNewPool = () => {
    setEditingPoolName(null);
    setPoolDraft(emptyPool);
    setPoolDialogOpen(true);
  };

  const openEditPool = (pool: LoadBalancerPool) => {
    setEditingPoolName(pool.name);
    setPoolDraft({
      name: pool.name,
      algorithm: pool.algorithm,
      connect_timeout_seconds: String(pool.connect_timeout_seconds),
      request_timeout_seconds: String(pool.request_timeout_seconds),
      passive_health: pool.passive_health,
      backends: pool.backends.map((backend) => ({
        address: backend.address,
        health_check: backend.health_check,
        health_path: backend.health_path ?? "",
        weight: String(backend.weight),
      })),
    });
    setPoolDialogOpen(true);
  };

  const persist = async (
    nextPools: LoadBalancerPool[],
    nextRoutes: LoadBalancerRoute[],
  ) => {
    const request = toConfigRequest(nextPools, nextRoutes);
    if (DEMO_MODE) {
      setSnapshot((current) =>
        current ? makeDemoSnapshot(request, current.generation + 1) : current,
      );
      return;
    }
    setSnapshot(await api.updateLoadBalancer(request));
  };

  const savePool = async (event: FormEvent) => {
    event.preventDefault();
    if (!snapshot || !canWrite) return;
    const name = poolDraft.name.trim();
    const connectTimeout = Number(poolDraft.connect_timeout_seconds);
    const requestTimeout = Number(poolDraft.request_timeout_seconds);
    const backends = poolDraft.backends
      .map((backend) => ({
        ...backend,
        address: backend.address.trim(),
        health_path: backend.health_path.trim(),
        weight: Number(backend.weight),
      }))
      .filter((backend) => backend.address);
    if (
      !name ||
      !Number.isInteger(connectTimeout) ||
      connectTimeout < 1 ||
      !Number.isInteger(requestTimeout) ||
      requestTimeout < 1 ||
      backends.length === 0 ||
      backends.some(
        (backend) =>
          !Number.isInteger(backend.weight) ||
          backend.weight < 1 ||
          backend.weight > 1000,
      )
    ) {
      setError(t("shell.poolValidation"));
      return;
    }
    if (
      backends.some(
        (backend) =>
          backend.health_check === "http" &&
          !backend.health_path.startsWith("/"),
      )
    ) {
      setError(t("shell.httpHealthPathValidation"));
      return;
    }
    const duplicate = pools.some(
      (pool) => pool.name === name && pool.name !== editingPoolName,
    );
    if (duplicate) {
      setError(t("shell.uniquePoolValidation"));
      return;
    }
    const nextPool: LoadBalancerPool = {
      name,
      algorithm: poolDraft.algorithm,
      connect_timeout_seconds: connectTimeout,
      request_timeout_seconds: requestTimeout,
      passive_health: poolDraft.passive_health,
      backends: backends.map((backend, id) => ({
        id,
        address: backend.address,
        health_check: backend.health_check,
        health_path:
          backend.health_check === "http" ? backend.health_path : null,
        weight: backend.weight,
        healthy: true,
        inflight: 0,
        response_time_ewma_ms: null,
        passive_failures: 0,
      })),
    };
    const nextPools =
      editingPoolName == null
        ? [...pools, nextPool]
        : pools.map((pool) =>
            pool.name === editingPoolName ? nextPool : pool,
          );
    const nextRoutes = routes.map((route) =>
      route.upstream_pool === editingPoolName
        ? { ...route, upstream_pool: name }
        : route,
    );
    setBusy(true);
    setError("");
    try {
      await persist(nextPools, nextRoutes);
      setPoolDialogOpen(false);
      toast.success(
        editingPoolName == null
          ? t("shell.upstreamPoolCreated")
          : t("shell.upstreamPoolUpdated"),
      );
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const removePool = (pool: LoadBalancerPool) => {
    if (!canWrite) return;
    const linkedRoutes = routes.filter(
      (route) => route.upstream_pool === pool.name,
    );
    if (linkedRoutes.length > 0) {
      setError(
        t("shell.linkedRoutesValidation", {
          name: pool.name,
          count: linkedRoutes.length,
        }),
      );
      return;
    }
    setConfirmTarget({ kind: "pool", name: pool.name });
  };

  const removeRoute = (route: LoadBalancerRoute) => {
    if (!canWrite) return;
    setConfirmTarget({ kind: "route", name: route.name });
  };

  const confirmRemove = async () => {
    if (!confirmTarget) return;
    const target = confirmTarget;
    setConfirmTarget(null);
    setBusy(true);
    setError("");
    try {
      if (target.kind === "pool") {
        await persist(
          pools.filter((item) => item.name !== target.name),
          routes,
        );
        toast.success(t("shell.upstreamPoolRemoved"));
      } else {
        await persist(
          pools,
          routes.filter((item) => item.name !== target.name),
        );
        toast.success(t("shell.routeRemoved"));
      }
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const openNewRoute = () => {
    setEditingRouteName(null);
    setRouteDraft({ ...emptyRoute, upstream_pool: pools[0]?.name ?? "" });
    setRouteDialogOpen(true);
  };

  const openEditRoute = (route: LoadBalancerRoute) => {
    setEditingRouteName(route.name);
    setRouteDraft(route);
    setRouteDialogOpen(true);
  };

  const saveRoute = async (event: FormEvent) => {
    event.preventDefault();
    if (!snapshot || !canWrite) return;
    const nextRoute = {
      ...routeDraft,
      name: routeDraft.name.trim(),
      host: routeDraft.host.trim().toLowerCase(),
      path_prefix: routeDraft.path_prefix.trim() || "/",
    };
    if (
      !nextRoute.name ||
      !nextRoute.host ||
      !nextRoute.path_prefix.startsWith("/") ||
      !nextRoute.upstream_pool
    ) {
      setError(t("shell.routeValidation"));
      return;
    }
    if (
      routes.some(
        (route) =>
          route.name === nextRoute.name && route.name !== editingRouteName,
      )
    ) {
      setError(t("shell.uniqueRouteValidation"));
      return;
    }
    setBusy(true);
    setError("");
    try {
      const nextRoutes =
        editingRouteName == null
          ? [...routes, nextRoute]
          : routes.map((route) =>
              route.name === editingRouteName ? nextRoute : route,
            );
      await persist(pools, nextRoutes);
      setRouteDialogOpen(false);
      toast.success(
        editingRouteName == null
          ? t("shell.routeCreated")
          : t("shell.routeUpdated"),
      );
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  return (
    <Main>
      <PageHeader
        title={t("shell.loadBalancerTitle")}
        description={t("shell.loadBalancerDescription")}
        action={
          <div className="flex flex-wrap items-center justify-end gap-2">
            <Badge
              variant="outline"
              className="hidden gap-1.5 rounded-full sm:inline-flex"
            >
              <span
                className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : loading ? "bg-amber-500" : "bg-emerald-500"}`}
              />
              {DEMO_MODE
                ? t("shell.demoData")
                : loading
                  ? t("shell.loadingRuntime")
                  : t("shell.generation", {
                      value: snapshot?.generation ?? "—",
                    })}
            </Badge>
            <Button
              variant="outline"
              size="icon"
              aria-label={t("shell.refreshLoadBalancer")}
              onClick={() => void refresh()}
              disabled={loading || busy}
            >
              <RefreshCw className={loading ? "animate-spin" : ""} />
            </Button>
            <Button onClick={openNewPool} disabled={!canWrite || busy}>
              <Plus /> {t("shell.addPool")}
            </Button>
          </div>
        }
      />
      {error && (
        <div
          role="alert"
          className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive"
        >
          {error}
        </div>
      )}

      <div className="mb-6 grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <Summary
          icon={GitBranch}
          label={t("shell.upstreamPools")}
          value={String(pools.length)}
          detail={t("shell.virtualHostRoutes", { count: routes.length })}
        />
        <Summary
          icon={Server}
          label={t("shell.backends")}
          value={`${healthyBackends} / ${backendCount}`}
          detail={t("shell.healthyBackendTargets")}
        />
        <Summary
          icon={Activity}
          label={t("shell.degradedPools")}
          value={String(degradedPools)}
          detail={
            degradedPools
              ? t("shell.reviewFailoverCapacity")
              : t("shell.allPoolsOperational")
          }
          warning={degradedPools > 0}
        />
        <Summary
          icon={Route}
          label={t("shell.routePrecedence")}
          value={t("shell.longestPath")}
          detail={t("shell.hostPathMatching")}
        />
      </div>

      <div className="grid gap-6 xl:grid-cols-[minmax(0,1.5fr)_minmax(320px,1fr)]">
        <Card>
          <CardHeader className="flex flex-row items-start justify-between gap-4">
            <div>
              <CardTitle>{t("shell.upstreamPools")}</CardTitle>
              <CardDescription>
                {t("shell.activeBackendsHealth")}
              </CardDescription>
            </div>
            <Button
              variant="outline"
              size="sm"
              onClick={openNewPool}
              disabled={!canWrite || busy}
            >
              <Plus />
              {t("shell.pool")}
            </Button>
          </CardHeader>
          <CardContent>
            {loading ? (
              <LoadingRows />
            ) : pools.length === 0 ? (
              <EmptyState
                title={t("shell.noUpstreamPools")}
                description={t("shell.createPoolBeforeRoute")}
                action={
                  <Button onClick={openNewPool} disabled={!canWrite}>
                    <Plus />
                    {t("shell.createPool")}
                  </Button>
                }
              />
            ) : (
              <div className="space-y-3">
                {pools.map((pool) => (
                  <PoolCard
                    key={pool.name}
                    pool={pool}
                    canWrite={canWrite}
                    busy={busy}
                    onEdit={() => openEditPool(pool)}
                    onDelete={() => removePool(pool)}
                  />
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>{t("shell.routingModel")}</CardTitle>
            <CardDescription>{t("shell.everyRequest")}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="rounded-lg border bg-muted/30 p-4 text-sm">
              <div className="flex items-center gap-2 font-medium">
                <Route className="size-4 text-primary" />
                {t("shell.virtualHostRouting")}
              </div>
              <p className="mt-2 text-xs leading-5 text-muted-foreground">
                {t("shell.routesEvaluated")}
              </p>
            </div>
            <div className="space-y-2">
              <p className="text-xs font-medium uppercase tracking-wide text-muted-foreground">
                {t("shell.prdCoverage")}
              </p>
              {algorithmRequirements.map((requirement) => {
                const available =
                  snapshot?.capabilities.algorithms.includes(
                    requirement.key,
                  ) === true;
                return (
                  <div
                    className="rounded-md border px-3 py-2"
                    key={requirement.key}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span className="text-xs font-medium">
                        {requirement.label}
                      </span>
                      <StatusBadge status={available ? "healthy" : "warning"}>
                        {available
                          ? t("shell.available")
                          : t("shell.notExposed")}
                      </StatusBadge>
                    </div>
                    <p className="mt-1 text-[11px] leading-4 text-muted-foreground">
                      {requirement.detail}
                    </p>
                  </div>
                );
              })}
              <Capability
                label={t("shell.activeChecks")}
                value={t("shell.types", {
                  count: snapshot?.capabilities.health_checks.length ?? 0,
                })}
                status="healthy"
              />
              <Capability
                label={t("shell.passiveHealthTelemetry")}
                value={
                  snapshot?.capabilities.passive_health
                    ? t("shell.available")
                    : t("shell.notExposed")
                }
                status={
                  snapshot?.capabilities.passive_health ? "healthy" : "warning"
                }
              />
              <Capability
                label={t("shell.adaptiveWeighting")}
                value={
                  snapshot?.capabilities.adaptive_weighting
                    ? t("shell.available")
                    : t("shell.learningPending")
                }
                status={
                  snapshot?.capabilities.adaptive_weighting
                    ? "healthy"
                    : "warning"
                }
              />
            </div>
            <Button variant="outline" className="w-full" asChild>
              <Link to="/analytics">
                {t("shell.reviewTrafficLatency")} <ArrowRight />
              </Link>
            </Button>
          </CardContent>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader className="flex flex-row items-start justify-between gap-4">
          <div>
            <CardTitle>{t("shell.virtualHostRoutesTitle")}</CardTitle>
            <CardDescription>{t("shell.mapDomains")}</CardDescription>
          </div>
          <Button
            variant="outline"
            onClick={openNewRoute}
            disabled={!canWrite || pools.length === 0 || busy}
          >
            <Plus />
            {t("shell.addRoute")}
          </Button>
        </CardHeader>
        <CardContent>
          {routes.length === 0 ? (
            <EmptyState
              title={t("shell.noRoutesConfigured")}
              description={t("shell.poolWithoutTraffic")}
              action={
                pools.length > 0 ? (
                  <Button onClick={openNewRoute} disabled={!canWrite}>
                    <Plus />
                    {t("shell.createRoute")}
                  </Button>
                ) : undefined
              }
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b text-left text-xs text-muted-foreground">
                    <th className="pb-3 font-medium">{t("shell.routeName")}</th>
                    <th className="pb-3 font-medium">{t("shell.host")}</th>
                    <th className="pb-3 font-medium">
                      {t("shell.pathPrefix")}
                    </th>
                    <th className="pb-3 font-medium">
                      {t("shell.upstreamPool")}
                    </th>
                    <th className="pb-3 text-right font-medium">
                      {t("shell.actions")}
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {routes.map((route) => (
                    <tr className="border-b last:border-0" key={route.name}>
                      <td className="py-4 font-medium">{route.name}</td>
                      <td className="py-4 font-mono text-xs">{route.host}</td>
                      <td className="py-4 font-mono text-xs">
                        {route.path_prefix}
                      </td>
                      <td className="py-4">
                        <Badge variant="secondary">{route.upstream_pool}</Badge>
                      </td>
                      <td className="py-4 text-right">
                        <div className="flex justify-end gap-1">
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label={t("shell.edit")}
                            onClick={() => openEditRoute(route)}
                            disabled={!canWrite || busy}
                          >
                            <Pencil />
                          </Button>
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label={t("shell.delete")}
                            onClick={() => removeRoute(route)}
                            disabled={!canWrite || busy}
                          >
                            <Trash2 />
                          </Button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>{t("shell.operationalGuardrails")}</CardTitle>
          <CardDescription>{t("shell.changesValidated")}</CardDescription>
        </CardHeader>
        <CardContent className="grid gap-3 text-sm md:grid-cols-3">
          <Guardrail
            icon={CheckCircle2}
            title={t("shell.atomicReload")}
            detail={t("shell.atomicReloadDetail")}
          />
          <Guardrail
            icon={Clock3}
            title={t("shell.boundedTimeouts")}
            detail={t("shell.boundedTimeoutsDetail")}
          />
          <Guardrail
            icon={Settings2}
            title={t("shell.hotConfiguration")}
            detail={t("shell.hotConfigurationDetail")}
          />
        </CardContent>
      </Card>

      <PoolDialog
        open={poolDialogOpen}
        onOpenChange={setPoolDialogOpen}
        draft={poolDraft}
        setDraft={setPoolDraft}
        editing={editingPoolName != null}
        algorithms={algorithmOptions}
        busy={busy}
        onSubmit={savePool}
      />
      <RouteDialog
        open={routeDialogOpen}
        onOpenChange={setRouteDialogOpen}
        draft={routeDraft}
        setDraft={setRouteDraft}
        editing={editingRouteName != null}
        pools={pools}
        busy={busy}
        onSubmit={saveRoute}
      />
      <ConfirmDialog
        open={confirmTarget != null}
        onOpenChange={(open) => {
          if (!open && !busy) setConfirmTarget(null);
        }}
        title={
          confirmTarget?.kind === "pool"
            ? t("shell.deleteUpstreamPool")
            : t("shell.deleteVirtualRoute")
        }
        description={
          confirmTarget?.kind === "pool"
            ? t("shell.poolWillBeRemoved", { name: confirmTarget.name })
            : t("shell.routeWillStop", {
                name: confirmTarget?.name ?? "selected",
              })
        }
        pending={busy}
        onConfirm={() => void confirmRemove()}
      />
    </Main>
  );
}

function PoolCard({
  pool,
  canWrite,
  busy,
  onEdit,
  onDelete,
}: {
  pool: LoadBalancerPool;
  canWrite: boolean;
  busy: boolean;
  onEdit: () => void;
  onDelete: () => void;
}) {
  const { t } = useTranslation();
  const healthy = pool.backends.filter((backend) => backend.healthy).length;
  return (
    <div className="rounded-lg border p-4">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <p className="font-medium">{pool.name}</p>
            <Badge variant="outline">{formatAlgorithm(pool.algorithm)}</Badge>
            {pool.passive_health && (
              <Badge variant="secondary">{t("shell.passiveHealth")}</Badge>
            )}
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            {healthy} / {pool.backends.length}{" "}
            {t("shell.healthy").toLowerCase()} · {pool.connect_timeout_seconds}s
            connect · {pool.request_timeout_seconds}s request
          </p>
        </div>
        <div className="flex gap-1">
          <Button
            variant="ghost"
            size="icon"
            aria-label={`${t("shell.edit")} ${pool.name}`}
            onClick={onEdit}
            disabled={!canWrite || busy}
          >
            <Pencil />
          </Button>
          <Button
            variant="ghost"
            size="icon"
            aria-label={`${t("shell.delete")} ${pool.name}`}
            onClick={onDelete}
            disabled={!canWrite || busy}
          >
            <Trash2 />
          </Button>
        </div>
      </div>
      <div className="mt-4 grid gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {pool.backends.map((backend) => (
          <BackendStatus backend={backend} key={backend.id} />
        ))}
      </div>
    </div>
  );
}

function BackendStatus({ backend }: { backend: LoadBalancerBackend }) {
  const { t } = useTranslation();
  return (
    <div className="rounded-md border bg-muted/20 p-3">
      <div className="flex items-start justify-between gap-2">
        <span className="truncate font-mono text-xs">{backend.address}</span>
        <StatusBadge status={backend.healthy ? "healthy" : "danger"}>
          {backend.healthy ? t("shell.healthy") : t("shell.unhealthy")}
        </StatusBadge>
      </div>
      <div className="mt-2 grid grid-cols-2 gap-x-2 gap-y-1 text-[11px] text-muted-foreground">
        <span>
          {backend.health_check === "http"
            ? `HTTP ${backend.health_path}`
            : t("shell.tcpProbe")}
        </span>
        <span className="text-right">
          {backend.inflight} {t("shell.inFlight")}
        </span>
        <span>
          {t("shell.weight")} {backend.weight}
        </span>
        <span className="text-right">
          {backend.response_time_ewma_ms == null
            ? t("shell.noEwma")
            : `${backend.response_time_ewma_ms}ms EWMA`}
        </span>
        {backend.passive_failures > 0 && (
          <span className="col-span-2 text-amber-700 dark:text-amber-400">
            {t("shell.passiveFailures", { count: backend.passive_failures })}
          </span>
        )}
      </div>
    </div>
  );
}

function PoolDialog({
  open,
  onOpenChange,
  draft,
  setDraft,
  editing,
  algorithms,
  busy,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  draft: PoolDraft;
  setDraft: (draft: PoolDraft) => void;
  editing: boolean;
  algorithms: string[];
  busy: boolean;
  onSubmit: (event: FormEvent) => void;
}) {
  const { t } = useTranslation();
  const updateBackend = (index: number, patch: Partial<BackendDraft>) =>
    setDraft({
      ...draft,
      backends: draft.backends.map((backend, current) =>
        current === index ? { ...backend, ...patch } : backend,
      ),
    });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="max-h-[90vh] overflow-y-auto sm:max-w-2xl">
        <DialogHeader>
          <DialogTitle>
            {editing
              ? t("shell.editUpstreamPool")
              : t("shell.createUpstreamPool")}
          </DialogTitle>
          <DialogDescription>
            {t("shell.poolDialogDescription")}
          </DialogDescription>
        </DialogHeader>
        <form id="pool-form" className="space-y-5" onSubmit={onSubmit}>
          <div className="grid gap-4 sm:grid-cols-2">
            <Field
              label={t("shell.poolName")}
              value={draft.name}
              onChange={(value) => setDraft({ ...draft, name: value })}
              placeholder="api-pool"
            />
            <div className="space-y-2">
              <Label htmlFor="pool-algorithm">{t("shell.algorithm")}</Label>
              <select
                id="pool-algorithm"
                value={draft.algorithm}
                onChange={(event) =>
                  setDraft({
                    ...draft,
                    algorithm: event.target.value as LoadBalancerAlgorithm,
                  })
                }
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                disabled={busy}
              >
                {algorithms.map((algorithm) => (
                  <option value={algorithm} key={algorithm}>
                    {formatAlgorithm(algorithm)}
                  </option>
                ))}
              </select>
            </div>
            <Field
              label={t("shell.connectTimeout")}
              type="number"
              value={draft.connect_timeout_seconds}
              onChange={(value) =>
                setDraft({ ...draft, connect_timeout_seconds: value })
              }
            />
            <Field
              label={t("shell.requestTimeout")}
              type="number"
              value={draft.request_timeout_seconds}
              onChange={(value) =>
                setDraft({ ...draft, request_timeout_seconds: value })
              }
            />
          </div>
          <label className="flex items-start gap-3 rounded-lg border p-3 text-sm">
            <input
              type="checkbox"
              checked={draft.passive_health}
              onChange={(event) =>
                setDraft({ ...draft, passive_health: event.target.checked })
              }
              disabled={busy}
              className="mt-0.5 size-4 accent-primary"
            />
            <span>
              <span className="font-medium">
                {t("shell.enablePassiveHealth")}
              </span>
              <span className="mt-1 block text-xs text-muted-foreground">
                {t("shell.passiveHealthDetail")}
              </span>
            </span>
          </label>
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-medium">
                  {t("shell.backendTargets")}
                </p>
                <p className="text-xs text-muted-foreground">
                  {t("shell.weightsBound")}
                </p>
              </div>
              <Button
                type="button"
                variant="outline"
                size="sm"
                onClick={() =>
                  setDraft({
                    ...draft,
                    backends: [
                      ...draft.backends,
                      {
                        address: "",
                        health_check: "tcp",
                        health_path: "",
                        weight: "1",
                      },
                    ],
                  })
                }
                disabled={busy}
              >
                <Plus />
                {t("shell.backend")}
              </Button>
            </div>
            {draft.backends.map((backend, index) => (
              <div
                className="grid gap-3 rounded-lg border p-3 sm:grid-cols-[minmax(0,1fr)_110px_90px_minmax(0,1fr)_auto]"
                key={`${index}-${backend.address}`}
              >
                <Field
                  label={t("shell.address", { index: index + 1 })}
                  value={backend.address}
                  onChange={(value) => updateBackend(index, { address: value })}
                  placeholder="10.0.0.11:8080"
                />
                <div className="space-y-2">
                  <Label htmlFor={`health-check-${index}`}>
                    {t("shell.check")}
                  </Label>
                  <select
                    id={`health-check-${index}`}
                    value={backend.health_check}
                    onChange={(event) =>
                      updateBackend(index, {
                        health_check: event.target
                          .value as LoadBalancerHealthCheck,
                      })
                    }
                    className="h-9 w-full rounded-md border border-input bg-background px-2 text-sm"
                    disabled={busy}
                  >
                    <option value="tcp">TCP</option>
                    <option value="http">HTTP</option>
                  </select>
                </div>
                <Field
                  label={t("shell.weight")}
                  type="number"
                  value={backend.weight}
                  onChange={(value) => updateBackend(index, { weight: value })}
                  placeholder="1"
                  disabled={busy}
                />
                <Field
                  label={t("shell.httpPath")}
                  value={backend.health_path}
                  onChange={(value) =>
                    updateBackend(index, { health_path: value })
                  }
                  placeholder="/health"
                  disabled={busy || backend.health_check !== "http"}
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="self-end"
                  aria-label={t("shell.removeBackend", { index: index + 1 })}
                  onClick={() =>
                    setDraft({
                      ...draft,
                      backends: draft.backends.filter(
                        (_, current) => current !== index,
                      ),
                    })
                  }
                  disabled={busy || draft.backends.length === 1}
                >
                  <Trash2 />
                </Button>
              </div>
            ))}
          </div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("shell.cancel")}
          </Button>
          <Button type="submit" form="pool-form" disabled={busy}>
            <Settings2 />
            {editing ? t("shell.savePool") : t("shell.createPool")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function RouteDialog({
  open,
  onOpenChange,
  draft,
  setDraft,
  editing,
  pools,
  busy,
  onSubmit,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  draft: RouteDraft;
  setDraft: (draft: RouteDraft) => void;
  editing: boolean;
  pools: LoadBalancerPool[];
  busy: boolean;
  onSubmit: (event: FormEvent) => void;
}) {
  const { t } = useTranslation();
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>
            {editing
              ? t("shell.editVirtualRoute")
              : t("shell.createVirtualRoute")}
          </DialogTitle>
          <DialogDescription>
            {t("shell.routeDialogDescription")}
          </DialogDescription>
        </DialogHeader>
        <form id="route-form" className="space-y-4" onSubmit={onSubmit}>
          <Field
            label={t("shell.routeName")}
            value={draft.name}
            onChange={(value) => setDraft({ ...draft, name: value })}
            placeholder="public-api"
          />
          <Field
            label={t("shell.host")}
            value={draft.host}
            onChange={(value) => setDraft({ ...draft, host: value })}
            placeholder="api.example.com"
          />
          <Field
            label={t("shell.pathPrefix")}
            value={draft.path_prefix}
            onChange={(value) => setDraft({ ...draft, path_prefix: value })}
            placeholder="/"
          />
          <div className="space-y-2">
            <Label htmlFor="route-pool">{t("shell.upstreamPool")}</Label>
            <select
              id="route-pool"
              value={draft.upstream_pool}
              onChange={(event) =>
                setDraft({ ...draft, upstream_pool: event.target.value })
              }
              className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              disabled={busy}
            >
              {pools.map((pool) => (
                <option value={pool.name} key={pool.name}>
                  {pool.name}
                </option>
              ))}
            </select>
          </div>
        </form>
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("shell.cancel")}
          </Button>
          <Button type="submit" form="route-form" disabled={busy}>
            <Route />
            {editing ? t("shell.saveRoute") : t("shell.createRoute")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function Summary({
  icon: Icon,
  label,
  value,
  detail,
  warning = false,
}: {
  icon: typeof Server;
  label: string;
  value: string;
  detail: string;
  warning?: boolean;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {label}
        </CardTitle>
        <Icon
          className={`size-4 ${warning ? "text-amber-600" : "text-muted-foreground"}`}
        />
      </CardHeader>
      <CardContent>
        <p className="text-2xl font-bold tabular-nums">{value}</p>
        <p className="text-xs text-muted-foreground">{detail}</p>
      </CardContent>
    </Card>
  );
}
function Capability({
  label,
  value,
  status,
}: {
  label: string;
  value: string;
  status: "healthy" | "warning";
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-md border px-3 py-2 text-xs">
      <span className="text-muted-foreground">{label}</span>
      <StatusBadge status={status}>{value}</StatusBadge>
    </div>
  );
}
function Guardrail({
  icon: Icon,
  title,
  detail,
}: {
  icon: typeof CheckCircle2;
  title: string;
  detail: string;
}) {
  return (
    <div className="rounded-lg border p-4">
      <Icon className="size-4 text-primary" />
      <p className="mt-3 font-medium">{title}</p>
      <p className="mt-1 text-xs leading-5 text-muted-foreground">{detail}</p>
    </div>
  );
}
function EmptyState({
  title,
  description,
  action,
}: {
  title: string;
  description: string;
  action?: ReactNode;
}) {
  return (
    <div className="flex flex-col items-center justify-center rounded-lg border border-dashed px-6 py-12 text-center">
      <CircleAlert className="size-5 text-muted-foreground" />
      <p className="mt-3 text-sm font-medium">{title}</p>
      <p className="mt-1 max-w-sm text-xs text-muted-foreground">
        {description}
      </p>
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
function LoadingRows() {
  const { t } = useTranslation();
  return (
    <div
      className="space-y-3"
      role="status"
      aria-label={t("shell.loadingUpstreamPools")}
    >
      {[1, 2].map((item) => (
        <div className="h-28 animate-pulse rounded-lg bg-muted" key={item} />
      ))}
    </div>
  );
}
function Field({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
  disabled = false,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  disabled?: boolean;
}) {
  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <Input
        aria-label={label}
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        required
      />
    </div>
  );
}
function formatAlgorithm(value: string) {
  return value
    .split("_")
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(" ");
}
function toConfigRequest(
  pools: LoadBalancerPool[],
  routes: LoadBalancerRoute[],
): LoadBalancerConfigRequest {
  return {
    pools: pools.map((pool) => ({
      name: pool.name,
      algorithm: pool.algorithm,
      connect_timeout_seconds: pool.connect_timeout_seconds,
      request_timeout_seconds: pool.request_timeout_seconds,
      passive_health: pool.passive_health,
      backends: pool.backends.map((backend) => ({
        address: backend.address,
        health_check: backend.health_check,
        health_path:
          backend.health_check === "http" ? backend.health_path : null,
        weight: backend.weight,
      })),
    })),
    routes,
  };
}
function makeDemoSnapshot(
  request: LoadBalancerConfigRequest,
  generation: number,
): LoadBalancerSnapshot {
  return {
    generation,
    pools: request.pools.map((pool) => ({
      ...pool,
      backends: pool.backends.map((backend, id) => ({
        ...backend,
        id,
        healthy: true,
        inflight: 0,
        response_time_ewma_ms: null,
        passive_failures: 0,
      })),
    })),
    routes: request.routes,
    capabilities: demoSnapshot.capabilities,
  };
}
