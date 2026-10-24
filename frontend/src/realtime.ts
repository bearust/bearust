import { useEffect, useRef, useState } from "react";

export const REALTIME_STATUSES = ["connecting", "connected", "disconnected"] as const;
export type RealtimeStatus = (typeof REALTIME_STATUSES)[number];
export type RealtimeLoaders = Partial<{
  hosts: () => unknown | Promise<unknown>;
  certificates: () => unknown | Promise<unknown>;
  users: () => unknown | Promise<unknown>;
  roles: () => unknown | Promise<unknown>;
  auditLogs: () => unknown | Promise<unknown>;
  sessions: () => unknown | Promise<unknown>;
  waf: () => unknown | Promise<unknown>;
  rateLimit: () => unknown | Promise<unknown>;
  bot: () => unknown | Promise<unknown>;
  analytics: () => unknown | Promise<unknown>;
  baseline: () => unknown | Promise<unknown>;
  anomaly: () => unknown | Promise<unknown>;
  adaptiveTuning: () => unknown | Promise<unknown>;
  aiAdvisor: () => unknown | Promise<unknown>;
  plugins: () => unknown | Promise<unknown>;
  loadBalancer: () => unknown | Promise<unknown>;
  security: () => unknown | Promise<unknown>;
  cluster: () => unknown | Promise<unknown>;
}>;

const EVENT_LOADERS: Record<string, keyof RealtimeLoaders> = {
  "proxy_hosts.changed": "hosts",
  "load_balancer.changed": "loadBalancer",
  "certificates.changed": "certificates",
  "users.changed": "users",
  "roles.changed": "roles",
  audit: "auditLogs",
  "sessions.changed": "sessions",
  "waf.changed": "waf",
  "bot.changed": "bot",
  "rate_limit.changed": "rateLimit",
  "analytics.changed": "analytics",
  "baseline.changed": "baseline",
  "anomaly.changed": "anomaly",
  "adaptive_tuning.changed": "adaptiveTuning",
  "ai_advisor.changed": "aiAdvisor",
  "plugins.changed": "plugins",
  "security.changed": "security",
  "cluster.changed": "cluster",
};
const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;

export function useRealtimeUpdates(loaders: RealtimeLoaders): RealtimeStatus {
  const [status, setStatus] = useState<RealtimeStatus>("connecting");
  const loadersRef = useRef(loaders);
  loadersRef.current = loaders;

  useEffect(() => {
    if (import.meta.env.VITE_DEMO_MODE === "true") {
      setStatus("connected");
      return;
    }
    if (typeof EventSource === "undefined") {
      setStatus("disconnected");
      return;
    }
    let source: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    let delay = RECONNECT_BASE_MS;
    let connectedOnce = false;
    // Last seen `<epoch>:<sequence>` id, sent on reconnect so the server can
    // replay what was missed instead of forcing a full reload.
    let lastEventId = "";

    const reload = (loader: (() => unknown | Promise<unknown>) | undefined) => {
      if (loader) void Promise.resolve().then(loader).catch(() => undefined);
    };
    const resync = () => {
      // Reload current state when the server cannot replay the gap; page
      // hooks receive a single notification even when they listen to several kinds.
      for (const loader of new Set(Object.values(loadersRef.current))) reload(loader);
      window.dispatchEvent(new Event("bearust:realtime-resync"));
    };

    const connect = () => {
      if (stopped) return;
      setStatus("connecting");
      const url = lastEventId
        ? `/api/events?last_event_id=${encodeURIComponent(lastEventId)}`
        : "/api/events";
      const connection = new EventSource(url, { withCredentials: true });
      source = connection;
      const active = () => !stopped && source === connection;
      connection.onopen = () => {
        if (!active()) return;
        delay = RECONNECT_BASE_MS;
        setStatus("connected");
      };
      connection.addEventListener("ready", (event) => {
        if (!active()) return;
        let replay = "fresh";
        try {
          replay = (JSON.parse((event as MessageEvent).data) as { replay?: string }).replay ?? "fresh";
        } catch {
          // An unparseable ready frame is treated as a fresh stream.
        }
        // After a reconnect, anything but a complete replay means events may
        // have been missed (restart, failover, or an expired id).
        if (connectedOnce && replay !== "ok") resync();
        if (replay !== "ok") lastEventId = "";
        connectedOnce = true;
      });
      connection.onerror = () => {
        if (!active()) return;
        setStatus("disconnected");
        connection.close();
        source = null;
        if (timer === undefined) {
          timer = setTimeout(() => {
            timer = undefined;
            delay = Math.min(delay * 2, RECONNECT_MAX_MS);
            connect();
          }, delay);
        }
      };
      connection.addEventListener("reconnect", () => {
        if (active()) resync();
      });
      for (const kind of Object.keys(EVENT_LOADERS)) {
        connection.addEventListener(kind, (event) => {
          if (!active()) return;
          if (event.lastEventId) {
            if (!isNewer(event.lastEventId, lastEventId)) return;
            lastEventId = event.lastEventId;
          }
          window.dispatchEvent(new CustomEvent("bearust:realtime", { detail: kind }));
          reload(loadersRef.current[EVENT_LOADERS[kind]]);
          if (kind === "security.changed") {
            for (const key of ["waf", "bot", "rateLimit", "adaptiveTuning"] as const) {
              reload(loadersRef.current[key]);
            }
          }
        });
      }
    };
    connect();
    return () => {
      stopped = true;
      if (timer !== undefined) clearTimeout(timer);
      source?.close();
      source = null;
    };
  }, []);
  return status;
}

/** Compare `<epoch>:<sequence>` ids; an id from another epoch is newer. */
function isNewer(candidate: string, current: string): boolean {
  const [epoch, seq] = candidate.split(":");
  const [currentEpoch, currentSeq] = current.split(":");
  if (!current || epoch !== currentEpoch) return true;
  return Number(seq) > Number(currentSeq);
}
