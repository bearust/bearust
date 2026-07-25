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
  analytics: () => unknown | Promise<unknown>;
  baseline: () => unknown | Promise<unknown>;
  anomaly: () => unknown | Promise<unknown>;
  adaptiveTuning: () => unknown | Promise<unknown>;
}>;

const EVENT_LOADERS: Record<string, keyof RealtimeLoaders> = {
  "proxy_hosts.changed": "hosts",
  "certificates.changed": "certificates",
  "users.changed": "users",
  "roles.changed": "roles",
  audit: "auditLogs",
  "sessions.changed": "sessions",
  "waf.changed": "waf",
  "rate_limit.changed": "rateLimit",
  "analytics.changed": "analytics",
  "baseline.changed": "baseline",
  "anomaly.changed": "anomaly",
  "adaptive_tuning.changed": "adaptiveTuning",
};
const RECONNECT_BASE_MS = 1_000;
const RECONNECT_MAX_MS = 30_000;

export function useRealtimeUpdates(loaders: RealtimeLoaders): RealtimeStatus {
  const [status, setStatus] = useState<RealtimeStatus>("connecting");
  const loadersRef = useRef(loaders);
  loadersRef.current = loaders;

  useEffect(() => {
    if (typeof EventSource === "undefined") {
      setStatus("disconnected");
      return;
    }
    let source: EventSource | null = null;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let stopped = false;
    let delay = RECONNECT_BASE_MS;
    let lastId = 0;

    const connect = () => {
      if (stopped) return;
      setStatus("connecting");
      source = new EventSource("/api/events", { withCredentials: true });
      source.onopen = () => {
        delay = RECONNECT_BASE_MS;
        setStatus("connected");
      };
      source.onerror = () => {
        if (stopped) return;
        setStatus("disconnected");
        source?.close();
        source = null;
        if (timer === undefined) {
          timer = setTimeout(() => {
            timer = undefined;
            delay = Math.min(delay * 2, RECONNECT_MAX_MS);
            connect();
          }, delay);
        }
      };
      for (const kind of Object.keys(EVENT_LOADERS)) {
        source.addEventListener(kind, (event) => {
          const numericId = Number(event.lastEventId);
          if (Number.isFinite(numericId) && numericId > 0) {
            if (numericId <= lastId) return;
            lastId = numericId;
          }
          const loader = loadersRef.current[EVENT_LOADERS[kind]];
          if (loader) void Promise.resolve(loader()).catch(() => undefined);
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
