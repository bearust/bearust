// @vitest-environment jsdom
import React from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { useRealtimeUpdates } from "./realtime";
import { useRealtimeRefresh } from "./hooks/use-realtime-refresh";

type MockSource = {
  url: string;
  options?: EventSourceInit;
  onopen: (() => void) | null;
  onerror: (() => void) | null;
  close: ReturnType<typeof vi.fn>;
  addEventListener: (kind: string, listener: (event: MessageEvent) => void) => void;
  emit: (kind: string, id: string, data?: object) => void;
};

const sources: MockSource[] = [];
class MockEventSource {
  static instances = sources;
  onopen: (() => void) | null = null;
  onerror: (() => void) | null = null;
  close = vi.fn();
  private listeners = new Map<string, (event: MessageEvent) => void>();
  constructor(public url: string, public options?: EventSourceInit) {
    sources.push(this as unknown as MockSource);
  }
  addEventListener(kind: string, listener: (event: MessageEvent) => void) {
    this.listeners.set(kind, listener);
  }
  emit(kind: string, id: string, data: object = {}) {
    this.listeners.get(kind)?.(new MessageEvent(kind, { lastEventId: id, data: JSON.stringify(data) }));
  }
}

function Harness({ loaders, onStatus }: { loaders: Parameters<typeof useRealtimeUpdates>[0]; onStatus: (status: string) => void }) {
  const status = useRealtimeUpdates(loaders);
  onStatus(status);
  return <span>{status}</span>;
}

function PageHarness({ refresh }: { refresh: () => void }) {
  useRealtimeRefresh(["security.changed", "waf.changed"], refresh);
  return null;
}

describe("useRealtimeUpdates", () => {
  afterEach(() => {
    vi.useRealTimers();
    vi.restoreAllMocks();
    sources.length = 0;
    document.body.innerHTML = "";
    delete (globalThis as { EventSource?: unknown }).EventSource;
  });

  it("maps invalidation events, deduplicates ids, and passes credentials", async () => {
    (globalThis as unknown as { EventSource: typeof MockEventSource }).EventSource = MockEventSource;
    const auditLogs = vi.fn().mockResolvedValue(undefined);
    const hosts = vi.fn().mockResolvedValue(undefined);
    const certificates = vi.fn().mockResolvedValue(undefined);
    const users = vi.fn().mockResolvedValue(undefined);
    const roles = vi.fn().mockResolvedValue(undefined);
    const sessions = vi.fn().mockResolvedValue(undefined);
    const analytics = vi.fn().mockResolvedValue(undefined);
    const statuses: string[] = [];
    const element = document.createElement("div");
    document.body.appendChild(element);
    const root = createRoot(element);
    await act(async () => root.render(<Harness loaders={{ auditLogs, hosts, certificates, users, roles, sessions, analytics }} onStatus={(s) => statuses.push(s)} />));
    const source = sources[0];
    expect(source.url).toBe("/api/events");
    expect(source.options).toEqual({ withCredentials: true });
    await act(async () => source.onopen?.());
    await act(async () => source.emit("users.changed", "1"));
    await act(async () => source.emit("proxy_hosts.changed", "2"));
    await act(async () => source.emit("certificates.changed", "3"));
    await act(async () => source.emit("audit", "4"));
    await act(async () => source.emit("audit", "4"));
    await act(async () => source.emit("sessions.changed", "5"));
    await act(async () => source.emit("analytics.changed", "6"));
    await act(async () => source.emit("unknown", "7"));
    expect(users).toHaveBeenCalledTimes(1);
    expect(hosts).toHaveBeenCalledTimes(1);
    expect(certificates).toHaveBeenCalledTimes(1);
    expect(auditLogs).toHaveBeenCalledTimes(1);
    expect(sessions).toHaveBeenCalledTimes(1);
    expect(analytics).toHaveBeenCalledTimes(1);
    expect(statuses).toContain("connected");
    root.unmount();
    expect(source.close).toHaveBeenCalled();
  });

  it("marks disconnected and caps explicit reconnect delay", async () => {
    vi.useFakeTimers();
    (globalThis as unknown as { EventSource: typeof MockEventSource }).EventSource = MockEventSource;
    const element = document.createElement("div");
    document.body.appendChild(element);
    const root = createRoot(element);
    await act(async () => root.render(<Harness loaders={{}} onStatus={() => {}} />));
    const source = sources[0];
    await act(async () => source.onerror?.());
    expect(element.textContent).toBe("disconnected");
    await act(async () => vi.advanceTimersByTime(30_001));
    expect(sources.length).toBe(2);
    root.unmount();
  });

  it("delivers security and cluster invalidations to the active pages", async () => {
    vi.stubGlobal("EventSource", MockEventSource);
    const seen: string[] = [];
    const listener = (event: Event) => seen.push((event as CustomEvent<string>).detail);
    window.addEventListener("bearust:realtime", listener);
    const root = createRoot(document.body);
    try {
      await act(async () => root.render(<Harness loaders={{}} onStatus={() => {}} />));
      await act(async () => {
        sources[0].emit("security.changed", "1");
        sources[0].emit("cluster.changed", "2");
      });
      expect(seen).toEqual(["security.changed", "cluster.changed"]);
    } finally {
      await act(async () => root.unmount());
      window.removeEventListener("bearust:realtime", listener);
      vi.unstubAllGlobals();
    }
  });

  it("reloads missed data once per page and accepts reset ids after reconnect", async () => {
    vi.useFakeTimers();
    vi.stubGlobal("EventSource", MockEventSource);
    let pageRefreshes = 0;
    let hostRefreshes = 0;
    const root = createRoot(document.body);
    try {
      await act(async () => root.render(<>
        <Harness loaders={{ hosts: () => { hostRefreshes++; } }} onStatus={() => {}} />
        <PageHarness refresh={() => { pageRefreshes++; }} />
      </>));
      const first = sources[0];
      await act(async () => {
        first.onopen?.();
        first.emit("proxy_hosts.changed", "100");
        first.onerror?.();
      });
      await act(async () => vi.advanceTimersByTime(1_000));
      await act(async () => sources[1].onopen?.());
      expect(pageRefreshes).toBe(1);
      expect(hostRefreshes).toBe(2);
      await act(async () => sources[1].emit("proxy_hosts.changed", "1"));
      expect(hostRefreshes).toBe(3);
      // A late callback from the closed connection cannot advance the new cursor.
      await act(async () => {
        first.emit("proxy_hosts.changed", "101");
        sources[1].emit("proxy_hosts.changed", "2");
      });
      expect(hostRefreshes).toBe(4);
    } finally {
      await act(async () => root.unmount());
      vi.unstubAllGlobals();
    }
  });

  it("resynchronizes pages after the server reports a lagged subscriber", async () => {
    vi.stubGlobal("EventSource", MockEventSource);
    let refreshes = 0;
    const root = createRoot(document.body);
    try {
      await act(async () => root.render(<>
        <Harness loaders={{}} onStatus={() => {}} />
        <PageHarness refresh={() => { refreshes++; }} />
      </>));
      await act(async () => sources[0].emit("reconnect", "", { reason: "lagged" }));
      expect(refreshes).toBe(1);
    } finally {
      await act(async () => root.unmount());
      vi.unstubAllGlobals();
    }
  });
});
