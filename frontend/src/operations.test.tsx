// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { I18nextProvider } from "react-i18next";
import { api } from "@/api";
import { i18n, initI18n } from "@/i18n";
import { ThemeProvider } from "@/theme";
import { Operations } from "@/features/operations";

vi.mock("@tanstack/react-router", () => ({
  Link: ({ to, children, ...props }: { to: string; children: React.ReactNode } & Record<string, unknown>) => <a href={to} {...props}>{children}</a>,
}));

const summary = { requests: 600, status_2xx: 570, status_3xx: 10, status_4xx: 15, status_5xx: 5, waf_blocks: 8, bot_blocks: 2, bot_challenges: 4, rate_limited: 1, bandwidth_bytes: 64000, p50_ms: 22, p95_ms: 80, p99_ms: 140 };
const rows = [{ timestamp: "2026-08-16T10:00:00Z", proxy_host_id: 7, requests: 600, status_2xx: 570, status_3xx: 10, status_4xx: 15, status_5xx: 5, waf_blocks: 8, bot_blocks: 2, bot_challenges: 4, rate_limited: 1, bandwidth_bytes: 64000, p50_ms: 22, p95_ms: 80, p99_ms: 140 }];

describe("operations dashboard", () => {
  beforeEach(async () => {
    await initI18n("en");
    vi.spyOn(api, "getAnalyticsSummary").mockResolvedValue(summary);
    vi.spyOn(api, "getAnalyticsTimeseries").mockResolvedValue(rows);
    vi.spyOn(api, "hosts").mockResolvedValue([{ id: 7, name: "Main API", domain: "api.example.com", upstream_host: "127.0.0.1", upstream_port: 8080, tls_mode: "disabled", certificate_id: null, enabled: true }]);
    vi.spyOn(api, "clusterStatus").mockResolvedValue({ local_node_id: "node-1", cluster_enabled: false, total_peers: 0, healthy_peers: 0, peers: [], timestamp: "2026-08-16T10:00:00Z", raft_role: "standalone", raft_leader_id: null, raft_term: 0, raft_last_log_index: 0, raft_commit_index: 0, raft_quorum_available: true, raft_sync_state: "standalone" });
    vi.spyOn(api, "loadBalancer").mockResolvedValue({ generation: 3, pools: [{ name: "api-pool", algorithm: "round_robin", connect_timeout_seconds: 3, request_timeout_seconds: 30, passive_health: false, backends: [{ id: 0, address: "127.0.0.1:8080", health_check: "tcp", health_path: null, weight: 1, healthy: true, inflight: 2, response_time_ewma_ms: null, passive_failures: 0 }] }], routes: [], capabilities: { algorithms: ["round_robin"], health_checks: ["tcp"], passive_health: false, adaptive_weighting: false } });
    vi.spyOn(api, "certificates").mockResolvedValue([]);
    vi.spyOn(api, "wafConfig").mockResolvedValue({ mode: "block", updated_at: "2026-08-16T10:00:00Z" });
    vi.spyOn(api, "botConfig").mockResolvedValue({ mode: "challenge", threshold: 60, ttl_seconds: 900, updated_at: "2026-08-16T10:00:00Z" });
    vi.spyOn(api, "rateLimitConfig").mockResolvedValue({ enabled: true, action: "block", capacity: 100, refill_per_second: 1, key_scope: "proxy_host_ip", updated_at: "2026-08-16T10:00:00Z" });
    vi.spyOn(api, "plugins").mockResolvedValue([]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = "";
  });

  it("renders live traffic, upstream health, and telemetry boundaries", async () => {
    const root = createRoot(document.body);
    await act(async () => root.render(<I18nextProvider i18n={i18n}><ThemeProvider><Operations /></ThemeProvider></I18nextProvider>));
    await act(async () => { await new Promise((resolve) => setTimeout(resolve, 20)); });
    expect(document.body.textContent).toContain("Operations");
    expect(document.body.textContent).toContain("Requests / second");
    expect(document.body.textContent).toContain("api-pool");
    expect(document.body.textContent).toContain("Requests, bandwidth, status classes");
    expect(document.body.textContent).toContain("Open /metrics");
    root.unmount();
  });
});
