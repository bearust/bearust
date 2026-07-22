// @vitest-environment jsdom
import React from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AnalyticsSection } from "./App";
import { api } from "./api";

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return { ...actual, api: { ...actual.api, getAnalyticsSummary: vi.fn(), getAnalyticsTimeseries: vi.fn() } };
});

const summary = { requests: 4, status_2xx: 3, status_3xx: 0, status_4xx: 1, status_5xx: 0, waf_blocks: 1, bot_blocks: 0, bot_challenges: 0, rate_limited: 0, p50_ms: 12, p95_ms: 40, p99_ms: 50 };
const row = { timestamp: "2026-07-22T10:00:00Z", proxy_host_id: 1, requests: 4, status_2xx: 3, status_3xx: 0, status_4xx: 1, status_5xx: 0, waf_blocks: 1, bot_blocks: 0, bot_challenges: 0, rate_limited: 0, p50_ms: 12, p95_ms: 40, p99_ms: 50 };

describe("analytics dashboard", () => {
  afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML = ""; });
  it("renders loading then summary cards and table", async () => {
    vi.mocked(api.getAnalyticsSummary).mockResolvedValue(summary);
    vi.mocked(api.getAnalyticsTimeseries).mockResolvedValue([row]);
    const root = createRoot(document.body);
    await act(async () => root.render(<AnalyticsSection hosts={[{ id: 1, name: "Main", domain: "example.com", upstream_host: "127.0.0.1", upstream_port: 80, tls_mode: "disabled", certificate_id: null, enabled: true }]} />));
    expect(document.body.textContent).toContain("Loading analytics");
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 200)); });
    expect(document.body.textContent).toContain("Requests");
    expect(document.body.textContent).toContain("Latency percentiles");
    expect(document.body.textContent).toContain("p50");
    expect(document.body.textContent).toContain("p99");
    expect(document.body.textContent).toContain("WAF blocks");
    expect(document.body.textContent).toContain("Bot challenges");
    expect(document.body.textContent).toContain("Rate limited");
    expect(document.querySelectorAll('[role="progressbar"]')).toHaveLength(3);
    expect(document.querySelector('[aria-label="p95 latency"]')?.getAttribute("aria-valuenow")).toBe("40");
    expect(document.body.textContent).toContain("Analytics by minute");
    root.unmount();
  });
  it("renders empty and error states", async () => {
    vi.mocked(api.getAnalyticsSummary).mockResolvedValue({ ...summary, requests: 0 });
    vi.mocked(api.getAnalyticsTimeseries).mockResolvedValue([]);
    const root = createRoot(document.body);
    await act(async () => root.render(<AnalyticsSection hosts={[]} />));
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 200)); });
    expect(document.body.textContent).toContain("No analytics data");
    vi.mocked(api.getAnalyticsSummary).mockRejectedValue(new Error("offline"));
    await act(async () => root.render(<AnalyticsSection hosts={[]} refreshToken={1} />));
    await act(async () => { await new Promise(resolve => setTimeout(resolve, 200)); });
    expect(document.body.textContent).toContain("offline");
    root.unmount();
  });
});
