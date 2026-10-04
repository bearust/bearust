// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, expect, it, vi } from "vitest";
import { I18nextProvider } from "react-i18next";
import { Analytics } from ".";
import { api } from "@/api";
import { i18n, initI18n } from "@/i18n";

vi.mock("@tanstack/react-router", () => ({ Link: ({ children }: { children: React.ReactNode }) => <span>{children}</span> }));
vi.mock("@/api", () => ({ api: {
  hosts: vi.fn(async () => [{ id: 7, name: "API", domain: "api.test", upstream_host: "localhost", upstream_port: 80, tls_mode: "none", certificate_id: null, enabled: true }]),
  getAnalyticsRetention: vi.fn(async () => ({ retention_minutes: 1440 })),
  getAnalyticsSummary: vi.fn(async () => null),
  getAnalyticsTimeseries: vi.fn(async () => []),
  getAnalyticsDimensions: vi.fn(async () => null),
  getBaseline: vi.fn(async () => null),
  getAnomalies: vi.fn(async () => []),
  getRecommendations: vi.fn(async () => []),
  getTuningPolicy: vi.fn(async () => null),
} }));

let root: Root;
afterEach(async () => { if (root) await act(async () => root.unmount()); vi.clearAllMocks(); document.body.innerHTML = ""; });

it("requests the selected analytics interval without changing summary filters", async () => {
  await initI18n("en");
  root = createRoot(document.body);
  await act(async () => root.render(<I18nextProvider i18n={i18n}><Analytics /></I18nextProvider>));
  const select = document.querySelector<HTMLSelectElement>('select[aria-label="Interval"]');
  expect(select).not.toBeNull();
  expect(select!.value).toBe("minute");
  for (const interval of ["hour", "day"]) {
    await act(async () => { select!.value = interval; select!.dispatchEvent(new Event("change", { bubbles: true })); });
    expect(api.getAnalyticsTimeseries).toHaveBeenLastCalledWith(expect.objectContaining({ proxy_host_id: 7, interval }));
    expect(api.getAnalyticsSummary).toHaveBeenLastCalledWith(expect.not.objectContaining({ interval: expect.anything() }));
  }
});

it("ignores a stale interval failure after a newer selection succeeds", async () => {
  await initI18n("en");
  root = createRoot(document.body);
  await act(async () => root.render(<I18nextProvider i18n={i18n}><Analytics /></I18nextProvider>));
  let rejectOld!: (error: Error) => void;
  vi.mocked(api.getAnalyticsTimeseries).mockImplementationOnce(() => new Promise((_resolve, reject) => { rejectOld = reject; }));
  const select = document.querySelector<HTMLSelectElement>('select[aria-label="Interval"]')!;
  await act(async () => { select.value = "hour"; select.dispatchEvent(new Event("change", { bubbles: true })); });
  await act(async () => { select.value = "day"; select.dispatchEvent(new Event("change", { bubbles: true })); });
  await act(async () => rejectOld(new Error("stale interval failure")));
  expect(select.value).toBe("day");
  expect(document.querySelector('[role="alert"]')).toBeNull();
});

it("clears old telemetry when a new interval request fails", async () => {
  await initI18n("en");
  vi.mocked(api.getAnalyticsTimeseries).mockResolvedValue([{ timestamp: "2026-10-01T00:01:00Z", proxy_host_id: 7, requests: 987654, status_2xx: 987654, status_3xx: 0, status_4xx: 0, status_5xx: 0, waf_blocks: 0, bot_blocks: 0, bot_challenges: 0, rate_limited: 0, bandwidth_bytes: 1, p50_ms: 10, p95_ms: 10, p99_ms: 10 }]);
  root = createRoot(document.body);
  await act(async () => root.render(<I18nextProvider i18n={i18n}><Analytics /></I18nextProvider>));
  expect(document.querySelectorAll("tbody tr").length).toBe(1);
  vi.mocked(api.getAnalyticsTimeseries).mockRejectedValueOnce(new Error("interval failed"));
  const select = document.querySelector<HTMLSelectElement>('select[aria-label="Interval"]')!;
  await act(async () => { select.value = "day"; select.dispatchEvent(new Event("change", { bubbles: true })); });
  expect(document.querySelector('[role="alert"]')).not.toBeNull();
  expect(document.querySelectorAll("tbody tr").length).toBe(0);
});
