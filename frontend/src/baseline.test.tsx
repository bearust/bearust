// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BaselineSection } from "./App";
import { api, BaselineSnapshot } from "./api";

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return { ...actual, api: { ...actual.api, getBaseline: vi.fn() } };
});

describe("BaselineSection", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = "";
  });

  it("renders warming_up state correctly", async () => {
    const warmingUpSnapshot: BaselineSnapshot = {
      host_id: 1,
      status: "warming_up",
      window: "5m",
      sample_count: 2,
      metrics: {
        req_per_sec: 0.5,
        total_requests: 30,
        status_2xx: 30,
        status_3xx: 0,
        status_4xx: 0,
        status_5xx: 0,
        error_rate_percent: 0,
        p50_ms: 10,
        p95_ms: 20,
        p99_ms: 30,
        waf_blocks: 0,
        bot_blocks: 0,
        bot_challenges: 0,
        rate_limited: 0,
      },
      calculated_at: new Date().toISOString(),
    };

    vi.mocked(api.getBaseline).mockResolvedValue(warmingUpSnapshot);

    const root = createRoot(document.body);
    await act(async () => {
      root.render(
        <BaselineSection
          hosts={[
            {
              id: 1,
              name: "Main Host",
              domain: "example.com",
              upstream_host: "127.0.0.1",
              upstream_port: 8080,
              tls_mode: "off",
              certificate_id: null,
              enabled: true,
            },
          ]}
        />
      );
    });

    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });

    expect(document.body.textContent).toContain("Traffic Baseline");
    expect(document.body.textContent).toContain("Warming up");
    root.unmount();
  });
});
