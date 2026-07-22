// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AnomalySection } from "./App";
import { api, AnomalyRecord, User } from "./api";

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return { ...actual, api: { ...actual.api, getAnomalies: vi.fn(), ackAnomaly: vi.fn() } };
});

const adminUser: User = { id: 1, email: "admin@example.com", role: "admin", disabled: false };

describe("AnomalySection", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = "";
  });

  it("renders anomaly records and acknowledge button", async () => {
    const anomalyRecord: AnomalyRecord = {
      id: 42,
      host_id: 1,
      rule: "request_rate",
      severity: "critical",
      score: 8.5,
      summary: "Request rate spike of 15.0 req/s vs baseline 1.0 req/s",
      observed_at: new Date().toISOString(),
      acknowledged: false,
    };

    vi.mocked(api.getAnomalies).mockResolvedValue([anomalyRecord]);
    vi.mocked(api.ackAnomaly).mockResolvedValue({ ...anomalyRecord, acknowledged: true });

    const root = createRoot(document.body);
    await act(async () => {
      root.render(
        <AnomalySection
          user={adminUser}
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

    expect(document.body.textContent).toContain("Anomaly Detection");
    expect(document.body.textContent).toContain("Request rate spike");
    expect(document.body.textContent).toContain("Acknowledge");

    root.unmount();
  });
});
