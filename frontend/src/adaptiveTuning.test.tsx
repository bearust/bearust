// @vitest-environment jsdom
import React, { act } from "react";
import { createRoot } from "react-dom/client";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AdaptiveTuningSection } from "./App";
import { api, PolicyRecommendation, TuningPolicy, User } from "./api";

vi.mock("./api", async () => {
  const actual = await vi.importActual<typeof import("./api")>("./api");
  return {
    ...actual,
    api: {
      ...actual.api,
      getTuningPolicy: vi.fn(),
      updateTuningPolicy: vi.fn(),
      getRecommendations: vi.fn(),
      applyRecommendation: vi.fn(),
      rollbackRecommendation: vi.fn(),
      emergencyDisableTuning: vi.fn(),
    },
  };
});

const adminUser: User = { id: 1, email: "admin@example.com", role: "admin", disabled: false };

describe("AdaptiveTuningSection", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    document.body.innerHTML = "";
  });

  it("renders policy controls and recommendations", async () => {
    const policy: TuningPolicy = {
      mode: "monitor",
      max_delta_percent: 50,
      cooldown_seconds: 300,
      min_confidence: 0.8,
    };

    const recommendation: PolicyRecommendation = {
      id: 1,
      host_id: 1,
      patch: { capacity: 50 },
      confidence: 0.9,
      reason: "Recommendation for spike on host 1",
      created_at: new Date().toISOString(),
      applied: false,
    };

    vi.mocked(api.getTuningPolicy).mockResolvedValue(policy);
    vi.mocked(api.getRecommendations).mockResolvedValue([recommendation]);

    const root = createRoot(document.body);
    await act(async () => {
      root.render(
        <AdaptiveTuningSection
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

    expect(document.body.textContent).toContain("Adaptive Tuning");
    expect(document.body.textContent).toContain("Monitor-only (Default)");
    expect(document.body.textContent).toContain("Recommendation for spike on host 1");

    root.unmount();
  });
});
