// @vitest-environment jsdom
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import React from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { api, type AdvisorInsight, type AdvisorJobPage, type User } from "./api";
import { AiAdvisorSection } from "./aiAdvisor";
import { initI18n } from "./i18n";

const admin: User = { id: 1, email: "admin@example.com", role: "admin", disabled: false };
const viewer: User = { id: 2, email: "viewer@example.com", role: "viewer", disabled: false };

const draft: AdvisorInsight = {
  job_id: "00000000-0000-4000-8000-000000000001",
  workflow: "configuration_draft",
  status: "completed",
  redacted_input: {},
  redacted_result: {
    workflow: "configuration_draft",
    summary: "Safe",
    action: "set_waf_mode",
    mode: "monitor-only",
    expected_config_hash: "a".repeat(64),
  },
  error_code: null,
  provider_model: "model",
  config_version: "v1",
  config_hash: "a".repeat(64),
  created_at: "2026-01-01",
  updated_at: "2026-01-01",
  expires_at: "2099-01-01",
  draft_decision: null,
  draft_decided_at: null,
};

const page = (items: AdvisorInsight[]): AdvisorJobPage => ({
  page: 1,
  page_size: 20,
  total: items.length,
  items,
});

beforeAll(async () => {
  (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;
  await initI18n("en");
});

afterAll(() => {
  delete (globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT;
});

function render(user: User) {
  const element = document.createElement("div"); document.body.appendChild(element);
  const root = createRoot(element); act(() => { root.render(<AiAdvisorSection user={user} />); });
  return { element, root };
}

describe("AI advisor dashboard", () => {
  afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); document.body.innerHTML = ""; });
  it("omits itself when advisor is disabled", async () => {
    vi.spyOn(api, "aiAdvisorStatus").mockResolvedValue({ enabled: false });
    const view = render(viewer); await act(async () => {});
    expect(view.element.textContent).toBe(""); view.root.unmount();
  });
  it("loads localized insights and only admins see approval controls", async () => {
    vi.spyOn(api, "aiAdvisorStatus").mockResolvedValue({ enabled: true });
    vi.spyOn(api, "listAiInsights").mockResolvedValue(page([draft]));
    const view = render(admin); await act(async () => {});
    expect(view.element.textContent).toContain("Safe");
    expect(view.element.querySelectorAll("button").length).toBeGreaterThan(0);
    view.root.unmount();
  });
  it("hides approval controls for viewers", async () => {
    vi.spyOn(api, "aiAdvisorStatus").mockResolvedValue({ enabled: true });
    vi.spyOn(api, "listAiInsights").mockResolvedValue({ page: 1, page_size: 20, total: 0, items: [] });
    const view = render(viewer); await act(async () => {});
    expect(view.element.textContent).not.toContain("advisor.approve");
    expect(view.element.textContent).not.toContain("advisor.reject"); view.root.unmount();
  });

  it("keeps polling through the server timeout when a realtime completion event is missed", async () => {
    vi.useFakeTimers();
    const startedAt = Date.now();
    vi.spyOn(api, "aiAdvisorStatus").mockResolvedValue({ enabled: true });
    vi.spyOn(api, "listAiInsights").mockImplementation(async () => page([{
      ...draft,
      workflow: "incident_explanation",
      status: Date.now() - startedAt >= 300_000 ? "completed" : "running",
      redacted_result: Date.now() - startedAt >= 300_000 ? {
        workflow: "incident_explanation",
        summary: "Recovered without realtime",
        severity: "info",
        signals: [],
        reason_ids: [],
        score: 80,
      } : null,
    }]));

    const view = render(viewer);
    await act(async () => {});
    expect(view.element.textContent).toContain("Running");

    for (let poll = 0; poll < 300; poll += 1) {
      await act(async () => { await vi.advanceTimersByTimeAsync(1_000); });
    }
    expect(view.element.textContent).toContain("Recovered without realtime");
    const callsAtCompletion = vi.mocked(api.listAiInsights).mock.calls.length;

    await act(async () => { await vi.advanceTimersByTimeAsync(5_000); });
    expect(vi.mocked(api.listAiInsights)).toHaveBeenCalledTimes(callsAtCompletion);
    view.root.unmount();
  });

  it.each([
    ["approve", "advisor_stale_draft", "This draft is stale; refresh insights and try again."],
    ["reject", "advisor_expired", "This draft has expired."],
  ] as const)("keeps a draft non-actionable after an %s decision returns %s", async (decision, code, message) => {
    vi.spyOn(api, "aiAdvisorStatus").mockResolvedValue({ enabled: true });
    vi.spyOn(api, "listAiInsights").mockResolvedValue(page([draft]));
    vi.spyOn(api, decision === "approve" ? "approveAiDraft" : "rejectAiDraft")
      .mockRejectedValue(Object.assign(new Error("unsafe provider detail"), { code }));

    const view = render(admin);
    await act(async () => {});
    const label = decision === "approve" ? "Approve draft" : "Reject draft";
    const button = [...view.element.querySelectorAll("button")].find((candidate) => candidate.textContent === label);
    expect(button).toBeDefined();

    await act(async () => { button!.dispatchEvent(new MouseEvent("click", { bubbles: true })); });
    expect(view.element.textContent).toContain(message);
    expect(view.element.textContent).not.toContain("Approve draft");
    expect(view.element.textContent).not.toContain("Reject draft");
    expect(view.element.textContent).not.toContain("unsafe provider detail");

    const refresh = [...view.element.querySelectorAll("button")].find((candidate) => candidate.textContent === "Refresh");
    await act(async () => { refresh!.dispatchEvent(new MouseEvent("click", { bubbles: true })); });
    expect(view.element.textContent).not.toContain("Approve draft");
    expect(view.element.textContent).not.toContain("Reject draft");
    view.root.unmount();
  });
});
