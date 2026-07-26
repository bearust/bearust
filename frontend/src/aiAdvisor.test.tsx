// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { api, type User } from "./api";
import { AiAdvisorSection } from "./ui";

const admin: User = { id: 1, email: "admin@example.com", role: "admin", disabled: false };
const viewer: User = { id: 2, email: "viewer@example.com", role: "viewer", disabled: false };

function render(user: User) {
  const element = document.createElement("div"); document.body.appendChild(element);
  const root = createRoot(element); act(() => { root.render(<AiAdvisorSection user={user} />); });
  return { element, root };
}

describe("AI advisor dashboard", () => {
  afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML = ""; });
  it("omits itself when advisor is disabled", async () => {
    vi.spyOn(api, "aiAdvisorStatus").mockResolvedValue({ enabled: false });
    const view = render(viewer); await act(async () => {});
    expect(view.element.textContent).toBe(""); view.root.unmount();
  });
  it("loads localized insights and only admins see approval controls", async () => {
    vi.spyOn(api, "aiAdvisorStatus").mockResolvedValue({ enabled: true });
    vi.spyOn(api, "listAiInsights").mockResolvedValue({ page: 1, page_size: 20, total: 1, items: [{ job_id: "00000000-0000-4000-8000-000000000001", workflow: "configuration_draft", status: "completed", redacted_input: {}, redacted_result: { workflow: "configuration_draft", summary: "Safe", action: "set_waf_mode", mode: "monitor-only", expected_config_hash: "a".repeat(64) }, error_code: null, provider_model: "model", config_version: "v1", config_hash: "a".repeat(64), created_at: "2026-01-01", updated_at: "2026-01-01", expires_at: "2099-01-01", draft_decision: null, draft_decided_at: null }] });
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
});
