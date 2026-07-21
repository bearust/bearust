// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { api, User, WafConfig, WafRule } from "./api";
import { WafSection } from "./App";

const admin: User = { id: 1, email: "admin@example.com", role: "admin", disabled: false };
const viewer: User = { id: 2, email: "viewer@example.com", role: "viewer", disabled: false };
const config: WafConfig = { mode: "monitor-only", updated_at: "now" };
const rule: WafRule = { id: 4, name: "custom", source: "custom", category: "custom", severity: "medium", enabled: true, action: "inherit", matcher_json: '{"field":"query","pattern":"evil"}', created_at: "now", updated_at: "now" };

function render(user: User) {
  const element = document.createElement("div"); document.body.appendChild(element);
  const root = createRoot(element); act(() => { root.render(<WafSection user={user} />); });
  return { element, root };
}

describe("WAF dashboard", () => {
  afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML = ""; });
  it("shows mode and rules with admin controls", async () => {
    vi.spyOn(api, "wafConfig").mockResolvedValue(config); vi.spyOn(api, "wafRules").mockResolvedValue([rule]);
    const view = render(admin); await act(async () => {});
    expect(view.element.textContent).toContain("Monitor-only"); expect(view.element.textContent).toContain("custom");
    expect(view.element.querySelector("button")?.textContent).toContain("Block");
    view.root.unmount();
  });
  it("keeps non-admin users read-only", async () => {
    vi.spyOn(api, "wafConfig").mockResolvedValue(config); vi.spyOn(api, "wafRules").mockResolvedValue([rule]);
    const view = render(viewer); await act(async () => {});
    expect(view.element.textContent).toContain("Monitor-only"); expect(view.element.querySelector("button")).toBeNull();
    view.root.unmount();
  });
});

