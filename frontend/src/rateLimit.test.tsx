// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { api, User, RateLimitConfig } from "./api";
import { RateLimitSection } from "./App";

const admin: User = { id: 1, email: "admin@example.com", role: "admin", disabled: false };
const viewer: User = { id: 2, email: "viewer@example.com", role: "viewer", disabled: false };
const config: RateLimitConfig = { enabled: false, action: "monitor", capacity: 100, refill_per_second: 10, key_scope: "proxy_host_ip", updated_at: "now" };

function render(user: User) { const element = document.createElement("div"); document.body.appendChild(element); const root = createRoot(element); act(() => { root.render(<RateLimitSection user={user} />); }); return { element, root }; }
describe("rate-limit dashboard", () => {
  afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML = ""; });
  it("shows safe defaults and admin controls", async () => { vi.spyOn(api, "rateLimitConfig").mockResolvedValue(config); const view = render(admin); await act(async () => {}); expect(view.element.textContent).toContain("Monitor-only"); expect(view.element.querySelector('button')?.textContent).toContain("Save policy"); view.root.unmount(); });
  it("keeps viewer controls read-only", async () => { vi.spyOn(api, "rateLimitConfig").mockResolvedValue(config); const view = render(viewer); await act(async () => {}); expect(view.element.querySelector('button')).toBeNull(); expect((view.element.querySelector('input[type="checkbox"]') as HTMLInputElement).disabled).toBe(true); view.root.unmount(); });
});
