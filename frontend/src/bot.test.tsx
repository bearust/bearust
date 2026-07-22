// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from "vitest";
import React from "react";
import { act } from "react";
import { createRoot } from "react-dom/client";
import { api, User } from "./api";
import { BotChallengePage, BotProtectionSection } from "./App";

const admin: User = { id: 1, email: "admin@example.com", role: "admin", disabled: false };
const config = { mode: "monitor" as const, threshold: 50, ttl_seconds: 300, updated_at: "now" };
const crawler = { id: 1, category: "trusted_crawler" as const, weight: 0, trusted_user_agent: "Googlebot", trusted_domain: "google.com", enabled: true };

function render(element: React.ReactElement) { const container = document.createElement("div"); document.body.appendChild(container); const root = createRoot(container); act(() => { root.render(element); }); return { container, root }; }

describe("bot protection dashboard", () => {
  afterEach(() => { vi.restoreAllMocks(); document.body.innerHTML = ""; });
  it("shows monitor-only by default and trusted crawler", async () => {
    vi.spyOn(api, "botConfig").mockResolvedValue(config); vi.spyOn(api, "trustedCrawlers").mockResolvedValue([crawler]);
    const view = render(<BotProtectionSection user={admin} />); await act(async () => {});
    expect(view.container.textContent).toContain("Monitor-only"); expect(view.container.textContent).toContain("Googlebot");
    view.root.unmount();
  });
  it("saves policy and validates crawler fields", async () => {
    vi.spyOn(api, "botConfig").mockResolvedValue(config); vi.spyOn(api, "trustedCrawlers").mockResolvedValue([]);
    const update = vi.spyOn(api, "updateBotConfig").mockResolvedValue({ ...config, mode: "challenge" });
    const view = render(<BotProtectionSection user={admin} />); await act(async () => {});
    const select = view.container.querySelector("select") as HTMLSelectElement; const inputs = view.container.querySelectorAll("input");
    await act(async () => { select.value = "challenge"; select.dispatchEvent(new Event("change", { bubbles: true })); inputs[2].value = "Googlebot"; inputs[2].dispatchEvent(new Event("input", { bubbles: true })); inputs[3].value = "google.com"; inputs[3].dispatchEvent(new Event("input", { bubbles: true })); });
    const save = Array.from(view.container.querySelectorAll("button")).find((button) => button.textContent === "Save policy") as HTMLButtonElement;
    await act(async () => { save.click(); });
    expect(update).toHaveBeenCalledWith({ mode: "challenge", threshold: 50, ttl_seconds: 300 });
    view.root.unmount();
  });
  it("renders challenge completion and generic errors", async () => {
    vi.spyOn(api, "botChallenge").mockResolvedValue({ token: "1.nonce.prefix.1.999.sig", difficulty: 1, expires_at: 999, fingerprint_prefix: "Mozilla" });
    vi.spyOn(api, "verifyBotChallenge").mockResolvedValue({ ok: true });
    vi.spyOn(crypto.subtle, "digest").mockResolvedValue(new Uint8Array(32).buffer);
    const view = render(<BotChallengePage />); await act(async () => {});
    const verify = Array.from(view.container.querySelectorAll("button")).find((button) => button.textContent?.includes("Verify browser")) as HTMLButtonElement;
    await act(async () => { verify.click(); });
    expect(view.container.textContent).toContain("Verification complete");
    view.root.unmount();
    vi.restoreAllMocks();
    vi.spyOn(api, "botChallenge").mockRejectedValue(new Error("down"));
    const failed = render(<BotChallengePage />); await act(async () => {});
    expect(failed.container.textContent).toContain("Challenge unavailable"); failed.root.unmount();
  });
});
