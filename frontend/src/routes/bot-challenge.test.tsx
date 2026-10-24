// @vitest-environment jsdom
import { describe, expect, it, vi, afterEach } from "vitest";
import { act } from "react";
import { api } from "@/api";
import type { BotChallenge } from "@/api";
import { renderRoute } from "@/test-utils/render-route";
import { Route as BotChallengeRoute } from "./bot-challenge";

const FINGERPRINT = "0123456789abcdef";

const challenge: BotChallenge = {
  token: "header.payload.signature",
  difficulty: 0,
  expires_at: Date.now() + 60_000,
  fingerprint_prefix: FINGERPRINT.slice(0, 8),
};

describe("Bot Challenge route", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    sessionStorage.clear();
    document.body.innerHTML = "";
  });

  it("does not get stuck showing the context-unavailable error once the challenge loads via fingerprint_prefix", async () => {
    sessionStorage.clear();
    vi.spyOn(api, "botChallenge").mockResolvedValue(challenge);
    const { element } = await renderRoute(
      [BotChallengeRoute],
      `/bot-challenge?fingerprint_prefix=${FINGERPRINT}`,
    );
    // Let the sessionStorage-write effect commit, the fingerprint-dependent
    // fetch effect re-run with the correct value, and the mocked
    // api.botChallenge promise resolve.
    await act(async () => {
      await new Promise((resolve) => setTimeout(resolve, 50));
    });
    expect(api.botChallenge).toHaveBeenCalledWith(FINGERPRINT);
    expect(element.textContent).not.toContain("Challenge context unavailable");
    const button = element.querySelector("button") as HTMLButtonElement;
    expect(button.disabled).toBe(false);
  });

  it("renders the configured CAPTCHA and verifies with its response token", async () => {
    vi.spyOn(api, "botChallenge").mockResolvedValue({ ...challenge, captcha: { provider: "turnstile", site_key: "site-123" } });
    const verify = vi.spyOn(api, "verifyBotChallenge").mockResolvedValue({ ok: true });
    const render = vi.fn((_element: HTMLElement, options: Record<string, unknown>) => (options.callback as (token: string) => void)("captcha-token"));
    (window as unknown as { turnstile: unknown }).turnstile = { render };
    try {
      const { element } = await renderRoute([BotChallengeRoute], `/bot-challenge?fingerprint_prefix=${FINGERPRINT}`);
      await act(async () => {
        await new Promise((resolve) => setTimeout(resolve, 100));
      });
      expect(render.mock.calls[0][1]).toMatchObject({ sitekey: "site-123" });
      expect(verify).toHaveBeenCalledWith({ token: challenge.token, fingerprint: FINGERPRINT, captcha_response: "captcha-token" });
      expect(element.textContent).toContain("Verification complete");
    } finally {
      delete (window as unknown as { turnstile?: unknown }).turnstile;
    }
  });
});
