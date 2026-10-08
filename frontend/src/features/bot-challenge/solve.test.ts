// @vitest-environment jsdom
import { describe, expect, it, beforeEach } from "vitest";
import { serverChallengeFingerprint, solveBotChallenge } from "./solve";
import type { BotChallenge } from "@/api";

describe("serverChallengeFingerprint", () => {
  beforeEach(() => sessionStorage.clear());

  it("returns empty string when nothing is stored", () => {
    expect(serverChallengeFingerprint()).toBe("");
  });

  it("returns the stored value when it matches the 16-hex-char shape", () => {
    sessionStorage.setItem("bearust-bot-fingerprint", "0123456789abcdef");
    expect(serverChallengeFingerprint()).toBe("0123456789abcdef");
  });

  it("rejects a malformed stored value", () => {
    sessionStorage.setItem("bearust-bot-fingerprint", "not-hex");
    expect(serverChallengeFingerprint()).toBe("");
  });
});

describe("solveBotChallenge", () => {
  it("finds a nonce whose SHA-256 digest starts with the required zero prefix", async () => {
    const challenge: BotChallenge = {
      token: "header.payload.signature",
      difficulty: 1,
      expires_at: Date.now() + 60_000,
      fingerprint_prefix: "abcd",
    };
    const solution = await solveBotChallenge(challenge, "0123456789abcdef");
    const encoder = new TextEncoder();
    const digest = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(`${challenge.token.split(".")[1] ?? ""}${solution}`),
    );
    const hex = Array.from(new Uint8Array(digest), (b) => b.toString(16).padStart(2, "0")).join("");
    expect(hex.startsWith("0")).toBe(true);
  });
});
