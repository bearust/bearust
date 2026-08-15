import type { BotChallenge } from "@/api";
import { i18n } from "@/i18n";

/** The proxy fingerprint is keyed and must be supplied by the server. Never
 * substitute a browser/user-agent value: it cannot match the data-plane hash. */
export const serverChallengeFingerprint = () => {
  if (typeof sessionStorage === "undefined") return "";
  const value = sessionStorage.getItem("bearust-bot-fingerprint") ?? "";
  return /^[a-f0-9]{16}$/.test(value) ? value : "";
};

export async function solveBotChallenge(
  challenge: BotChallenge,
  fingerprint: string,
): Promise<string> {
  if (typeof crypto === "undefined" || !crypto.subtle)
    throw new Error(i18n.t("errors.challengeUnavailable"));
  const encoder = new TextEncoder();
  const prefix = "0".repeat(Math.min(challenge.difficulty, 4));
  for (let nonce = 0; nonce < 1_000_000; nonce += 1) {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(`${challenge.token.split(".")[1] ?? ""}${nonce}`),
    );
    const hex = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    if (hex.startsWith(prefix)) return String(nonce);
  }
  throw new Error(i18n.t("errors.challengeVerification"));
}
