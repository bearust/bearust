import { useEffect, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { api } from "@/api";
import type { BotChallenge } from "@/api";
import { serverChallengeFingerprint, solveBotChallenge } from "@/features/bot-challenge/solve";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";

type BotChallengeSearch = { fingerprint_prefix?: string };

export const Route = createFileRoute("/bot-challenge")({
  component: BotChallengePage,
  validateSearch: (search: Record<string, unknown>): BotChallengeSearch => ({
    fingerprint_prefix: typeof search.fingerprint_prefix === "string" ? search.fingerprint_prefix : undefined,
  }),
});

function BotChallengePage() {
  const { t } = useTranslation();
  const { fingerprint_prefix } = Route.useSearch();
  useEffect(() => {
    if (fingerprint_prefix && /^[a-f0-9]{16}$/.test(fingerprint_prefix)) {
      sessionStorage.setItem("bearust-bot-fingerprint", fingerprint_prefix);
    }
  }, [fingerprint_prefix]);

  const fingerprint = serverChallengeFingerprint();
  const [challenge, setChallenge] = useState<BotChallenge | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [complete, setComplete] = useState(false);

  useEffect(() => {
    setError("");
    if (!fingerprint) {
      setError(t("errors.challengeContext"));
      return;
    }
    setBusy(true);
    api
      .botChallenge(fingerprint)
      .then(setChallenge)
      .catch(() => setError(t("errors.challengeUnavailable")))
      .finally(() => setBusy(false));
  }, [fingerprint, t]);

  const verify = async () => {
    if (!challenge) return;
    setBusy(true);
    setError("");
    try {
      const solution = await solveBotChallenge(challenge, fingerprint);
      await api.verifyBotChallenge({ token: challenge.token, fingerprint, solution });
      setComplete(true);
    } catch {
      setError(t("errors.challengeVerification"));
    } finally {
      setBusy(false);
    }
  };

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4 py-8 text-foreground">
      <Card className="mx-auto w-full max-w-lg">
        <CardHeader>
          <CardTitle>{t("bot.quickCheck")}</CardTitle>
          <CardDescription>{t("bot.quickCheckDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          {error && <p role="alert" className="mb-4 text-sm text-destructive">{error}</p>}
          {complete ? (
            <p className="text-sm text-primary">{t("bot.verificationComplete")}</p>
          ) : (
            <Button disabled={busy || !challenge} onClick={() => void verify()}>
              {busy ? t("bot.verifying") : t("bot.verifyBrowser")}
            </Button>
          )}
        </CardContent>
      </Card>
    </main>
  );
}
