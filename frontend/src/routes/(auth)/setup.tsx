import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { api } from "@/api";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export const Route = createFileRoute("/(auth)/setup")({
  component: SetupPage,
});

function sanitizeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function SetupPage() {
  const { t } = useTranslation();
  const navigate = Route.useNavigate();
  const [email, setEmail] = useState(""),
    [password, setPassword] = useState(""),
    [token, setToken] = useState(""),
    [error, setError] = useState("");

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4 py-8 text-foreground">
      <Card className="mx-auto w-full max-w-lg">
        <CardHeader>
          <CardTitle>{t("auth.setupTitle")}</CardTitle>
          <CardDescription>{t("auth.setupDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-4"
            onSubmit={async (e) => {
              e.preventDefault();
              try {
                await api.setup({ email, password, setup_token: token });
                // @ts-expect-error -- "/" becomes a valid route once the dashboard index route lands in a later task.
                void navigate({ to: "/" });
              } catch (x) {
                setError(sanitizeError(x));
              }
            }}
          >
            <div className="space-y-1.5">
              <Label htmlFor="setup-email">{t("common.email")}</Label>
              <Input id="setup-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="setup-password">{t("auth.passwordHint")}</Label>
              <Input id="setup-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="setup-token">{t("auth.setupToken")}</Label>
              <Input id="setup-token" value={token} onChange={(e) => setToken(e.target.value)} />
            </div>
            {error && (
              <p role="alert" className="text-sm text-destructive">
                {error}
              </p>
            )}
            <Button type="submit" className="w-full">
              {t("auth.createAccount")}
            </Button>
          </form>
        </CardContent>
      </Card>
    </main>
  );
}
