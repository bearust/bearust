import { useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { api } from "@/api";
import { sanitizeError } from "@/App";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

export const Route = createFileRoute("/(auth)/login")({
  component: LoginPage,
});

function LoginPage() {
  const { t } = useTranslation();
  const navigate = Route.useNavigate();
  const [email, setEmail] = useState(""),
    [password, setPassword] = useState(""),
    [error, setError] = useState("");

  return (
    <main className="flex min-h-screen items-center justify-center bg-background px-4 py-8 text-foreground">
      <div className="w-full max-w-md">
        <div className="mb-6 flex items-center justify-center gap-2.5">
          <span aria-hidden="true" className="inline-block h-3 w-3 rounded-full bg-primary" />
          <span className="font-display text-lg font-bold tracking-tight">{t("dashboard.brand")}</span>
        </div>
        <Card>
          <CardHeader>
            <CardTitle>{t("auth.loginTitle")}</CardTitle>
          </CardHeader>
          <CardContent>
            <form
              className="space-y-4"
              onSubmit={async (e) => {
                e.preventDefault();
                try {
                  await api.login({ email, password });
                  // @ts-expect-error -- "/" becomes a valid route once the dashboard index route lands in a later task.
                  void navigate({ to: "/" });
                } catch (x) {
                  setError(sanitizeError(x));
                }
              }}
            >
              <div className="space-y-1.5">
                <Label htmlFor="login-email">{t("common.email")}</Label>
                <Input id="login-email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} />
              </div>
              <div className="space-y-1.5">
                <Label htmlFor="login-password">{t("common.password")}</Label>
                <Input id="login-password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} />
              </div>
              {error && (
                <p role="alert" className="text-sm text-destructive">
                  {error}
                </p>
              )}
              <Button type="submit" className="w-full">
                {t("auth.signIn")}
              </Button>
            </form>
          </CardContent>
        </Card>
      </div>
    </main>
  );
}
