import { useEffect, useState } from "react";
import { createFileRoute } from "@tanstack/react-router";
import { useTranslation } from "react-i18next";
import { api, type PublicSsoProvider } from "@/api";
import { sanitizeError } from "@/lib/errors";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardFooter, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { DEMO_MODE, DEMO_USER } from "@/lib/demo";
import { useAuthStore } from "@/stores/auth-store";
import { AuthLayout } from "@/features/auth/auth-layout";

export const Route = createFileRoute("/(auth)/login")({
  component: LoginPage,
});

function LoginPage() {
  const { t } = useTranslation();
  const navigate = Route.useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(() => {
    const reason = new URLSearchParams(window.location.search).get("sso_error");
    return reason ? t("auth.ssoError", { reason: reason.replace(/[^a-z_]/g, "") }) : "";
  });
  const [providers, setProviders] = useState<PublicSsoProvider[]>([]);
  useEffect(() => {
    if (DEMO_MODE) return;
    void api.ssoProviders().then(setProviders).catch(() => setProviders([]));
  }, []);

  return (
    <AuthLayout>
      <Card className="gap-5">
        <CardHeader>
          <CardTitle className="text-lg tracking-tight">{t("auth.loginTitle")}</CardTitle>
            <CardDescription>{t("shell.loginDescription")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form
            className="space-y-4"
            onSubmit={async (event) => {
              event.preventDefault();
              try {
                if (DEMO_MODE) {
                  useAuthStore.getState().setUser(DEMO_USER);
                  void navigate({ to: "/" });
                  return;
                }
                const user = await api.login({ email, password });
                useAuthStore.getState().setUser(user);
                void navigate({ to: "/" });
              } catch (exception) {
                setError(sanitizeError(exception));
              }
            }}
          >
            <div className="space-y-2">
              <Label htmlFor="login-email">{t("common.email")}</Label>
              <Input id="login-email" type="email" value={email} onChange={(event) => setEmail(event.target.value)} />
            </div>
            <div className="space-y-2">
              <div className="flex items-center justify-between gap-4">
                <Label htmlFor="login-password">{t("common.password")}</Label>
                <span className="text-xs text-muted-foreground">{DEMO_MODE ? t("shell.demoAccess") : t("shell.useControlPlaneAccount")}</span>
              </div>
              <Input id="login-password" type="password" value={password} onChange={(event) => setPassword(event.target.value)} />
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
          {providers.length > 0 && (
            <div className="mt-5 space-y-3">
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span className="h-px flex-1 bg-border" />
                {t("auth.ssoDivider")}
                <span className="h-px flex-1 bg-border" />
              </div>
              {providers.map((provider) => (
                <Button key={provider.slug} variant="outline" className="w-full" asChild>
                  <a href={api.ssoStartUrl(provider.slug)}>{t("auth.ssoContinue", { name: provider.name })}</a>
                </Button>
              ))}
            </div>
          )}
        </CardContent>
        <CardFooter className="border-t pt-5">
          <p className="w-full text-center text-xs text-muted-foreground">
            {t("shell.termsNotice")}
          </p>
        </CardFooter>
      </Card>
    </AuthLayout>
  );
}
