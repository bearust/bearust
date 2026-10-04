import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Link } from "@tanstack/react-router";
import {
  Bell,
  Gauge,
  LockKeyhole,
  Palette,
  Save,
  UserRound,
} from "lucide-react";
import { api } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { useAuthStore } from "@/stores/auth-store";
import { readNotificationPreferences, saveNotificationPreferences } from "@/lib/notification-preferences";
import { normalizeLocale, useLocalePreference, type Locale } from "@/i18n";
import { useTheme, type ThemeMode } from "@/theme";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";

export function Settings() {
  const { t } = useTranslation();
  const user = useAuthStore((state) => state.user);
  const { mode, resolved, setMode } = useTheme();
  const { locale, setLocale } = useLocalePreference();
  const [notifications, setNotifications] = useState(() => readNotificationPreferences(user?.id));
  const [notificationError, setNotificationError] = useState(false);
  const [savingLocale, setSavingLocale] = useState(false);
  const [localeMessage, setLocaleMessage] = useState("");
  const [retention, setRetention] = useState("1440");
  const [retentionMessage, setRetentionMessage] = useState("");
  const [savingRetention, setSavingRetention] = useState(false);

  useEffect(() => {
    setNotifications(readNotificationPreferences(user?.id));
    setNotificationError(false);
  }, [user?.id]);

  const saveNotifications = () => {
    const saved = saveNotificationPreferences(user?.id, notifications);
    setNotificationError(!saved);
    if (saved) toast.success(t("settings.notificationSaved"));
  };

  useEffect(() => {
    if (DEMO_MODE || user?.role !== "admin") return;
    void api
      .getAnalyticsRetention()
      .then((config) => setRetention(String(config.retention_minutes)))
      .catch(() => setRetentionMessage(t("settings.retentionLoadError")));
  }, [user?.role]);

  const saveLocale = async (next: Locale) => {
    setSavingLocale(true);
    setLocaleMessage("");
    try {
      const saved = await setLocale(next);
      if (saved && !DEMO_MODE && user)
        useAuthStore.getState().setUser({ ...user, preferred_locale: next });
      setLocaleMessage(saved ? "settings.localeSaved" : "settings.localeLocalOnly");
    } catch {
      setLocaleMessage("settings.localeLocalOnly");
    } finally {
      setSavingLocale(false);
    }
  };

  const saveRetention = async (event: FormEvent) => {
    event.preventDefault();
    const minutes = Number(retention);
    if (!Number.isInteger(minutes) || minutes < 60 || minutes > 10_080) {
      setRetentionMessage(t("settings.retentionInvalid"));
      return;
    }
    setSavingRetention(true);
    setRetentionMessage("");
    try {
      if (!DEMO_MODE) {
        const config = await api.updateAnalyticsRetention(minutes);
        setRetention(String(config.retention_minutes));
      }
      setRetentionMessage(t("settings.retentionSaved"));
    } catch {
      setRetentionMessage(t("settings.retentionSaveError"));
    } finally {
      setSavingRetention(false);
    }
  };

  return (
    <Main>
      <PageHeader
        title={t("settings.title")}
        description={t("settings.description")}
        action={
          <Badge variant="outline" className="gap-1.5 rounded-full">
            <span
              className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : "bg-emerald-500"}`}
            />
            {DEMO_MODE
              ? t("settings.localDemo")
              : t("settings.accountSettings")}
          </Badge>
        }
      />
      <Tabs defaultValue="profile" className="space-y-6">
        <TabsList>
          <TabsTrigger value="profile">
            <UserRound />
            {t("settings.profile")}
          </TabsTrigger>
          <TabsTrigger value="appearance">
            <Palette />
            {t("settings.appearance")}
          </TabsTrigger>
          <TabsTrigger value="notifications">
            <Bell />
            {t("settings.notifications")}
          </TabsTrigger>
          <TabsTrigger value="security">
            <LockKeyhole />
            {t("settings.security")}
          </TabsTrigger>
          {user?.role === "admin" && (
            <TabsTrigger value="analytics">
              <Gauge />
              {t("settings.analytics")}
            </TabsTrigger>
          )}
        </TabsList>
        <TabsContent value="profile">
          <Card>
            <CardHeader>
              <CardTitle>{t("settings.profile")}</CardTitle>
              <CardDescription>
                {t("settings.profileDescription")}
              </CardDescription>
            </CardHeader>
            <CardContent className="max-w-xl space-y-4">
              <ReadOnly
                label={t("settings.email")}
                value={user?.email ?? "—"}
              />
              <ReadOnly label={t("settings.role")} value={user?.role ?? "—"} />
              <div className="space-y-2">
                <Label htmlFor="settings-locale">
                  {t("settings.preferredLanguage")}
                </Label>
                <select
                  id="settings-locale"
                  value={locale}
                  onChange={(event) =>
                    void saveLocale(normalizeLocale(event.target.value))
                  }
                  disabled={savingLocale}
                  className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                >
                  <option value="en">{t("settings.english")}</option>
                  <option value="id">{t("settings.indonesian")}</option>
                  <option value="ja">{t("settings.japanese")}</option>
                </select>
              </div>
              {localeMessage && (
                <p role="status" className="text-sm text-muted-foreground">
                  {t(localeMessage)}
                </p>
              )}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="appearance">
          <Card>
            <CardHeader>
              <CardTitle>{t("settings.appearance")}</CardTitle>
              <CardDescription>
                {t("settings.appearanceDescription")}
              </CardDescription>
            </CardHeader>
            <CardContent className="max-w-xl space-y-4">
              <div className="space-y-2">
                <Label htmlFor="settings-theme">{t("settings.theme")}</Label>
                <select
                  id="settings-theme"
                  value={mode}
                  onChange={(event) => setMode(event.target.value as ThemeMode)}
                  className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                >
                  <option value="system">{t("settings.system")}</option>
                  <option value="light">{t("settings.light")}</option>
                  <option value="dark">{t("settings.dark")}</option>
                </select>
              </div>
              <p className="text-xs text-muted-foreground">
                {t("settings.resolvedTheme", { theme: resolved })}
              </p>
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="notifications">
          <Card>
            <CardHeader>
              <CardTitle>{t("settings.notifications")}</CardTitle>
              <CardDescription>
                {t("settings.notificationsDescription")}
              </CardDescription>
            </CardHeader>
            <CardContent className="max-w-xl space-y-3">
              <Preference
                label={t("settings.securityEvents")}
                checked={notifications.security}
                onChange={(checked) =>
                  setNotifications({ ...notifications, security: checked })
                }
              />
              <Preference
                label={t("settings.certificateRenewals")}
                checked={notifications.certificates}
                onChange={(checked) =>
                  setNotifications({ ...notifications, certificates: checked })
                }
              />
              <Preference
                label={t("settings.clusterHealth")}
                checked={notifications.cluster}
                onChange={(checked) =>
                  setNotifications({ ...notifications, cluster: checked })
                }
              />
              <Button
                variant="outline"
                onClick={saveNotifications}
              >
                <Save />
                {t("settings.saveLocalPreferences")}
              </Button>
              {notificationError && <p role="alert" className="text-sm text-destructive">{t("settings.notificationSaveError")}</p>}
            </CardContent>
          </Card>
        </TabsContent>
        <TabsContent value="security">
          <Card>
            <CardHeader>
              <CardTitle>{t("settings.sessionTitle")}</CardTitle>
              <CardDescription>
                {t("settings.sessionDescription")}
              </CardDescription>
            </CardHeader>
            <CardContent className="max-w-xl space-y-4">
              <div className="rounded-lg border bg-muted/30 p-4 text-sm text-muted-foreground">
                {t("settings.sessionInfo")}
              </div>
              {user?.role === "admin" && <Button variant="outline" asChild>
                <Link to="/users"><LockKeyhole />{t("settings.reviewSession")}</Link>
              </Button>}
            </CardContent>
          </Card>
        </TabsContent>
        {user?.role === "admin" && (
          <TabsContent value="analytics">
            <Card>
              <CardHeader>
                <CardTitle>{t("settings.analyticsTitle")}</CardTitle>
                <CardDescription>
                  {t("settings.analyticsDescription")}
                </CardDescription>
              </CardHeader>
              <CardContent className="max-w-xl">
                <form className="space-y-4" onSubmit={saveRetention}>
                  <div className="space-y-2">
                    <Label htmlFor="analytics-retention">
                      {t("settings.retentionMinutes")}
                    </Label>
                    <Input
                      id="analytics-retention"
                      type="number"
                      min={60}
                      max={10080}
                      step={60}
                      value={retention}
                      onChange={(event) => setRetention(event.target.value)}
                      disabled={savingRetention}
                    />
                    <p className="text-xs text-muted-foreground">
                      {t("settings.retentionHint")}
                    </p>
                  </div>
                  <Button type="submit" disabled={savingRetention}>
                    <Save />
                    {t("settings.saveRetention")}
                  </Button>
                  {retentionMessage && (
                    <p role="status" className="text-sm text-muted-foreground">
                      {retentionMessage}
                    </p>
                  )}
                </form>
              </CardContent>
            </Card>
          </TabsContent>
        )}
      </Tabs>
    </Main>
  );
}

function ReadOnly({ label, value }: { label: string; value: string }) {
  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <div className="rounded-md border bg-muted/30 px-3 py-2 text-sm">
        {value}
      </div>
    </div>
  );
}
function Preference({
  label,
  checked,
  onChange,
}: {
  label: string;
  checked: boolean;
  onChange: (checked: boolean) => void;
}) {
  return (
    <label className="flex items-center justify-between rounded-lg border p-4 text-sm">
      <span>{label}</span>
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="size-4 accent-primary"
      />
    </label>
  );
}
