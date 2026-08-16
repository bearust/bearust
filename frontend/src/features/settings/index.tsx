import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { Bell, Gauge, LockKeyhole, Palette, Save, UserRound } from "lucide-react";
import { api } from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { useAuthStore } from "@/stores/auth-store";
import { normalizeLocale, useLocalePreference, type Locale } from "@/i18n";
import { useTheme, type ThemeMode } from "@/theme";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";

export function Settings() {
  const user = useAuthStore((state) => state.user);
  const { mode, resolved, setMode } = useTheme();
  const { locale, setLocale } = useLocalePreference();
  const [notifications, setNotifications] = useState({ security: true, certificates: true, cluster: true });
  const [savingLocale, setSavingLocale] = useState(false);
  const [localeMessage, setLocaleMessage] = useState("");
  const [retention, setRetention] = useState("1440");
  const [retentionMessage, setRetentionMessage] = useState("");
  const [savingRetention, setSavingRetention] = useState(false);

  useEffect(() => {
    if (DEMO_MODE || user?.role !== "admin") return;
    void api.getAnalyticsRetention().then((config) => setRetention(String(config.retention_minutes))).catch(() => setRetentionMessage("Analytics retention could not be loaded."));
  }, [user?.role]);

  const saveLocale = async (next: Locale) => {
    setSavingLocale(true); setLocaleMessage("");
    try { await setLocale(next); if (!DEMO_MODE && user) useAuthStore.getState().setUser({ ...user, preferred_locale: next }); setLocaleMessage("Language preference saved to this account."); } catch { setLocaleMessage("Language changed locally; account preference could not be saved."); } finally { setSavingLocale(false); }
  };

  const saveRetention = async (event: FormEvent) => {
    event.preventDefault();
    const minutes = Number(retention);
    if (!Number.isInteger(minutes) || minutes < 60 || minutes > 10_080) {
      setRetentionMessage("Retention must be between 60 minutes and 7 days.");
      return;
    }
    setSavingRetention(true); setRetentionMessage("");
    try { if (!DEMO_MODE) { const config = await api.updateAnalyticsRetention(minutes); setRetention(String(config.retention_minutes)); } setRetentionMessage("Analytics retention saved."); } catch { setRetentionMessage("Analytics retention could not be saved."); } finally { setSavingRetention(false); }
  };

  return <Main><PageHeader title="Settings" description="Manage account preferences and local control-plane behavior." action={<Badge variant="outline" className="gap-1.5 rounded-full"><span className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : "bg-emerald-500"}`} />{DEMO_MODE ? "Local demo" : "Account settings"}</Badge>} />
    <Tabs defaultValue="profile" className="space-y-6"><TabsList><TabsTrigger value="profile"><UserRound />Profile</TabsTrigger><TabsTrigger value="appearance"><Palette />Appearance</TabsTrigger><TabsTrigger value="notifications"><Bell />Notifications</TabsTrigger><TabsTrigger value="security"><LockKeyhole />Security</TabsTrigger>{user?.role === "admin" && <TabsTrigger value="analytics"><Gauge />Analytics</TabsTrigger>}</TabsList>
      <TabsContent value="profile"><Card><CardHeader><CardTitle>Profile</CardTitle><CardDescription>Identity returned by the authenticated control-plane session.</CardDescription></CardHeader><CardContent className="max-w-xl space-y-4"><ReadOnly label="Email" value={user?.email ?? "—"} /><ReadOnly label="Role" value={user?.role ?? "—"} /><div className="space-y-2"><Label htmlFor="settings-locale">Preferred language</Label><select id="settings-locale" value={locale} onChange={(event) => void saveLocale(normalizeLocale(event.target.value))} disabled={savingLocale} className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"><option value="en">English</option><option value="id">Bahasa Indonesia</option><option value="ja">日本語</option></select></div>{localeMessage && <p role="status" className="text-sm text-muted-foreground">{localeMessage}</p>}</CardContent></Card></TabsContent>
      <TabsContent value="appearance"><Card><CardHeader><CardTitle>Appearance</CardTitle><CardDescription>Theme is stored locally so the control plane remains usable during backend maintenance.</CardDescription></CardHeader><CardContent className="max-w-xl space-y-4"><div className="space-y-2"><Label htmlFor="settings-theme">Theme</Label><select id="settings-theme" value={mode} onChange={(event) => setMode(event.target.value as ThemeMode)} className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"><option value="system">System</option><option value="light">Light</option><option value="dark">Dark</option></select></div><p className="text-xs text-muted-foreground">Current resolved theme: {resolved}.</p></CardContent></Card></TabsContent>
      <TabsContent value="notifications"><Card><CardHeader><CardTitle>Notifications</CardTitle><CardDescription>Local display preferences for operational signals.</CardDescription></CardHeader><CardContent className="max-w-xl space-y-3"><Preference label="Security events" checked={notifications.security} onChange={(checked) => setNotifications({ ...notifications, security: checked })} /><Preference label="Certificate renewals" checked={notifications.certificates} onChange={(checked) => setNotifications({ ...notifications, certificates: checked })} /><Preference label="Cluster health" checked={notifications.cluster} onChange={(checked) => setNotifications({ ...notifications, cluster: checked })} /><Button variant="outline" onClick={() => toast.success("Notification preferences saved locally")}><Save />Save local preferences</Button></CardContent></Card></TabsContent>
      <TabsContent value="security"><Card><CardHeader><CardTitle>Security session</CardTitle><CardDescription>Session controls available from the authenticated account menu.</CardDescription></CardHeader><CardContent className="max-w-xl space-y-4"><div className="rounded-lg border bg-muted/30 p-4 text-sm text-muted-foreground">Session logout calls the control-plane API. User session revocation is available to administrators from Users & Roles.</div><Button variant="outline" onClick={() => toast.info("Use Users & Roles to revoke another account's sessions")}><LockKeyhole />Review session controls</Button></CardContent></Card></TabsContent>
      {user?.role === "admin" && <TabsContent value="analytics"><Card><CardHeader><CardTitle>Analytics retention</CardTitle><CardDescription>Keep minute-level telemetry in the bounded process-local ring buffer for 1 hour to 7 days.</CardDescription></CardHeader><CardContent className="max-w-xl"><form className="space-y-4" onSubmit={saveRetention}><div className="space-y-2"><Label htmlFor="analytics-retention">Retention (minutes)</Label><Input id="analytics-retention" type="number" min={60} max={10080} step={60} value={retention} onChange={(event) => setRetention(event.target.value)} disabled={savingRetention} /><p className="text-xs text-muted-foreground">The default is 1,440 minutes (24 hours). Data remains aggregate and resets when the process restarts.</p></div><Button type="submit" disabled={savingRetention}><Save />Save retention</Button>{retentionMessage && <p role="status" className="text-sm text-muted-foreground">{retentionMessage}</p>}</form></CardContent></Card></TabsContent>}
    </Tabs>
  </Main>;
}

function ReadOnly({ label, value }: { label: string; value: string }) { return <div className="space-y-2"><Label>{label}</Label><div className="rounded-md border bg-muted/30 px-3 py-2 text-sm">{value}</div></div>; }
function Preference({ label, checked, onChange }: { label: string; checked: boolean; onChange: (checked: boolean) => void }) { return <label className="flex items-center justify-between rounded-lg border p-4 text-sm"><span>{label}</span><input type="checkbox" checked={checked} onChange={(event) => onChange(event.target.checked)} className="size-4 accent-primary" /></label>; }
