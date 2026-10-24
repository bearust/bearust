import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Save } from "lucide-react";
import { api, type CaptchaProvider, type CaptchaSettings } from "@/api";
import { sanitizeError } from "@/lib/errors";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

/** CAPTCHA provider used by bot challenges instead of proof-of-work. */
export function CaptchaPanel({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const [settings, setSettings] = useState<CaptchaSettings | null>(null);
  const [provider, setProvider] = useState<CaptchaProvider>("none");
  const [siteKey, setSiteKey] = useState("");
  const [secret, setSecret] = useState("");
  const [error, setError] = useState("");

  const apply = (next: CaptchaSettings) => {
    setSettings(next);
    setProvider(next.provider);
    setSiteKey(next.site_key);
    setSecret("");
  };
  useEffect(() => {
    void api.botCaptcha().then(apply).catch((e) => setError(sanitizeError(e)));
  }, []);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    try {
      apply(await api.updateBotCaptcha({ provider, site_key: siteKey, ...(secret ? { secret } : {}) }));
      toast.success(t("bot.captchaSaved"));
    } catch (exception) {
      setError(sanitizeError(exception));
    }
  };

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>{t("bot.captchaTitle")}</CardTitle>
        <CardDescription>{t("bot.captchaDescription")}</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="max-w-xl space-y-4" onSubmit={save}>
          <div className="space-y-2">
            <Label htmlFor="captcha-provider">{t("bot.captchaProvider")}</Label>
            <select id="captcha-provider" className="h-9 w-full rounded-md border bg-transparent px-3 text-sm" value={provider} disabled={!canWrite} onChange={(e) => setProvider(e.target.value as CaptchaProvider)}>
              <option value="none">{t("bot.captchaNone")}</option>
              <option value="turnstile">Cloudflare Turnstile</option>
              <option value="hcaptcha">hCaptcha</option>
              <option value="recaptcha">Google reCAPTCHA</option>
            </select>
          </div>
          {provider !== "none" && (
            <>
              <div className="space-y-2">
                <Label htmlFor="captcha-site-key">{t("bot.captchaSiteKey")}</Label>
                <Input id="captcha-site-key" value={siteKey} disabled={!canWrite} onChange={(e) => setSiteKey(e.target.value)} />
              </div>
              <div className="space-y-2">
                <Label htmlFor="captcha-secret">{t("bot.captchaSecret")}</Label>
                <Input id="captcha-secret" type="password" autoComplete="off" value={secret} disabled={!canWrite} placeholder={settings?.has_secret ? "••••••••" : ""} onChange={(e) => setSecret(e.target.value)} />
              </div>
            </>
          )}
          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          {canWrite && <Button type="submit"><Save />{t("bot.captchaSave")}</Button>}
        </form>
      </CardContent>
    </Card>
  );
}
