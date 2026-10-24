import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Save, ShieldCheck } from "lucide-react";
import { api, type SecLangStatus } from "@/api";
import { errorDetails, sanitizeError } from "@/lib/errors";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

/** OWASP CRS toggle, paranoia/threshold tuning, and custom SecLang rules. */
export function CrsPanel({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const [status, setStatus] = useState<SecLangStatus | null>(null);
  const [enabled, setEnabled] = useState(false);
  const [paranoia, setParanoia] = useState(1);
  const [threshold, setThreshold] = useState("5");
  const [custom, setCustom] = useState("");
  const [error, setError] = useState("");
  const [saving, setSaving] = useState(false);

  const apply = (next: SecLangStatus) => {
    setStatus(next);
    setEnabled(next.crs_enabled);
    setParanoia(next.paranoia_level);
    setThreshold(String(next.inbound_threshold));
    setCustom(next.custom_rules);
  };
  useEffect(() => {
    void api.wafSecLang().then(apply).catch((e) => setError(sanitizeError(e)));
  }, []);

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setSaving(true);
    setError("");
    try {
      apply(await api.updateWafSecLang({ crs_enabled: enabled, paranoia_level: paranoia, inbound_threshold: Number(threshold), custom_rules: custom }));
      toast.success(t("security.crsSaved"));
    } catch (exception) {
      // Rule diagnostics (file, line, construct) come from the admin's own
      // rules and are needed to fix them.
      const details = errorDetails(exception);
      setError(details.code === "invalid_rules" && details.message ? details.message : sanitizeError(exception));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2"><ShieldCheck className="size-4" />{t("security.crsTitle")}</CardTitle>
        <CardDescription>{t("security.crsDescription")}</CardDescription>
      </CardHeader>
      <CardContent>
        <form className="max-w-2xl space-y-4" onSubmit={save}>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={enabled} disabled={!canWrite} onChange={(e) => setEnabled(e.target.checked)} />
            {t("security.crsEnabled")}
          </label>
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="space-y-2">
              <Label htmlFor="crs-paranoia">{t("security.crsParanoia")}</Label>
              <select id="crs-paranoia" className="h-9 w-full rounded-md border bg-transparent px-3 text-sm" value={paranoia} disabled={!canWrite} onChange={(e) => setParanoia(Number(e.target.value))}>
                {[1, 2, 3, 4].map((level) => <option key={level} value={level}>PL{level}</option>)}
              </select>
              <p className="text-xs text-muted-foreground">{t("security.crsParanoiaHint")}</p>
            </div>
            <div className="space-y-2">
              <Label htmlFor="crs-threshold">{t("security.crsThreshold")}</Label>
              <Input id="crs-threshold" type="number" min={1} max={1000} value={threshold} disabled={!canWrite} onChange={(e) => setThreshold(e.target.value)} />
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="crs-custom">{t("security.crsCustomRules")}</Label>
            <textarea
              id="crs-custom"
              className="min-h-40 w-full rounded-md border bg-transparent p-3 font-mono text-xs"
              value={custom}
              disabled={!canWrite}
              spellCheck={false}
              placeholder={'SecRule REQUEST_HEADERS:User-Agent "@pm badbot" "id:10001,phase:1,deny"'}
              onChange={(e) => setCustom(e.target.value)}
            />
          </div>
          {status && <p className="text-xs text-muted-foreground">{t("security.crsActiveRules", { count: status.active_rules, version: status.crs_version })}</p>}
          {error && <p role="alert" className="whitespace-pre-wrap text-sm text-destructive">{error}</p>}
          {canWrite && <Button type="submit" disabled={saving}><Save />{t("security.crsSave")}</Button>}
        </form>
      </CardContent>
    </Card>
  );
}
