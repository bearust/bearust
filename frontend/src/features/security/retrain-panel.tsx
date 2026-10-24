import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { RotateCcw, Save, Wand2 } from "lucide-react";
import { api, type RetrainRecommendation, type RetrainSettings, type RuleTuning } from "@/api";
import { sanitizeError } from "@/lib/errors";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

/** Feedback-driven retraining settings, recommendations, and reverts. */
export function RetrainPanel({ canWrite }: { canWrite: boolean }) {
  const { t } = useTranslation();
  const [settings, setSettings] = useState<RetrainSettings>({ mode: "off", min_reports: 5, false_positive_percent: 80, window_days: 30 });
  const [recommendations, setRecommendations] = useState<RetrainRecommendation[]>([]);
  const [tunings, setTunings] = useState<RuleTuning[]>([]);
  const [error, setError] = useState("");

  const load = async () => {
    try {
      const [config, recs, tuned] = await Promise.all([api.wafRetrain(), api.wafRetrainRecommendations(), api.wafRuleTunings()]);
      setSettings(config);
      setRecommendations(recs);
      setTunings(tuned);
    } catch (exception) {
      setError(sanitizeError(exception));
    }
  };
  useEffect(() => {
    void load();
  }, []);

  const run = async (action: () => Promise<unknown>, message: string) => {
    setError("");
    try {
      await action();
      toast.success(message);
      await load();
    } catch (exception) {
      setError(sanitizeError(exception));
    }
  };
  const save = (event: FormEvent) => {
    event.preventDefault();
    void run(() => api.updateWafRetrain(settings), t("security.retrainSaved"));
  };
  const number = (key: "min_reports" | "false_positive_percent" | "window_days") => (value: string) => setSettings({ ...settings, [key]: Number(value) });

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle>{t("security.retrainTitle")}</CardTitle>
        <CardDescription>{t("security.retrainDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        <form className="grid max-w-3xl gap-4 sm:grid-cols-4" onSubmit={save}>
          <div className="space-y-2">
            <Label htmlFor="retrain-mode">{t("security.retrainMode")}</Label>
            <select id="retrain-mode" className="h-9 w-full rounded-md border bg-transparent px-3 text-sm" value={settings.mode} disabled={!canWrite} onChange={(e) => setSettings({ ...settings, mode: e.target.value as RetrainSettings["mode"] })}>
              <option value="off">{t("security.retrainOff")}</option>
              <option value="recommend">{t("security.retrainRecommend")}</option>
              <option value="enforce">{t("security.retrainEnforce")}</option>
            </select>
          </div>
          <div className="space-y-2">
            <Label htmlFor="retrain-min">{t("security.retrainMinReports")}</Label>
            <Input id="retrain-min" type="number" min={1} value={settings.min_reports} disabled={!canWrite} onChange={(e) => number("min_reports")(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="retrain-percent">{t("security.retrainPercent")}</Label>
            <Input id="retrain-percent" type="number" min={50} max={100} value={settings.false_positive_percent} disabled={!canWrite} onChange={(e) => number("false_positive_percent")(e.target.value)} />
          </div>
          <div className="space-y-2">
            <Label htmlFor="retrain-window">{t("security.retrainWindow")}</Label>
            <Input id="retrain-window" type="number" min={1} max={365} value={settings.window_days} disabled={!canWrite} onChange={(e) => number("window_days")(e.target.value)} />
          </div>
          {canWrite && <Button type="submit" className="sm:col-span-4 sm:w-fit"><Save />{t("security.retrainSave")}</Button>}
        </form>
        <div className="space-y-2">
          {recommendations.length === 0 ? (
            <p className="text-sm text-muted-foreground">{t("security.retrainNoRecommendations")}</p>
          ) : (
            <ul className="space-y-1 text-sm">
              {recommendations.map((rec) => (
                <li key={rec.rule_id}>{t("security.retrainRecommendation", { id: rec.rule_id, fp: rec.false_positives, tp: rec.true_positives })}</li>
              ))}
            </ul>
          )}
          {canWrite && settings.mode !== "off" && recommendations.length > 0 && (
            <Button variant="outline" onClick={() => void run(async () => { const applied = await api.runWafRetrain(); toast.message(t("security.retrainApplied", { count: applied.length })); }, t("security.retrainSaved"))}>
              <Wand2 />{t("security.retrainApply")}
            </Button>
          )}
        </div>
        {tunings.length > 0 && (
          <div className="space-y-2">
            <h3 className="text-sm font-medium">{t("security.retrainTunings")}</h3>
            <ul className="divide-y rounded-lg border">
              {tunings.map((tuning) => (
                <li key={tuning.rule_id} className="flex items-center justify-between gap-2 p-3 text-sm">
                  <span>
                    <span className="font-mono">{tuning.rule_id}</span>{" "}
                    <Badge variant="outline">{tuning.kind === "seclang" ? "CRS" : "WAF"}</Badge>{" "}
                    <span className="text-muted-foreground">{tuning.false_positives}/{tuning.true_positives} · {tuning.source}</span>
                  </span>
                  {canWrite && (
                    <Button variant="ghost" size="sm" onClick={() => void run(() => api.revertWafRuleTuning(tuning.rule_id), t("security.retrainReverted"))}>
                      <RotateCcw />{t("security.retrainRevert")}
                    </Button>
                  )}
                </li>
              ))}
            </ul>
          </div>
        )}
        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
      </CardContent>
    </Card>
  );
}
