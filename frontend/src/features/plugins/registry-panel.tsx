import { useEffect, useState } from "react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Download, RefreshCw, ShieldCheck, ShieldAlert } from "lucide-react";
import { api, type RegistryListing } from "@/api";
import { sanitizeError } from "@/lib/errors";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

/** Browse/install/upgrade plugins from the registry index. */
export function RegistryPanel({ canManage, onInstalled }: { canManage: boolean; onInstalled: () => void }) {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const [listing, setListing] = useState<RegistryListing | null>(null);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");

  const load = async (q: string) => {
    setError("");
    try {
      setListing(await api.pluginRegistry(q));
    } catch (exception) {
      setError(sanitizeError(exception));
    }
  };
  useEffect(() => {
    const timer = setTimeout(() => void load(query), 250);
    return () => clearTimeout(timer);
  }, [query]);

  const install = async (id: string, force: boolean) => {
    setBusy(id);
    setError("");
    try {
      const result = await api.installRegistryPlugin(id, force);
      toast.success(t("shell.registryInstalledToast", { id: result.id, version: result.version }));
      onInstalled();
      await load(query);
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Card className="mt-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          {t("shell.registryTitle")}
          {listing && (
            <Badge variant={listing.index_signed ? "secondary" : "outline"} className="gap-1">
              {listing.index_signed ? <ShieldCheck className="size-3" /> : <ShieldAlert className="size-3" />}
              {listing.index_signed ? t("shell.registryIndexSigned") : t("shell.registryIndexUnsigned")}
            </Badge>
          )}
        </CardTitle>
        <CardDescription>{t("shell.registryDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        <Input aria-label={t("shell.registrySearch")} placeholder={t("shell.registrySearch")} value={query} onChange={(e) => setQuery(e.target.value)} />
        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
        {listing?.entries.length === 0 && <p className="text-sm text-muted-foreground">{t("shell.registryEmpty")}</p>}
        {listing?.entries.map((entry) => (
          <div key={entry.id} className="flex flex-col gap-3 rounded-lg border p-4 sm:flex-row sm:items-center sm:justify-between">
            <div className="min-w-0">
              <p className="font-medium">{entry.display_name} <span className="font-mono text-xs text-muted-foreground">{entry.id} · v{entry.version}</span></p>
              <p className="text-sm text-muted-foreground">{entry.description}</p>
              <div className="mt-1 flex gap-2">
                <Badge variant="outline">{entry.signed ? t("shell.registrySignedPackage") : t("shell.registryUnsignedPackage")}</Badge>
                {entry.installed_version && <Badge variant="secondary">{t("shell.registryInstalled", { version: entry.installed_version })}</Badge>}
              </div>
            </div>
            {canManage && (!entry.installed_version || entry.update_available) && (
              <Button size="sm" variant={entry.update_available ? "default" : "outline"} disabled={busy != null} onClick={() => void install(entry.id, entry.update_available)}>
                {busy === entry.id ? <RefreshCw className="animate-spin" /> : <Download />}
                {entry.update_available ? t("shell.registryUpgrade", { version: entry.version }) : t("shell.registryInstall")}
              </Button>
            )}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
