import { useEffect, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import { Save, Trash2 } from "lucide-react";
import { api, type SsoKind, type SsoProvider } from "@/api";
import { sanitizeError } from "@/lib/errors";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";

const TEMPLATES: Record<SsoKind, object> = {
  oidc: {
    issuer: "https://accounts.example.com",
    client_id: "bearust",
    redirect_base_url: window.location.origin,
    default_role: "viewer",
    auto_provision: false,
    link_by_email: true,
    allowed_domains: [],
  },
  saml: {
    idp_metadata_xml: "<md:EntityDescriptor …>",
    redirect_base_url: window.location.origin,
    email_attribute: "email",
    trust_email: false,
    default_role: "viewer",
    auto_provision: false,
    link_by_email: false,
    allowed_domains: [],
  },
};

/** Admin panel for OIDC/SAML identity providers. */
export function SsoProviders() {
  const { t } = useTranslation();
  const [providers, setProviders] = useState<SsoProvider[]>([]);
  const [slug, setSlug] = useState("");
  const [name, setName] = useState("");
  const [kind, setKind] = useState<SsoKind>("oidc");
  const [config, setConfig] = useState(JSON.stringify(TEMPLATES.oidc, null, 2));
  const [secret, setSecret] = useState("");
  const [enabled, setEnabled] = useState(true);
  const [error, setError] = useState("");

  const load = () => void api.adminSsoProviders().then(setProviders).catch((e) => setError(sanitizeError(e)));
  useEffect(load, []);

  const edit = (provider: SsoProvider) => {
    setSlug(provider.slug);
    setName(provider.name);
    setKind(provider.kind);
    setConfig(JSON.stringify(provider.config, null, 2));
    setSecret("");
    setEnabled(provider.enabled);
  };

  const save = async (event: FormEvent) => {
    event.preventDefault();
    setError("");
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(config) as Record<string, unknown>;
    } catch {
      setError(t("settings.ssoInvalidJson"));
      return;
    }
    try {
      await api.saveSsoProvider({ slug, name, kind, enabled, config: parsed, ...(secret ? { client_secret: secret } : {}) });
      setSecret("");
      toast.success(t("settings.ssoSaved"));
      load();
    } catch (exception) {
      setError(sanitizeError(exception));
    }
  };

  const remove = async (target: string) => {
    try {
      await api.deleteSsoProvider(target);
      toast.success(t("settings.ssoDeleted"));
      load();
    } catch (exception) {
      setError(sanitizeError(exception));
    }
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle>{t("settings.ssoTitle")}</CardTitle>
        <CardDescription>{t("settings.ssoDescription")}</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {providers.length === 0 ? (
          <p className="text-sm text-muted-foreground">{t("settings.ssoNone")}</p>
        ) : (
          <ul className="divide-y rounded-lg border">
            {providers.map((provider) => (
              <li key={provider.slug} className="flex flex-wrap items-center justify-between gap-2 p-3">
                <button type="button" className="text-left" onClick={() => edit(provider)}>
                  <span className="font-medium">{provider.name}</span>{" "}
                  <span className="font-mono text-xs text-muted-foreground">{provider.slug}</span>
                </button>
                <span className="flex items-center gap-2">
                  <Badge variant="outline">{provider.kind.toUpperCase()}</Badge>
                  {!provider.enabled && <Badge variant="secondary">off</Badge>}
                  <Button variant="ghost" size="sm" aria-label={`${t("settings.ssoDelete")} ${provider.slug}`} onClick={() => void remove(provider.slug)}>
                    <Trash2 />
                  </Button>
                </span>
              </li>
            ))}
          </ul>
        )}
        <form className="max-w-2xl space-y-4" onSubmit={save}>
          <div className="grid gap-4 sm:grid-cols-3">
            <div className="space-y-2">
              <Label htmlFor="sso-slug">{t("settings.ssoSlug")}</Label>
              <Input id="sso-slug" value={slug} onChange={(e) => setSlug(e.target.value.toLowerCase())} pattern="[a-z0-9-]{1,64}" required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="sso-name">{t("settings.ssoName")}</Label>
              <Input id="sso-name" value={name} onChange={(e) => setName(e.target.value)} required />
            </div>
            <div className="space-y-2">
              <Label htmlFor="sso-kind">{t("settings.ssoKind")}</Label>
              <select
                id="sso-kind"
                className="h-9 w-full rounded-md border bg-transparent px-3 text-sm"
                value={kind}
                onChange={(e) => {
                  const next = e.target.value as SsoKind;
                  setKind(next);
                  setConfig(JSON.stringify(TEMPLATES[next], null, 2));
                }}
              >
                <option value="oidc">OIDC</option>
                <option value="saml">SAML</option>
              </select>
            </div>
          </div>
          <div className="space-y-2">
            <Label htmlFor="sso-config">{t("settings.ssoConfig")}</Label>
            <textarea
              id="sso-config"
              className="min-h-56 w-full rounded-md border bg-transparent p-3 font-mono text-xs"
              value={config}
              onChange={(e) => setConfig(e.target.value)}
              spellCheck={false}
            />
          </div>
          {kind === "oidc" && (
            <div className="space-y-2">
              <Label htmlFor="sso-secret">{t("settings.ssoClientSecret")}</Label>
              <Input id="sso-secret" type="password" autoComplete="off" value={secret} onChange={(e) => setSecret(e.target.value)} />
            </div>
          )}
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
            {t("settings.ssoEnabled")}
          </label>
          {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
          <Button type="submit"><Save />{t("settings.ssoSave")}</Button>
        </form>
      </CardContent>
    </Card>
  );
}
