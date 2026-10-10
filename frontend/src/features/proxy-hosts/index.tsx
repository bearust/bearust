import { useEffect, useMemo, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import {
  Ellipsis,
  KeyRound,
  LockKeyhole,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  Server,
  ShieldCheck,
  Trash2,
  Upload,
} from "lucide-react";
import {
  api,
  type AcmeRequest,
  type Certificate,
  type Host,
  type ProxyHostAuth,
} from "@/api";
import { DEMO_MODE } from "@/lib/demo";
import { sanitizeError } from "@/lib/errors";
import { useRealtimeRefresh } from "@/hooks/use-realtime-refresh";
import { useAuthStore } from "@/stores/auth-store";
import { ConfirmDialog } from "@/components/confirm-dialog";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";

type HostForm = {
  name: string;
  domain: string;
  upstream_host: string;
  upstream_port: string;
  tls_mode: string;
  certificate_id: string;
  enabled: boolean;
};

type AuthForm = {
  enabled: boolean;
  realm: string;
  username: string;
  password: string;
};

const emptyForm: HostForm = {
  name: "",
  domain: "",
  upstream_host: "",
  upstream_port: "8080",
  tls_mode: "disabled",
  certificate_id: "",
  enabled: true,
};

const emptyAuthForm: AuthForm = {
  enabled: false,
  realm: "Bearust protected host",
  username: "",
  password: "",
};

const demoHosts: Host[] = [
  {
    id: 1,
    name: "Public API",
    domain: "api.bearust.local",
    upstream_host: "api-pool",
    upstream_port: 8080,
    tls_mode: "letsencrypt",
    certificate_id: 1,
    enabled: true,
  },
  {
    id: 2,
    name: "Admin Console",
    domain: "console.bearust.local",
    upstream_host: "console",
    upstream_port: 3000,
    tls_mode: "letsencrypt",
    certificate_id: 1,
    enabled: true,
  },
  {
    id: 3,
    name: "Documentation",
    domain: "docs.bearust.local",
    upstream_host: "docs",
    upstream_port: 8080,
    tls_mode: "internal",
    certificate_id: null,
    enabled: false,
  },
  {
    id: 4,
    name: "Metrics endpoint",
    domain: "metrics.bearust.local",
    upstream_host: "prometheus",
    upstream_port: 9090,
    tls_mode: "letsencrypt",
    certificate_id: 1,
    enabled: true,
  },
];

const demoCertificates: Certificate[] = [
  {
    id: 1,
    name: "Public wildcard",
    source: "Let's Encrypt",
    covered_hostnames: [
      "api.bearust.local",
      "console.bearust.local",
      "metrics.bearust.local",
    ],
    expiry: "2026-11-14T00:00:00Z",
    active: true,
  },
  {
    id: 2,
    name: "Internal CA",
    source: "Uploaded",
    covered_hostnames: ["docs.bearust.local"],
    expiry: "2027-02-21T00:00:00Z",
    active: false,
  },
];

export function ProxyHosts() {
  const { t } = useTranslation();
  const user = useAuthStore((state) => state.user);
  const canWrite = user?.role !== "viewer";
  const [hosts, setHosts] = useState<Host[]>(DEMO_MODE ? demoHosts : []);
  const [certificates, setCertificates] = useState<Certificate[]>(
    DEMO_MODE ? demoCertificates : [],
  );
  const [query, setQuery] = useState("");
  const [open, setOpen] = useState(false);
  const [authOpen, setAuthOpen] = useState(false);
  const [authHost, setAuthHost] = useState<Host | null>(null);
  const [auth, setAuth] = useState<ProxyHostAuth | null>(null);
  const [authForm, setAuthForm] = useState<AuthForm>(emptyAuthForm);
  const [certificateOpen, setCertificateOpen] = useState(false);
  const [uploadOpen, setUploadOpen] = useState(false);
  const [editingId, setEditingId] = useState<number | null>(null);
  const [form, setForm] = useState<HostForm>(emptyForm);
  const [acme, setAcme] = useState<AcmeRequest>({
    environment: "staging",
    challenge: "http01",
    hostnames: [],
  });
  const [hostnameText, setHostnameText] = useState("");
  const [uploadName, setUploadName] = useState("");
  const [certificateFile, setCertificateFile] = useState<File | null>(null);
  const [keyFile, setKeyFile] = useState<File | null>(null);
  const [confirmHost, setConfirmHost] = useState<Host | null>(null);
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState("");

  const refresh = async () => {
    if (DEMO_MODE) return;
    setLoading(true);
    setError("");
    try {
      const [nextHosts, nextCertificates] = await Promise.all([
        api.hosts(),
        api.certificates(),
      ]);
      const withAcme = await Promise.all(
        nextCertificates.map(async (certificate) => {
          try {
            return {
              ...certificate,
              acme: await api.certificateStatus(certificate.id),
            };
          } catch {
            return certificate;
          }
        }),
      );
      setHosts(nextHosts);
      setCertificates(withAcme);
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    void refresh();
  }, []);
  useRealtimeRefresh(["proxy_hosts.changed", "certificates.changed", "security.changed"], refresh);

  const visibleHosts = useMemo(
    () =>
      hosts.filter((host) =>
        `${host.name} ${host.domain} ${host.upstream_host}:${host.upstream_port}`
          .toLowerCase()
          .includes(query.toLowerCase()),
      ),
    [hosts, query],
  );
  const activeHosts = hosts.filter((host) => host.enabled).length;
  const tlsHosts = hosts.filter((host) => host.tls_mode !== "disabled").length;

  const openCreate = () => {
    setEditingId(null);
    setForm(emptyForm);
    setError("");
    setOpen(true);
  };

  const openEdit = (host: Host) => {
    setEditingId(host.id);
    setForm({
      name: host.name,
      domain: host.domain,
      upstream_host: host.upstream_host,
      upstream_port: String(host.upstream_port),
      tls_mode: host.tls_mode,
      certificate_id:
        host.certificate_id == null ? "" : String(host.certificate_id),
      enabled: host.enabled,
    });
    setError("");
    setOpen(true);
  };

  const openAuth = async (host: Host) => {
    setAuthHost(host);
    setAuthForm(emptyAuthForm);
    setError("");
    setAuthOpen(true);
    if (DEMO_MODE) {
      setAuth({
        host_id: host.id,
        enabled: false,
        realm: emptyAuthForm.realm,
        username: "",
        updated_at: "",
      });
      return;
    }
    try {
      const next = await api.hostAuth(host.id);
      setAuth(next);
      setAuthForm({
        enabled: next.enabled,
        realm: next.realm,
        username: next.username,
        password: "",
      });
    } catch (exception) {
      setAuthOpen(false);
      setError(sanitizeError(exception));
    }
  };

  const submitAuth = async (event: FormEvent) => {
    event.preventDefault();
    if (!authHost) return;
    if (
      authForm.enabled &&
      (!authForm.username.trim() || (!auth?.enabled && !authForm.password))
    ) {
      setError(t("proxyHosts.authValidation"));
      return;
    }
    if (authForm.password && authForm.password.length < 12) {
      setError(t("proxyHosts.authPasswordError"));
      return;
    }
    setBusy(`auth-${authHost.id}`);
    setError("");
    try {
      const payload = {
        enabled: authForm.enabled,
        realm: authForm.realm.trim(),
        username: authForm.username.trim(),
        ...(authForm.password ? { password: authForm.password } : {}),
      };
      if (DEMO_MODE)
        setAuth({
          host_id: authHost.id,
          enabled: payload.enabled,
          realm: payload.realm,
          username: payload.username,
          updated_at: new Date().toISOString(),
        });
      else setAuth(await api.updateHostAuth(authHost.id, payload));
      setAuthForm((current) => ({ ...current, password: "" }));
      setAuthOpen(false);
      toast.success(t("proxyHosts.authUpdated"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(null);
    }
  };

  const submitHost = async (event: FormEvent) => {
    event.preventDefault();
    const port = Number(form.upstream_port);
    if (
      !form.name.trim() ||
      !form.domain.trim() ||
      !form.upstream_host.trim() ||
      !Number.isInteger(port) ||
      port < 1 ||
      port > 65535
    ) {
      setError(t("proxyHosts.hostValidation"));
      return;
    }
    const payload = {
      name: form.name.trim(),
      domain: form.domain.trim(),
      upstream_host: form.upstream_host.trim(),
      upstream_port: port,
      tls_mode: form.tls_mode,
      certificate_id: form.certificate_id ? Number(form.certificate_id) : null,
      enabled: form.enabled,
    };
    setBusy("host");
    setError("");
    try {
      if (DEMO_MODE) {
        const next = { id: editingId ?? Date.now(), ...payload };
        setHosts((current) =>
          editingId == null
            ? [...current, next]
            : current.map((host) => (host.id === editingId ? next : host)),
        );
      } else if (editingId == null) {
        await api.createHost(payload);
        await refresh();
      } else {
        await api.updateHost(editingId, payload);
        await refresh();
      }
      setOpen(false);
      toast.success(
        editingId == null
          ? t("proxyHosts.hostCreated")
          : t("proxyHosts.hostUpdated"),
      );
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(null);
    }
  };

  const removeHost = (host: Host) => {
    if (!canWrite) return;
    setConfirmHost(host);
  };

  const confirmRemoveHost = async () => {
    if (!confirmHost) return;
    const host = confirmHost;
    setConfirmHost(null);
    setBusy(`delete-${host.id}`);
    try {
      if (DEMO_MODE)
        setHosts((current) => current.filter((item) => item.id !== host.id));
      else {
        await api.deleteHost(host.id);
        await refresh();
      }
      toast.success(t("proxyHosts.hostRemoved"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(null);
    }
  };

  const certificateAction = async (
    certificate: Certificate,
    action: "renew" | "activate",
  ) => {
    setBusy(`${action}-${certificate.id}`);
    setError("");
    try {
      if (!DEMO_MODE) {
        if (action === "renew") await api.renewCertificate(certificate.id);
        else await api.activateCertificate(certificate.id);
        await refresh();
      } else if (action === "activate") {
        setCertificates((current) =>
          current.map((item) => ({
            ...item,
            active: item.id === certificate.id,
          })),
        );
      }
      toast.success(
        action === "renew"
          ? t("proxyHosts.certificateRenewalQueued")
          : t("proxyHosts.certificateActivated"),
      );
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(null);
    }
  };

  const issueCertificate = async (event: FormEvent) => {
    event.preventDefault();
    const hostnames = hostnameText
      .split(",")
      .map((hostname) => hostname.trim())
      .filter(Boolean);
    if (hostnames.length === 0) {
      setError(t("proxyHosts.addHostnameError"));
      return;
    }
    setBusy("acme");
    setError("");
    try {
      if (DEMO_MODE)
        toast.success(t("proxyHosts.certificateQueued"), {
          description: t("proxyHosts.acmeDemoAccepted"),
        });
      else
        await api.issueAcme({
          ...acme,
          hostnames,
          ...(acme.cloudflare_api_token
            ? { cloudflare_api_token: acme.cloudflare_api_token }
            : {}),
        });
      setCertificateOpen(false);
      setHostnameText("");
      setAcme({ environment: "staging", challenge: "http01", hostnames: [] });
      await refresh();
      toast.success(t("proxyHosts.certificateQueued"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(null);
    }
  };

  const uploadCertificate = async (event: FormEvent) => {
    event.preventDefault();
    if (!uploadName.trim() || !certificateFile || !keyFile) {
      setError(t("proxyHosts.uploadValidation"));
      return;
    }
    setBusy("upload");
    setError("");
    try {
      if (DEMO_MODE) {
        setCertificates((current) => [
          ...current,
          {
            id: Date.now(),
            name: uploadName.trim(),
            source: "Uploaded",
            covered_hostnames: [],
            expiry: "2027-01-01T00:00:00Z",
            active: false,
          },
        ]);
      } else {
        await api.uploadCertificate({
          name: uploadName.trim(),
          certificate: certificateFile,
          key: keyFile,
        });
        await refresh();
      }
      setUploadOpen(false);
      setUploadName("");
      setCertificateFile(null);
      setKeyFile(null);
      toast.success(t("proxyHosts.certificateUploaded"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(null);
    }
  };

  return (
    <Main>
      <PageHeader
        title={t("proxyHosts.title")}
        description={t("proxyHosts.description")}
        action={
          <>
            <Badge
              variant="outline"
              className="hidden gap-1.5 rounded-full sm:inline-flex"
            >
              <span
                className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : "bg-emerald-500"}`}
              />
              {DEMO_MODE
                ? t("proxyHosts.demoData")
                : t("proxyHosts.apiConnected")}
            </Badge>
            <Button onClick={openCreate} disabled={!canWrite}>
              <Plus />
              {t("proxyHosts.addProxyHost")}
            </Button>
          </>
        }
      />

      {error && (
        <div
          role="alert"
          className="mb-4 rounded-md border border-destructive/30 bg-destructive/10 px-4 py-3 text-sm text-destructive"
        >
          {error}
        </div>
      )}
      <div className="mb-6 grid gap-4 sm:grid-cols-3">
        <SummaryCard
          icon={Server}
          label={t("proxyHosts.activeHosts")}
          value={String(activeHosts)}
          detail={t("proxyHosts.configuredHosts", { count: hosts.length })}
        />
        <SummaryCard
          icon={ShieldCheck}
          label={t("proxyHosts.tlsCoverage")}
          value={
            hosts.length
              ? `${Math.round((tlsHosts / hosts.length) * 100)}%`
              : "0%"
          }
          detail={t("proxyHosts.tlsHosts", { count: tlsHosts })}
        />
        <SummaryCard
          icon={KeyRound}
          label={t("certificates.title")}
          value={String(certificates.length)}
          detail={t("proxyHosts.certificateCount", {
            count: certificates.filter((certificate) => certificate.active)
              .length,
          })}
        />
      </div>

      <Card>
        <CardHeader className="gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>{t("proxyHosts.configured")}</CardTitle>
            <CardDescription>
              {DEMO_MODE
                ? t("proxyHosts.demoRecords")
                : t("proxyHosts.persistedChanges")}
            </CardDescription>
          </div>
          <div className="flex w-full gap-2 sm:w-auto">
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
              <Input
                aria-label={t("proxyHosts.search")}
                placeholder={t("proxyHosts.searchPlaceholder")}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                className="h-9 pl-8"
              />
            </div>
            <Button
              variant="outline"
              size="icon"
              aria-label={t("proxyHosts.refresh")}
              onClick={() => void refresh()}
              disabled={loading}
            >
              <RefreshCw className={loading ? "animate-spin" : ""} />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <LoadingRows />
          ) : (
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("proxyHosts.host")}</TableHead>
                  <TableHead>{t("proxyHosts.domain")}</TableHead>
                  <TableHead>{t("proxyHosts.upstream")}</TableHead>
                  <TableHead>{t("proxyHosts.tls")}</TableHead>
                  <TableHead>{t("proxyHosts.status")}</TableHead>
                  <TableHead className="w-10">
                    <span className="sr-only">{t("proxyHosts.actions")}</span>
                  </TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {visibleHosts.map((host) => (
                  <TableRow key={host.id}>
                    <TableCell>
                      <div className="font-medium">{host.name}</div>
                      <div className="text-xs text-muted-foreground">
                        {host.enabled
                          ? t("common.enabled")
                          : t("common.disabled")}
                      </div>
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {host.domain}
                    </TableCell>
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {host.upstream_host}:{host.upstream_port}
                    </TableCell>
                    <TableCell>
                      <Badge variant="secondary">
                        {host.tls_mode === "disabled"
                          ? t("proxyHosts.off")
                          : host.tls_mode}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <StatusBadge
                        status={host.enabled ? "healthy" : "warning"}
                      >
                        {host.enabled
                          ? t("proxyHosts.healthy")
                          : t("common.disabled")}
                      </StatusBadge>
                    </TableCell>
                    <TableCell>
                      <DropdownMenu>
                        <DropdownMenuTrigger asChild>
                          <Button
                            variant="ghost"
                            size="icon"
                            aria-label={`Actions for ${host.name}`}
                          >
                            <Ellipsis />
                          </Button>
                        </DropdownMenuTrigger>
                        <DropdownMenuContent align="end">
                          <DropdownMenuItem
                            onClick={() => openEdit(host)}
                            disabled={!canWrite}
                          >
                            <Pencil />
                            {t("proxyHosts.editHost")}
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            onClick={() => void openAuth(host)}
                            disabled={!canWrite}
                          >
                            <LockKeyhole />
                            {t("proxyHosts.hostAuthentication")}
                          </DropdownMenuItem>
                          <DropdownMenuItem
                            onClick={() => setCertificateOpen(true)}
                            disabled={!canWrite}
                          >
                            <KeyRound />
                            {t("proxyHosts.issueCertificate")}
                          </DropdownMenuItem>
                          <DropdownMenuSeparator />
                          <DropdownMenuItem
                            variant="destructive"
                            onClick={() => removeHost(host)}
                            disabled={!canWrite || busy === `delete-${host.id}`}
                          >
                            <Trash2 />
                            {t("proxyHosts.deleteHost")}
                          </DropdownMenuItem>
                        </DropdownMenuContent>
                      </DropdownMenu>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
          {!loading && visibleHosts.length === 0 && (
            <div className="py-12 text-center text-sm text-muted-foreground">
              {t("proxyHosts.noMatch")}
            </div>
          )}
        </CardContent>
      </Card>

      <Card className="mt-6">
        <CardHeader className="gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>{t("certificates.title")}</CardTitle>
            <CardDescription>
              {t("proxyHosts.certificatesDescription")}
            </CardDescription>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              onClick={() => setUploadOpen(true)}
              disabled={!canWrite}
            >
              <Upload />
              {t("proxyHosts.uploadCertificate")}
            </Button>
            <Button
              variant="outline"
              onClick={() => setCertificateOpen(true)}
              disabled={!canWrite}
            >
              <Plus />
              {t("proxyHosts.requestCertificate")}
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>{t("certificates.title")}</TableHead>
                <TableHead>{t("proxyHosts.hostnames")}</TableHead>
                <TableHead>{t("proxyHosts.expires")}</TableHead>
                <TableHead>{t("common.status")}</TableHead>
                <TableHead className="text-right">
                  {t("proxyHosts.certificateActions")}
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {certificates.map((certificate) => {
                const renewable =
                  Boolean(certificate.acme) ||
                  /acme|letsencrypt/i.test(certificate.source);
                return (
                  <TableRow key={certificate.id}>
                    <TableCell>
                      <div className="font-medium">{certificate.name}</div>
                      <div className="text-xs text-muted-foreground">
                        {certificate.source}
                      </div>
                    </TableCell>
                    <TableCell className="max-w-64 truncate font-mono text-xs">
                      {certificate.covered_hostnames.join(", ")}
                    </TableCell>
                    <TableCell className="whitespace-nowrap text-sm text-muted-foreground">
                      {formatDate(certificate.expiry)}
                    </TableCell>
                    <TableCell>
                      <StatusBadge
                        status={certificate.active ? "healthy" : "info"}
                      >
                        {certificate.active ? "Active" : "Available"}
                      </StatusBadge>
                    </TableCell>
                    <TableCell className="text-right">
                      <div className="flex justify-end gap-2">
                        {renewable && (
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() =>
                              void certificateAction(certificate, "renew")
                            }
                            disabled={!canWrite || busy != null}
                          >
                            {busy === `renew-${certificate.id}`
                              ? "Renewing…"
                              : "Renew"}
                          </Button>
                        )}
                        {!certificate.active && (
                          <Button
                            variant="outline"
                            size="sm"
                            onClick={() =>
                              void certificateAction(certificate, "activate")
                            }
                            disabled={!canWrite || busy != null}
                          >
                            {busy === `activate-${certificate.id}`
                              ? "Activating…"
                              : "Activate"}
                          </Button>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                );
              })}
            </TableBody>
          </Table>
          {certificates.length === 0 && (
            <p className="py-8 text-center text-sm text-muted-foreground">
              {t("certificates.empty")}
            </p>
          )}
        </CardContent>
      </Card>

      <Dialog open={open} onOpenChange={setOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>
              {editingId == null
                ? t("proxyHosts.addHostTitle")
                : t("proxyHosts.editHostTitle")}
            </DialogTitle>
            <DialogDescription>
              {t("proxyHosts.hostFormDescription")}
            </DialogDescription>
          </DialogHeader>
          <form
            id="host-form"
            className="grid gap-4 sm:grid-cols-2"
            onSubmit={(event) => void submitHost(event)}
          >
            <Field
              id="host-name"
              label={t("proxyHosts.displayName")}
              value={form.name}
              onChange={(value) => setForm({ ...form, name: value })}
              placeholder={t("proxyHosts.displayNamePlaceholder")}
            />
            <Field
              id="host-domain"
              label={t("proxyHosts.domain")}
              value={form.domain}
              onChange={(value) => setForm({ ...form, domain: value })}
              placeholder={t("proxyHosts.domainPlaceholder")}
            />
            <Field
              id="host-upstream"
              label={t("proxyHosts.upstreamHost")}
              value={form.upstream_host}
              onChange={(value) => setForm({ ...form, upstream_host: value })}
              placeholder={t("proxyHosts.upstreamPlaceholder")}
            />
            <Field
              id="host-port"
              label={t("proxyHosts.upstreamPort")}
              type="number"
              value={form.upstream_port}
              onChange={(value) => setForm({ ...form, upstream_port: value })}
              placeholder={t("proxyHosts.portPlaceholder")}
            />
            <div className="space-y-2">
              <Label htmlFor="host-tls">{t("proxyHosts.tlsMode")}</Label>
              <select
                id="host-tls"
                value={form.tls_mode}
                onChange={(event) =>
                  setForm({ ...form, tls_mode: event.target.value })
                }
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="disabled">{t("proxyHosts.tlsDisabled")}</option>
                <option value="letsencrypt">Let's Encrypt</option>
                <option value="internal">{t("proxyHosts.internalCa")}</option>
              </select>
            </div>
            <div className="space-y-2">
              <Label htmlFor="host-certificate">
                {t("proxyHosts.certificate")}
              </Label>
              <select
                id="host-certificate"
                value={form.certificate_id}
                onChange={(event) =>
                  setForm({ ...form, certificate_id: event.target.value })
                }
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                <option value="">{t("proxyHosts.noCertificate")}</option>
                {certificates.map((certificate) => (
                  <option key={certificate.id} value={certificate.id}>
                    {certificate.name}
                  </option>
                ))}
              </select>
            </div>
            <p className="text-xs text-muted-foreground sm:col-span-2">
              {t("proxyHosts.tlsHint")}
            </p>
            <label className="flex items-center gap-2 text-sm sm:col-span-2">
              <input
                type="checkbox"
                checked={form.enabled}
                onChange={(event) =>
                  setForm({ ...form, enabled: event.target.checked })
                }
                className="size-4 accent-primary"
              />
              {t("proxyHosts.enableHost")}
            </label>
          </form>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setOpen(false)}
            >
              {t("common.cancel")}
            </Button>
            <Button type="submit" form="host-form" disabled={busy === "host"}>
              {busy === "host"
                ? t("common.loading")
                : editingId == null
                  ? t("proxyHosts.addHost")
                  : t("common.save")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={certificateOpen} onOpenChange={setCertificateOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("proxyHosts.requestAcme")}</DialogTitle>
            <DialogDescription>
              {t("proxyHosts.acmeDescription")}
            </DialogDescription>
          </DialogHeader>
          <form
            id="certificate-form"
            className="space-y-4"
            onSubmit={(event) => void issueCertificate(event)}
          >
            <div className="space-y-2">
              <Label htmlFor="certificate-hostnames">
                {t("proxyHosts.hostnamesLabel")}
              </Label>
              <Input
                id="certificate-hostnames"
                value={hostnameText}
                onChange={(event) => setHostnameText(event.target.value)}
                placeholder={t("proxyHosts.hostnamesPlaceholder")}
                required
              />
              <p className="text-xs text-muted-foreground">
                {t("proxyHosts.hostnamesHint")}
              </p>
            </div>
            <div className="grid gap-4 sm:grid-cols-2">
              <div className="space-y-2">
                <Label htmlFor="acme-environment">
                  {t("proxyHosts.environment")}
                </Label>
                <select
                  id="acme-environment"
                  value={acme.environment}
                  onChange={(event) =>
                    setAcme({
                      ...acme,
                      environment: event.target
                        .value as AcmeRequest["environment"],
                    })
                  }
                  className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                >
                  <option value="staging">{t("acme.staging")}</option>
                  <option value="production">{t("acme.production")}</option>
                </select>
              </div>
              <div className="space-y-2">
                <Label htmlFor="acme-challenge">
                  {t("proxyHosts.challenge")}
                </Label>
                <select
                  id="acme-challenge"
                  value={acme.challenge}
                  onChange={(event) =>
                    setAcme({
                      ...acme,
                      challenge: event.target.value as AcmeRequest["challenge"],
                    })
                  }
                  className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
                >
                  <option value="http01">{t("acme.http01")}</option>
                  <option value="cloudflare_dns01">
                    {t("acme.cloudflareDns01")}
                  </option>
                </select>
              </div>
            </div>
            {acme.challenge === "cloudflare_dns01" && (
              <div className="space-y-2">
                <Label htmlFor="cloudflare-token">
                  {t("proxyHosts.cloudflareToken")}
                </Label>
                <Input
                  id="cloudflare-token"
                  type="password"
                  value={acme.cloudflare_api_token ?? ""}
                  onChange={(event) =>
                    setAcme({
                      ...acme,
                      cloudflare_api_token: event.target.value,
                    })
                  }
                  autoComplete="off"
                />
              </div>
            )}
          </form>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setCertificateOpen(false)}
            >
              {t("common.cancel")}
            </Button>
            <Button
              type="submit"
              form="certificate-form"
              disabled={busy === "acme"}
            >
              {busy === "acme"
                ? t("common.loading")
                : t("proxyHosts.requestCertificate")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog
        open={uploadOpen}
        onOpenChange={(nextOpen) => {
          setUploadOpen(nextOpen);
          if (!nextOpen) {
            setUploadName("");
            setCertificateFile(null);
            setKeyFile(null);
          }
        }}
      >
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("proxyHosts.uploadTitle")}</DialogTitle>
            <DialogDescription>
              {t("proxyHosts.uploadDescription")}
            </DialogDescription>
          </DialogHeader>
          <form
            id="upload-certificate-form"
            className="space-y-4"
            onSubmit={(event) => void uploadCertificate(event)}
          >
            <Field
              id="upload-certificate-name"
              label={t("proxyHosts.certificateName")}
              value={uploadName}
              onChange={setUploadName}
              placeholder={t("proxyHosts.certificateNamePlaceholder")}
            />
            <div className="space-y-2">
              <Label htmlFor="upload-certificate-file">
                {t("proxyHosts.certificateFile")}
              </Label>
              <Input
                id="upload-certificate-file"
                type="file"
                accept=".pem,.crt,.cer,application/x-pem-file"
                onChange={(event) =>
                  setCertificateFile(event.target.files?.[0] ?? null)
                }
                required
              />
            </div>
            <div className="space-y-2">
              <Label htmlFor="upload-key-file">
                {t("proxyHosts.privateKeyFile")}
              </Label>
              <Input
                id="upload-key-file"
                type="file"
                accept=".pem,.key,application/x-pem-file"
                onChange={(event) =>
                  setKeyFile(event.target.files?.[0] ?? null)
                }
                required
              />
            </div>
          </form>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setUploadOpen(false)}
            >
              {t("common.cancel")}
            </Button>
            <Button
              type="submit"
              form="upload-certificate-form"
              disabled={busy === "upload"}
            >
              {busy === "upload"
                ? t("common.loading")
                : t("proxyHosts.uploadCertificate")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={confirmHost != null}
        onOpenChange={(open) => {
          if (!open && busy == null) setConfirmHost(null);
        }}
        title={t("proxyHosts.deleteConfirmTitle")}
        description={
          confirmHost
            ? `${confirmHost.domain} and its routing entry will be removed from the control plane.`
            : t("proxyHosts.deleteHost")
        }
        pending={busy != null}
        onConfirm={() => void confirmRemoveHost()}
      />
      <Dialog open={authOpen} onOpenChange={setAuthOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("proxyHosts.authTitle")}</DialogTitle>
            <DialogDescription>
              {authHost
                ? t("proxyHosts.authDescriptionHost", { host: authHost.domain })
                : t("proxyHosts.authDescription")}
            </DialogDescription>
          </DialogHeader>
          <form
            id="host-auth-form"
            className="space-y-4"
            onSubmit={(event) => void submitAuth(event)}
          >
            <label className="flex items-center gap-3 text-sm">
              <input
                type="checkbox"
                checked={authForm.enabled}
                onChange={(event) =>
                  setAuthForm({ ...authForm, enabled: event.target.checked })
                }
                disabled={!canWrite || busy != null}
                className="size-4 accent-primary"
              />
              {t("proxyHosts.requireAuth")}
            </label>
            <Field
              id="auth-realm"
              label={t("proxyHosts.realm")}
              value={authForm.realm}
              onChange={(value) => setAuthForm({ ...authForm, realm: value })}
              placeholder={t("proxyHosts.realmPlaceholder")}
            />
            <Field
              id="auth-username"
              label={t("proxyHosts.username")}
              value={authForm.username}
              onChange={(value) =>
                setAuthForm({ ...authForm, username: value })
              }
              placeholder="service-user"
            />
            <Field
              id="auth-password"
              label={
                auth?.enabled
                  ? t("proxyHosts.newPassword")
                  : t("proxyHosts.password")
              }
              type="password"
              value={authForm.password}
              onChange={(value) =>
                setAuthForm({ ...authForm, password: value })
              }
              placeholder={t("proxyHosts.passwordHint")}
            />
          </form>
          <DialogFooter>
            <Button
              type="button"
              variant="outline"
              onClick={() => setAuthOpen(false)}
            >
              {t("common.cancel")}
            </Button>
            <Button
              type="submit"
              form="host-auth-form"
              disabled={!canWrite || busy === `auth-${authHost?.id}`}
            >
              <LockKeyhole />
              {t("common.save")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </Main>
  );
}

function Field({
  id,
  label,
  value,
  onChange,
  placeholder,
  type = "text",
}: {
  id: string;
  label: string;
  value: string;
  onChange: (value: string) => void;
  placeholder?: string;
  type?: string;
}) {
  return (
    <div className="space-y-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        required
      />
    </div>
  );
}

function SummaryCard({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: typeof Server;
  label: string;
  value: string;
  detail: string;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {label}
        </CardTitle>
        <Icon className="size-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-bold tabular-nums">{value}</div>
        <p className="text-xs text-muted-foreground">{detail}</p>
      </CardContent>
    </Card>
  );
}

function LoadingRows() {
  const { t } = useTranslation();
  return (
    <div
      className="space-y-3 py-2"
      role="status"
      aria-label={t("proxyHosts.loading")}
    >
      {Array.from({ length: 4 }, (_, index) => (
        <div className="h-12 animate-pulse rounded-md bg-muted" key={index} />
      ))}
    </div>
  );
}

function formatDate(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? value
    : new Intl.DateTimeFormat(undefined, { dateStyle: "medium" }).format(date);
}
