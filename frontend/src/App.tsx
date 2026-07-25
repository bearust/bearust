import {
  useEffect,
  useRef,
  useState,
  type MutableRefObject,
  type FormEvent,
} from "react";
import {
  api,
  AcmeRequest,
  AuditLogItem,
  AuditLogQuery,
  Certificate,
  Host,
  PermissionKey,
  RoleRecord,
  Role,
  User,
  WafConfig,
  WafRule,
  BotConfig,
  BotMode,
  TrustedCrawler,
  BotChallenge,
  RateLimitConfig,
  RateLimitAction,
  AnalyticsSummary,
  AnalyticsBucket,
  BaselineSnapshot,
  BaselineWindow,
  BaselineStatus,
  AnomalyRecord,
  AnomalyRule,
  AnomalySeverity,
  TuningPolicy,
  TuningMode,
  PolicyRecommendation,
} from "./api";
import { useRealtimeUpdates, RealtimeStatus } from "./realtime";
import {
  i18n,
  initI18n,
  LocalePreferenceProvider,
  useLocalePreference,
} from "./i18n";
import {
  Alert,
  Button,
  Card,
  Field,
  LanguageSelect,
  SelectField,
  TextareaField,
  ThemeSelect,
} from "./ui";
import { useTranslation } from "react-i18next";

void initI18n();

export const sanitizeError = (message: string) => {
  if (/internal stack|database|password\s*[:=]/i.test(message))
    return i18n.t("errors.generic");
  return message
    .replace(
      /(api[_ -]?token|authorization|bearer)\s*[:=]\s*[^\s,;]+/gi,
      "$1: [redacted]",
    )
    .replace(/\b[A-Za-z0-9_-]{30,}\b/g, "[redacted]");
};
export const userError = (error: unknown) => {
  const message = error instanceof Error ? error.message : String(error);
  const status = (error as { status?: number })?.status;
  if (
    status === 401 ||
    status === 403 ||
    /\b403\b|forbidden|permission/i.test(message)
  )
    return i18n.t("errors.usersPermission");
  if (
    status === 400 ||
    status === 422 ||
    /\b400\b|validation|invalid|required/i.test(message)
  )
    return i18n.t("errors.usersValidation");
  if (status === 404) return i18n.t("errors.userNotFound");
  if (status === 409) return i18n.t("errors.userConflict");
  return i18n.t("errors.generic");
};
export const validHostname = (
  host: string,
  challenge: "http01" | "cloudflare_dns01",
): boolean => {
  const h = host.trim().toLowerCase();
  if (!h || /\s/.test(h)) return false;
  if (h.startsWith("*."))
    return (
      challenge === "cloudflare_dns01" &&
      validHostname(h.slice(2), "cloudflare_dns01") &&
      !h.slice(2).includes("*")
    );
  if (h.includes("*") || h.length > 253) return false;
  return h
    .split(".")
    .every(
      (x) =>
        x.length > 0 &&
        x.length <= 63 &&
        !x.startsWith("-") &&
        !x.endsWith("-") &&
        /^[a-z0-9-]+$/.test(x),
    );
};
export const acmeSubmissionReady = (
  challenge: AcmeRequest["challenge"],
  hosts: string[],
  token: string,
) =>
  hosts.length > 0 &&
  hosts.every((host) => validHostname(host, challenge)) &&
  (challenge !== "cloudflare_dns01" || token.trim().length > 0);
function Setup({ onDone }: { onDone: (u: User) => void }) {
  const { t } = useTranslation();
  const [email, setEmail] = useState(""),
    [password, setPassword] = useState(""),
    [token, setToken] = useState(""),
    [error, setError] = useState("");
  return (
    <main className="min-h-screen bg-page px-4 py-8 text-foreground sm:px-6 lg:px-8">
      <Card className="mx-auto max-w-lg">
        <h1 className="mb-2 text-2xl font-semibold">{t("auth.setupTitle")}</h1>
        <p className="mb-6 text-muted">{t("auth.setupDescription")}</p>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              onDone(await api.setup({ email, password, setup_token: token }));
            } catch (x) {
              setError(sanitizeError((x as Error).message));
            }
          }}
        >
          <Field
            label={t("common.email")}
            type="email"
            value={email}
            onChange={(e: any) => setEmail(e.target.value)}
          />
          <Field
            label={t("auth.passwordHint")}
            type="password"
            value={password}
            onChange={(e: any) => setPassword(e.target.value)}
          />
          <Field
            label={t("auth.setupToken")}
            value={token}
            onChange={(e: any) => setToken(e.target.value)}
          />
          {error && <Alert variant="danger">{error}</Alert>}
          <Button type="submit">{t("auth.createAccount")}</Button>
        </form>
      </Card>
    </main>
  );
}
function Login({ onDone }: { onDone: (u: User) => void }) {
  const { t } = useTranslation();
  const [email, setEmail] = useState(""),
    [password, setPassword] = useState(""),
    [error, setError] = useState("");
  return (
    <main className="min-h-screen bg-page px-4 py-8 text-foreground sm:px-6 lg:px-8">
      <Card className="mx-auto max-w-lg">
        <h1 className="mb-6 text-2xl font-semibold">{t("auth.loginTitle")}</h1>
        <form
          onSubmit={async (e) => {
            e.preventDefault();
            try {
              onDone(await api.login({ email, password }));
            } catch (x) {
              setError(sanitizeError((x as Error).message));
            }
          }}
        >
          <Field
            label={t("common.email")}
            type="email"
            value={email}
            onChange={(e: any) => setEmail(e.target.value)}
          />
          <Field
            label={t("common.password")}
            type="password"
            value={password}
            onChange={(e: any) => setPassword(e.target.value)}
          />
          {error && <Alert variant="danger">{error}</Alert>}
          <Button type="submit">{t("auth.signIn")}</Button>
        </form>
      </Card>
    </main>
  );
}

export function AcmeWizard({
  onIssued,
  canWrite = true,
}: {
  onIssued: () => void;
  canWrite?: boolean;
}) {
  const { t } = useTranslation();
  const [challenge, setChallenge] =
      useState<AcmeRequest["challenge"]>("http01"),
    [environment, setEnvironment] =
      useState<AcmeRequest["environment"]>("staging"),
    [domains, setDomains] = useState(""),
    [token, setToken] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  if (!canWrite) return null;
  const hosts = domains
    .split(/[,\n]+/)
    .map((x) => x.trim())
    .filter(Boolean);
  const invalid = hosts.some((h) => !validHostname(h, challenge));
  const missingToken = challenge === "cloudflare_dns01" && !token.trim();
  return (
    <Card>
      <h2 className="mb-4 text-xl font-semibold">{t("acme.title")}</h2>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          if (invalid || missingToken || busy) return;
          if (
            environment === "production" &&
            !window.confirm(t("acme.productionConfirm"))
          )
            return;
          setBusy(true);
          setError("");
          try {
            await api.issueAcme({
              environment,
              challenge,
              hostnames: hosts,
              ...(challenge === "cloudflare_dns01"
                ? { cloudflare_api_token: token }
                : {}),
            });
            setDomains("");
            setToken("");
            onIssued();
          } catch (x) {
            setError(sanitizeError((x as Error).message));
          } finally {
            setBusy(false);
          }
        }}
      >
        <SelectField
          label={t("acme.environment")}
          value={environment}
          onChange={(e) =>
            setEnvironment(e.target.value as AcmeRequest["environment"])
          }
        >
          <option value="staging">{t("acme.staging")}</option>
          <option value="production">{t("acme.production")}</option>
        </SelectField>
        <SelectField
          label={t("acme.challenge")}
          value={challenge}
          onChange={(e) =>
            setChallenge(e.target.value as AcmeRequest["challenge"])
          }
        >
          <option value="http01">{t("acme.http01")}</option>
          <option value="cloudflare_dns01">{t("acme.cloudflareDns01")}</option>
        </SelectField>
        <TextareaField
          label={t("acme.domains")}
          value={domains}
          onChange={(e) => setDomains(e.target.value)}
          required
          rows={3}
          placeholder={t("acme.domainsPlaceholder")}
        />
        {invalid && <Alert variant="warning">{t("acme.invalidHosts")}</Alert>}
        {challenge === "cloudflare_dns01" && (
          <Field
            label={t("acme.cloudflareToken")}
            type="password"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoComplete="off"
            placeholder={t("acme.tokenRequired")}
            required
            error={missingToken ? t("acme.tokenError") : undefined}
          />
        )}
        {error && <Alert variant="danger">{error}</Alert>}
        <Button
          type="submit"
          disabled={busy || invalid || missingToken || hosts.length === 0}
        >
          {busy ? t("acme.issuing") : t("acme.issue")}
        </Button>
      </form>
    </Card>
  );
}

export function CertificateTable({
  user,
  onChanged,
}: {
  user: User;
  onChanged: () => void;
}) {
  const { t } = useTranslation();
  const [items, setItems] = useState<Certificate[]>([]),
    [error, setError] = useState(""),
    [refreshing, setRefreshing] = useState(false),
    [busy, setBusy] = useState<Record<number, string>>({});
  const canWrite = user.role !== "viewer";
  const refresh = async () => {
    setRefreshing(true);
    setError("");
    try {
      const rows = await api.certificates();
      const updated = await Promise.all(
        rows.map(async (row) => {
          if (!row.acme) return row;
          try {
            return { ...row, acme: await api.certificateStatus(row.id) };
          } catch {
            return row;
          }
        }),
      );
      setItems(updated);
    } catch (e) {
      setError(sanitizeError((e as Error).message));
    } finally {
      setRefreshing(false);
    }
  };
  const action = async (
    id: number,
    kind: "renew" | "activate",
    run: () => Promise<unknown>,
  ) => {
    setBusy((x) => ({ ...x, [id]: kind }));
    setError("");
    try {
      await run();
      await refresh();
      onChanged();
    } catch (e) {
      setError(sanitizeError((e as Error).message));
    } finally {
      setBusy((x) => {
        const next = { ...x };
        delete next[id];
        return next;
      });
    }
  };
  useEffect(() => {
    void refresh();
  }, []);
  return (
    <Card>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-xl font-semibold">{t("certificates.title")}</h2>
        <Button
          variant="secondary"
          onClick={() => void refresh()}
          disabled={refreshing}
        >
          {refreshing ? t("common.refreshing") : t("common.refresh")}
        </Button>
      </div>
      {error && <Alert variant="danger">{error}</Alert>}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {items.map((c) => (
          <article
            className="flex flex-col gap-2 rounded-md border border-border bg-surface-muted p-4"
            key={c.id}
          >
            <strong className="font-semibold">{c.name}</strong>
            <span className="text-sm text-muted">
              {c.source} · {c.covered_hostnames.join(", ")}
            </span>
            <span className="text-sm text-muted">
              {t("certificates.expires", { expiry: c.expiry })}
            </span>
            <span className="text-sm">
              {t("certificates.status", {
                status: c.active
                  ? t("common.active")
                  : t("certificates.inactive"),
              })}
              {c.acme &&
                ` · ${t("certificates.renewal", { state: c.acme.renewal_state })}`}
            </span>
            {c.acme?.last_error_code && (
              <span className="text-sm text-danger-foreground">
                {t("certificates.lastError", {
                  error: sanitizeError(c.acme.last_error_code),
                })}
              </span>
            )}
            <div>
              {canWrite && (
                <>
                  <Button
                    variant="secondary"
                    disabled={!!busy[c.id]}
                    onClick={() =>
                      void action(c.id, "renew", () =>
                        api.renewCertificate(c.id),
                      )
                    }
                  >
                    {busy[c.id] === "renew"
                      ? t("certificates.renewing")
                      : t("certificates.renew")}
                  </Button>
                  {!c.active && (
                    <Button
                      variant="secondary"
                      disabled={!!busy[c.id]}
                      onClick={() =>
                        void action(c.id, "activate", () =>
                          api.activateCertificate(c.id),
                        )
                      }
                    >
                      {busy[c.id] === "activate"
                        ? t("certificates.activating")
                        : t("certificates.activate")}
                    </Button>
                  )}
                </>
              )}
            </div>
          </article>
        ))}
      </div>
      {items.length === 0 && <p>{t("certificates.empty")}</p>}
    </Card>
  );
}

export function UsersSection({
  user,
  users,
  roles = [],
  onChanged,
  userErrorMessage = "",
}: {
  user: User;
  users: User[];
  roles?: RoleRecord[];
  onChanged: () => void | Promise<void>;
  userErrorMessage?: string;
}) {
  const { t } = useTranslation();
  const [error, setError] = useState(""),
    [busy, setBusy] = useState<number | null>(null);
  const [email, setEmail] = useState(""),
    [password, setPassword] = useState(""),
    [role, setRole] = useState<Role>("viewer");
  if (user.role !== "admin") return null;
  const run = async (id: number, action: () => Promise<unknown>) => {
    setBusy(id);
    setError("");
    try {
      await action();
      await onChanged();
    } catch (e) {
      setError(userError(e));
    } finally {
      setBusy(null);
    }
  };
  const roleOptions = [
    ...roles,
    ...["admin", "operator", "viewer"]
      .filter((slug) => !roles.some((role) => role.slug === slug))
      .map((slug) => ({ slug, name: slug[0].toUpperCase() + slug.slice(1) })),
  ];
  return (
    <Card data-testid="users-section">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-xl font-semibold">{t("users.title")}</h2>
        <Button
          data-testid="users-refresh"
          variant="secondary"
          onClick={() => void run(-2, () => Promise.resolve())}
        >
          {t("common.refresh")}
        </Button>
      </div>
      {(error || userErrorMessage) && (
        <Alert variant="danger">{error || userErrorMessage}</Alert>
      )}
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead>
            <tr>
              <th>{t("common.email")}</th>
              <th>{t("common.role")}</th>
              <th>{t("common.status")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {users.map((item) => {
              const self = item.id === user.id;
              return (
                <tr key={item.id}>
                  <td>
                    {item.email}
                    {self ? ` ${t("users.self")}` : ""}
                  </td>
                  <td>
                    <SelectField
                      label={t("common.role")}
                      value={item.role}
                      disabled={self || busy === item.id}
                      onChange={(e) =>
                        void run(item.id, () =>
                          api.updateUser(item.id, {
                            role: e.target.value as Role,
                          }),
                        )
                      }
                    >
                      {roleOptions.map((role) => (
                        <option value={role.slug} key={role.slug}>
                          {role.name}
                        </option>
                      ))}
                    </SelectField>
                  </td>
                  <td>
                    {item.disabled ? t("common.disabled") : t("common.active")}
                  </td>
                  <td>
                    {!self && (
                      <>
                        <Button
                          variant="secondary"
                          disabled={busy === item.id}
                          onClick={() => {
                            if (
                              window.confirm(
                                item.disabled
                                  ? t("users.enableConfirm")
                                  : t("users.disableConfirm"),
                              )
                            )
                              void run(item.id, () =>
                                api.updateUser(item.id, {
                                  disabled: !item.disabled,
                                }),
                              );
                          }}
                        >
                          {item.disabled
                            ? t("common.enable")
                            : t("common.disable")}
                        </Button>{" "}
                        <Button
                          variant="secondary"
                          disabled={busy === item.id}
                          onClick={() =>
                            void run(item.id, async () => {
                              const result = await api.revokeUserSessions(
                                item.id,
                              );
                              window.alert(
                                t("users.revokedSessions", {
                                  count: result.revoked,
                                }),
                              );
                            })
                          }
                        >
                          {t("users.revokeSessions")}
                        </Button>{" "}
                        <Button
                          variant="danger"
                          disabled={busy === item.id}
                          onClick={() => {
                            if (window.confirm(t("users.deleteConfirm")))
                              void run(item.id, () => api.deleteUser(item.id));
                          }}
                        >
                          {t("common.delete")}
                        </Button>
                      </>
                    )}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
      <form
        data-testid="user-create-form"
        className="mt-6 grid gap-4 sm:grid-cols-2"
        onSubmit={async (e) => {
          e.preventDefault();
          if (!email.trim() || password.length < 12) return;
          await run(-1, async () => {
            await api.createUser({ email: email.trim(), password, role });
            setEmail("");
            setPassword("");
            setRole("viewer");
          });
        }}
      >
        <h3>{t("users.add")}</h3>
        <Field
          label={t("common.email")}
          type="email"
          value={email}
          onChange={(e: any) => setEmail(e.target.value)}
        />
        <Field
          label={t("auth.passwordHint")}
          type="password"
          value={password}
          onChange={(e: any) => setPassword(e.target.value)}
        />
        <SelectField
          label={t("common.role")}
          value={role}
          onChange={(e) => setRole(e.target.value as Role)}
        >
          <option value="admin">{t("users.admin")}</option>
          <option value="operator">{t("users.operator")}</option>
          <option value="viewer">{t("users.viewer")}</option>
        </SelectField>
        <Button
          type="submit"
          disabled={busy === -1 || !email.trim() || password.length < 12}
        >
          {t("users.create")}
        </Button>
      </form>
    </Card>
  );
}

const PERMISSIONS: PermissionKey[] = [
  "proxy_hosts.read",
  "proxy_hosts.write",
  "certificates.read",
  "certificates.write",
  "users.manage",
  "roles.manage",
  "audit_logs.read",
  "audit_logs.export",
  "system.settings.manage",
  "sessions.revoke",
];
type ScopeDraft = Record<
  number,
  Record<"proxy_hosts.read" | "proxy_hosts.write", number[]>
>;
export function RolesSection({
  user,
  roles,
  hosts = [],
  onChanged,
}: {
  user: User;
  roles: RoleRecord[];
  hosts?: Host[];
  onChanged: () => void | Promise<void>;
}) {
  const { t } = useTranslation();
  const [slug, setSlug] = useState(""),
    [name, setName] = useState(""),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false);
  const [drafts, setDrafts] = useState<ScopeDraft>(
    () =>
      Object.fromEntries(
        roles.map((role) => [
          role.id,
          {
            "proxy_hosts.read":
              role.scopes?.find((s) => s.permission === "proxy_hosts.read")
                ?.proxy_host_ids ?? [],
            "proxy_hosts.write":
              role.scopes?.find((s) => s.permission === "proxy_hosts.write")
                ?.proxy_host_ids ?? [],
          },
        ]),
      ) as ScopeDraft,
  );
  useEffect(() => {
    setDrafts((current) => {
      const next: ScopeDraft = {};
      for (const role of roles) {
        next[role.id] = {
          "proxy_hosts.read":
            current[role.id]?.["proxy_hosts.read"] ??
            role.scopes?.find((s) => s.permission === "proxy_hosts.read")
              ?.proxy_host_ids ??
            [],
          "proxy_hosts.write":
            current[role.id]?.["proxy_hosts.write"] ??
            role.scopes?.find((s) => s.permission === "proxy_hosts.write")
              ?.proxy_host_ids ??
            [],
        };
      }
      return next;
    });
  }, [roles]);
  if (user.role !== "admin") return null;
  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError("");
    try {
      await action();
      await onChanged();
    } catch (e) {
      setError(
        (e as { status?: number })?.status === 400 ||
          (e as { status?: number })?.status === 422
          ? t("errors.rolesValidation")
          : userError(e),
      );
    } finally {
      setBusy(false);
    }
  };
  const updateScope = (
    roleId: number,
    permission: "proxy_hosts.read" | "proxy_hosts.write",
    hostId: number,
    checked: boolean,
  ) => {
    setDrafts((all) => {
      const current = all[roleId] ?? {
        "proxy_hosts.read": [],
        "proxy_hosts.write": [],
      };
      const ids = checked
        ? [...new Set([...current[permission], hostId])].sort((a, b) => a - b)
        : current[permission].filter((id) => id !== hostId);
      return { ...all, [roleId]: { ...current, [permission]: ids } };
    });
  };
  const scopePayload = (roleId: number) =>
    (["proxy_hosts.read", "proxy_hosts.write"] as const)
      .map((permission) => ({
        permission,
        proxy_host_ids: [...new Set(drafts[roleId]?.[permission] ?? [])].sort(
          (a, b) => a - b,
        ),
      }))
      .filter((scope) => scope.proxy_host_ids.length);
  return (
    <Card>
      <h2 className="mb-4 text-xl font-semibold">{t("roles.title")}</h2>
      {error && <Alert variant="danger">{error}</Alert>}
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead>
            <tr>
              <th>{t("common.name")}</th>
              <th>{t("roles.slug")}</th>
              <th>{t("roles.permissions")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {roles.map((role) => (
              <tr key={role.id}>
                <td>{role.name}</td>
                <td>{role.slug}</td>
                <td>
                  {role.permissions.join(", ")}
                  <div
                    data-testid={`role-scope-editor-${role.id}`}
                    className="mt-3 grid gap-3 sm:grid-cols-2"
                  >
                    <fieldset className="min-w-0">
                      <legend className="font-medium">
                        {t("roles.proxyRead")}
                      </legend>
                      {hosts.map((host) => (
                        <label
                          className="flex items-center gap-2 text-sm"
                          key={`read-${host.id}`}
                        >
                          <input
                            data-testid={`scope-read-host-${host.id}`}
                            type="checkbox"
                            disabled={role.system_managed || busy}
                            checked={
                              drafts[role.id]?.["proxy_hosts.read"]?.includes(
                                host.id,
                              ) ?? false
                            }
                            onChange={(e) =>
                              updateScope(
                                role.id,
                                "proxy_hosts.read",
                                host.id,
                                e.target.checked,
                              )
                            }
                          />
                          <span className="truncate">{host.domain}</span>
                        </label>
                      ))}
                    </fieldset>
                    <fieldset className="min-w-0">
                      <legend className="font-medium">
                        {t("roles.proxyWrite")}
                      </legend>
                      {hosts.map((host) => (
                        <label
                          className="flex items-center gap-2 text-sm"
                          key={`write-${host.id}`}
                        >
                          <input
                            data-testid={`scope-write-host-${host.id}`}
                            type="checkbox"
                            disabled={role.system_managed || busy}
                            checked={
                              drafts[role.id]?.["proxy_hosts.write"]?.includes(
                                host.id,
                              ) ?? false
                            }
                            onChange={(e) =>
                              updateScope(
                                role.id,
                                "proxy_hosts.write",
                                host.id,
                                e.target.checked,
                              )
                            }
                          />
                          <span className="truncate">{host.domain}</span>
                        </label>
                      ))}
                    </fieldset>
                    {!role.system_managed && (
                      <div className="flex flex-wrap gap-2 sm:col-span-2">
                        <Button
                          data-testid={`role-scope-save-${role.id}`}
                          variant="secondary"
                          disabled={busy}
                          onClick={() =>
                            void run(() =>
                              api.updateRole(role.id, {
                                description: role.description,
                                scopes: scopePayload(role.id),
                              }),
                            )
                          }
                        >
                          {t("roles.saveScopes")}
                        </Button>
                        <Button
                          data-testid={`role-scope-clear-${role.id}`}
                          variant="secondary"
                          disabled={busy}
                          onClick={() =>
                            setDrafts((all) => ({
                              ...all,
                              [role.id]: {
                                "proxy_hosts.read": [],
                                "proxy_hosts.write": [],
                              },
                            }))
                          }
                        >
                          {t("roles.clearScopes")}
                        </Button>
                      </div>
                    )}
                  </div>
                </td>
                <td>
                  {!role.system_managed && (
                    <Button
                      variant="danger"
                      disabled={busy}
                      onClick={() =>
                        window.confirm(t("users.deleteConfirm")) &&
                        void run(() => api.deleteRole(role.id))
                      }
                    >
                      {t("common.delete")}
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <form
        className="mt-6 grid gap-4 sm:grid-cols-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (!slug.trim() || !name.trim()) return;
          void run(async () => {
            await api.createRole({
              slug: slug.trim(),
              name: name.trim(),
              description: "",
              permissions: ["audit_logs.read"],
              scopes: [],
            });
            setSlug("");
            setName("");
          });
        }}
      >
        <h3 className="sm:col-span-2 font-semibold">{t("roles.add")}</h3>
        <Field
          label={t("roles.slug")}
          value={slug}
          onChange={(e: any) => setSlug(e.target.value)}
        />
        <Field
          label={t("common.name")}
          value={name}
          onChange={(e: any) => setName(e.target.value)}
        />
        <Button type="submit" disabled={busy || !slug.trim() || !name.trim()}>
          {t("roles.create")}
        </Button>
      </form>
      <p className="mt-4 text-sm text-muted">
        {t("roles.available", { permissions: PERMISSIONS.join(", ") })}
      </p>
    </Card>
  );
}

export function WafSection({
  user,
  refreshToken = 0,
}: {
  user: User;
  refreshToken?: number;
}) {
  const { t } = useTranslation();
  const [config, setConfig] = useState<WafConfig | null>(null),
    [rules, setRules] = useState<WafRule[]>([]),
    [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [toml, setToml] = useState("");
  const admin = user.role === "admin";
  const reload = async () => {
    try {
      const [nextConfig, nextRules] = await Promise.all([
        api.wafConfig(),
        api.wafRules(),
      ]);
      setConfig(nextConfig);
      setRules(nextRules);
      setError("");
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
    }
  };
  useEffect(() => {
    void reload();
  }, [refreshToken]);
  const changeMode = async () => {
    if (!config || !admin) return;
    setBusy(true);
    try {
      setConfig(
        await api.updateWafConfig({
          mode: config.mode === "block" ? "monitor-only" : "block",
        }),
      );
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
    } finally {
      setBusy(false);
    }
  };
  const importToml = async () => {
    setBusy(true);
    try {
      await api.importWafRules(toml);
      setToml("");
      await reload();
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
    } finally {
      setBusy(false);
    }
  };
  const exportToml = async () => {
    try {
      setToml(await api.exportWafRules());
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
    }
  };
  return (
    <Card data-testid="waf-section">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="mr-auto text-xl font-semibold">{t("waf.title")}</h2>
        <span
          className="rounded-full border border-border px-3 py-1 text-sm"
          data-testid="waf-mode"
        >
          {config?.mode === "block"
            ? t("common.block")
            : t("common.monitorOnly")}
        </span>
        {admin && (
          <Button
            variant="secondary"
            disabled={busy || !config}
            onClick={() => void changeMode()}
          >
            {config?.mode === "block"
              ? t("common.monitorOnly")
              : t("common.block")}
          </Button>
        )}
      </div>
      {error && <Alert variant="danger">{error}</Alert>}
      <div className="mt-4 overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead>
            <tr>
              <th>{t("common.name")}</th>
              <th>{t("waf.category")}</th>
              <th>{t("waf.severity")}</th>
              <th>{t("common.action")}</th>
              <th>{t("common.status")}</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.id}>
                <td>{rule.name}</td>
                <td>{rule.category}</td>
                <td>{rule.severity}</td>
                <td>{rule.action}</td>
                <td>
                  {rule.enabled ? t("common.enabled") : t("common.disabled")}
                </td>
                <td>
                  {admin && rule.source === "custom" && (
                    <Button
                      variant="danger"
                      disabled={busy}
                      onClick={() =>
                        void api
                          .deleteWafRule(rule.id)
                          .then(reload)
                          .catch((e) =>
                            setError(
                              sanitizeError(
                                e instanceof Error ? e.message : String(e),
                              ),
                            ),
                          )
                      }
                    >
                      {t("common.delete")}
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {admin && (
        <div className="mt-5 grid gap-3">
          <TextareaField
            label={t("waf.toml")}
            value={toml}
            onChange={(e) => setToml(e.target.value)}
            rows={8}
            placeholder={t("waf.tomlPlaceholder")}
          />
          <div className="flex flex-wrap gap-2">
            <Button
              variant="secondary"
              disabled={busy || !toml.trim()}
              onClick={() => void importToml()}
            >
              {t("waf.import")}
            </Button>
            <Button
              variant="secondary"
              disabled={busy}
              onClick={() => void exportToml()}
            >
              {t("waf.export")}
            </Button>
          </div>
        </div>
      )}
    </Card>
  );
}

/** The proxy fingerprint is keyed and must be supplied by the server. Never
 * substitute a browser/user-agent value: it cannot match the data-plane hash. */
const serverChallengeFingerprint = () => {
  if (typeof sessionStorage === "undefined") return "";
  const value = sessionStorage.getItem("bearust-bot-fingerprint") ?? "";
  return /^[a-f0-9]{16}$/.test(value) ? value : "";
};

export async function solveBotChallenge(
  challenge: BotChallenge,
  fingerprint: string,
): Promise<string> {
  if (typeof crypto === "undefined" || !crypto.subtle)
    throw new Error(i18n.t("errors.challengeUnavailable"));
  const encoder = new TextEncoder();
  const prefix = "0".repeat(Math.min(challenge.difficulty, 4));
  for (let nonce = 0; nonce < 1_000_000; nonce += 1) {
    const digest = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(`${challenge.token.split(".")[1] ?? ""}${nonce}`),
    );
    const hex = Array.from(new Uint8Array(digest), (byte) =>
      byte.toString(16).padStart(2, "0"),
    ).join("");
    if (hex.startsWith(prefix)) return String(nonce);
  }
  throw new Error(i18n.t("errors.challengeVerification"));
}

export function BotProtectionSection({
  user,
  refreshToken = 0,
}: {
  user: User;
  refreshToken?: number;
}) {
  const { t } = useTranslation();
  const [config, setConfig] = useState<BotConfig | null>(null),
    [crawlers, setCrawlers] = useState<TrustedCrawler[]>([]);
  const [mode, setMode] = useState<BotMode>("monitor"),
    [threshold, setThreshold] = useState(""),
    [ttl, setTtl] = useState(""),
    [ua, setUa] = useState(""),
    [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [saved, setSaved] = useState(false);
  const reload = async () => {
    try {
      const [nextConfig, nextCrawlers] = await Promise.all([
        api.botConfig(),
        api.trustedCrawlers(),
      ]);
      setConfig(nextConfig);
      setMode(nextConfig.mode);
      setThreshold(String(nextConfig.threshold));
      setTtl(String(nextConfig.ttl_seconds));
      setCrawlers(nextCrawlers);
      setError("");
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
    }
  };
  useEffect(() => {
    if (user.role === "admin") void reload();
  }, [refreshToken, user.role]);
  if (user.role !== "admin") return null;
  const run = async (action: () => Promise<unknown>) => {
    setBusy(true);
    setError("");
    setSaved(false);
    try {
      await action();
      setSaved(true);
      await reload();
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
    } finally {
      setBusy(false);
    }
  };
  const validCrawler =
    ua.trim().length > 0 &&
    ua.trim().length <= 256 &&
    domain.trim().length > 0 &&
    domain.trim().length <= 253 &&
    !/\s/.test(domain);
  return (
    <Card data-testid="bot-protection-section">
      <h2 className="mb-2 text-xl font-semibold">{t("bot.title")}</h2>
      <p className="mb-4 text-sm text-muted">{t("bot.description")}</p>
      {error && <Alert variant="danger">{error}</Alert>}
      {saved && <Alert variant="success">{t("bot.saved")}</Alert>}
      <form
        className="grid gap-4 sm:grid-cols-3"
        onSubmit={(e) => {
          e.preventDefault();
          if (!config || !threshold || !ttl) return;
          void run(() =>
            api.updateBotConfig({
              mode,
              threshold: Number(threshold),
              ttl_seconds: Number(ttl),
            }),
          );
        }}
      >
        <SelectField
          label={t("common.mode")}
          value={mode}
          onChange={(e) => setMode(e.target.value as BotMode)}
          disabled={busy}
        >
          <option value="monitor">{t("common.monitorOnly")}</option>
          <option value="challenge">{t("bot.challenge")}</option>
          <option value="block">{t("common.block")}</option>
        </SelectField>
        <Field
          label={t("bot.riskThreshold")}
          type="number"
          min="0"
          max="100"
          value={threshold}
          onChange={(e) => setThreshold(e.target.value)}
          disabled={busy}
          required
        />
        <Field
          label={t("bot.challengeTtl")}
          type="number"
          min="30"
          max="86400"
          value={ttl}
          onChange={(e) => setTtl(e.target.value)}
          disabled={busy}
          required
        />
        <Button type="submit" disabled={busy || !threshold || !ttl}>
          {t("bot.savePolicy")}
        </Button>
      </form>
      <div className="mt-6">
        <h3 className="mb-3 font-semibold">{t("bot.trustedCrawlers")}</h3>
        <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead>
              <tr>
                <th>{t("bot.userAgent")}</th>
                <th>{t("common.domain")}</th>
                <th>{t("common.status")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {crawlers.map((crawler) => (
                <tr key={crawler.id}>
                  <td>
                    {crawler.trusted_user_agent ?? t("common.notAvailable")}
                  </td>
                  <td>{crawler.trusted_domain ?? t("common.notAvailable")}</td>
                  <td>
                    {crawler.enabled
                      ? t("common.enabled")
                      : t("common.disabled")}
                  </td>
                  <td>
                    <Button
                      variant="secondary"
                      disabled={busy}
                      onClick={() =>
                        void run(() =>
                          api.updateTrustedCrawler(crawler.id, {
                            user_agent: crawler.trusted_user_agent ?? "",
                            domain: crawler.trusted_domain ?? "",
                            enabled: !crawler.enabled,
                          }),
                        )
                      }
                    >
                      {crawler.enabled
                        ? t("common.disable")
                        : t("common.enable")}
                    </Button>{" "}
                    <Button
                      variant="danger"
                      disabled={busy}
                      onClick={() =>
                        void run(() => api.deleteTrustedCrawler(crawler.id))
                      }
                    >
                      {t("common.delete")}
                    </Button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <form
          className="mt-4 grid gap-4 sm:grid-cols-2"
          onSubmit={(e) => {
            e.preventDefault();
            if (!validCrawler) return;
            void run(async () => {
              await api.createTrustedCrawler({
                user_agent: ua.trim(),
                domain: domain.trim(),
                enabled: true,
              });
              setUa("");
              setDomain("");
            });
          }}
        >
          <Field
            label={t("bot.crawlerUserAgent")}
            value={ua}
            onChange={(e) => setUa(e.target.value)}
            maxLength={256}
            required
          />
          <Field
            label={t("bot.crawlerDomain")}
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            maxLength={253}
            placeholder={t("bot.crawlerDomainPlaceholder")}
            required
          />
          <Button type="submit" disabled={busy || !validCrawler}>
            {t("bot.addCrawler")}
          </Button>
        </form>
      </div>
    </Card>
  );
}

export function RateLimitSection({
  user,
  refreshToken = 0,
}: {
  user: User;
  refreshToken?: number;
}) {
  const { t } = useTranslation();
  const [config, setConfig] = useState<RateLimitConfig | null>(null);
  const [error, setError] = useState(""),
    [busy, setBusy] = useState(false),
    [saved, setSaved] = useState(false);
  const [enabled, setEnabled] = useState(false),
    [action, setAction] = useState<RateLimitAction>("monitor"),
    [capacity, setCapacity] = useState("100"),
    [refill, setRefill] = useState("10");
  const admin = user.role === "admin";
  const reload = async () => {
    try {
      const next = await api.rateLimitConfig();
      setConfig(next);
      setEnabled(next.enabled);
      setAction(next.action);
      setCapacity(String(next.capacity));
      setRefill(String(next.refill_per_second));
      setError("");
    } catch (e) {
      setError(t("errors.rateLimitLoad"));
    }
  };
  useEffect(() => {
    void reload();
  }, [refreshToken]);
  const save = async (event: FormEvent) => {
    event.preventDefault();
    if (!admin) return;
    const c = Number(capacity),
      r = Number(refill);
    if (
      !Number.isInteger(c) ||
      c < 1 ||
      c > 1_000_000 ||
      !Number.isFinite(r) ||
      r < 0.001 ||
      r > 100_000
    ) {
      setError(t("errors.rateLimitValidation"));
      return;
    }
    setBusy(true);
    setError("");
    setSaved(false);
    try {
      const next = await api.updateRateLimitConfig({
        enabled,
        action,
        capacity: c,
        refill_per_second: r,
        key_scope: "proxy_host_ip",
      });
      setConfig(next);
      setSaved(true);
    } catch {
      setError(t("errors.rateLimitSave"));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Card data-testid="rate-limit-section">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="mr-auto text-xl font-semibold">
          {t("rateLimit.title")}
        </h2>
        <span className="rounded-full border border-border px-3 py-1 text-sm">
          {config?.action === "block"
            ? t("common.block")
            : t("common.monitorOnly")}
        </span>
      </div>
      <p className="mt-2 text-sm text-muted">{t("rateLimit.description")}</p>
      {error && <Alert variant="danger">{error}</Alert>}
      {saved && <Alert variant="success">{t("rateLimit.saved")}</Alert>}
      <form
        className="mt-4 grid gap-4 sm:grid-cols-2"
        onSubmit={(e) => void save(e)}
      >
        <label className="flex min-h-11 items-center gap-3 text-sm font-medium">
          <input
            aria-label={t("rateLimit.enable")}
            type="checkbox"
            checked={enabled}
            onChange={(e) => setEnabled(e.target.checked)}
            disabled={!admin || busy}
          />
          {t("rateLimit.enable")}
        </label>
        <SelectField
          label={t("common.action")}
          value={action}
          onChange={(e) => setAction(e.target.value as RateLimitAction)}
          disabled={!admin || busy}
        >
          <option value="monitor">{t("common.monitorOnly")}</option>
          <option value="block">{t("rateLimit.blockLimited")}</option>
        </SelectField>
        <Field
          label={t("rateLimit.burstCapacity")}
          type="number"
          min="1"
          max="1000000"
          value={capacity}
          onChange={(e) => setCapacity(e.target.value)}
          disabled={!admin || busy}
          required
        />
        <Field
          label={t("rateLimit.refill")}
          type="number"
          min="0.001"
          max="100000"
          step="0.001"
          value={refill}
          onChange={(e) => setRefill(e.target.value)}
          disabled={!admin || busy}
          required
        />
        <SelectField
          label={t("rateLimit.keyScope")}
          value="proxy_host_ip"
          disabled
        >
          <option value="proxy_host_ip">{t("rateLimit.scopeValue")}</option>
        </SelectField>
        {admin && (
          <Button type="submit" disabled={busy}>
            {busy ? t("rateLimit.saving") : t("rateLimit.savePolicy")}
          </Button>
        )}
      </form>
    </Card>
  );
}

export function AnalyticsSection({
  hosts,
  refreshToken = 0,
}: {
  hosts: Host[];
  refreshToken?: number;
}) {
  const { t } = useTranslation();
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [rows, setRows] = useState<AnalyticsBucket[]>([]);
  const [host, setHost] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const autoSelectedHost = useRef(false);
  const query = () => ({
    ...(host ? { proxy_host_id: Number(host) } : {}),
    ...(from ? { from: new Date(from).toISOString() } : {}),
    ...(to ? { to: new Date(to).toISOString() } : {}),
    limit: 1440,
  });
  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const q = query();
      const [s, t] = await Promise.all([
        api.getAnalyticsSummary(q),
        api.getAnalyticsTimeseries(q),
      ]);
      setSummary(s);
      setRows(t);
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
      setSummary(null);
      setRows([]);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    if (hosts.length === 0) return;
    if (!autoSelectedHost.current) {
      autoSelectedHost.current = true;
      setHost(String(hosts[0].id));
      return;
    }
    if (host && !hosts.some((candidate) => String(candidate.id) === host))
      setHost(String(hosts[0].id));
  }, [hosts]);
  useEffect(() => {
    const timer = setTimeout(() => void load(), 150);
    return () => clearTimeout(timer);
  }, [refreshToken, host, from, to]);
  const cards = summary
    ? [
        [t("analytics.requests"), summary.requests],
        [t("analytics.status2xx"), summary.status_2xx],
        [t("analytics.status4xx"), summary.status_4xx],
        [t("analytics.status5xx"), summary.status_5xx],
        [
          t("analytics.p95Latency"),
          summary.p95_ms == null
            ? t("common.notAvailable")
            : t("analytics.milliseconds", { value: summary.p95_ms }),
        ],
        [
          t("analytics.securityEvents"),
          summary.waf_blocks +
            summary.bot_blocks +
            summary.bot_challenges +
            summary.rate_limited,
        ],
      ]
    : [];
  const latency = summary
    ? ([
        [t("analytics.p50"), summary.p50_ms],
        [t("analytics.p95"), summary.p95_ms],
        [t("analytics.p99"), summary.p99_ms],
      ] as const)
    : [];
  const latencyMax = Math.max(...latency.map(([, value]) => value ?? 0), 1);
  return (
    <Card data-testid="analytics-section">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="mr-auto text-xl font-semibold">
          {t("analytics.title")}
        </h2>
        <span className="text-sm text-muted">{t("analytics.description")}</span>
      </div>
      <div
        className="mt-4 grid gap-4 sm:grid-cols-3"
        role="group"
        aria-label={t("analytics.filters")}
      >
        <SelectField
          id="analytics-proxy-host"
          label={t("common.proxyHost")}
          value={host}
          onChange={(e) => setHost(e.target.value)}
        >
          <option value="">{t("common.allHosts")}</option>
          {hosts.slice(0, 100).map((h) => (
            <option key={h.id} value={h.id}>
              {h.name} ({h.domain})
            </option>
          ))}
        </SelectField>
        <Field
          label={t("common.from")}
          type="datetime-local"
          value={from}
          onChange={(e) => setFrom(e.target.value)}
        />
        <Field
          label={t("common.to")}
          type="datetime-local"
          value={to}
          onChange={(e) => setTo(e.target.value)}
        />
      </div>
      {loading && (
        <p role="status" className="mt-4 text-muted">
          {t("analytics.loading")}
        </p>
      )}
      {!loading && error && <Alert variant="danger">{error}</Alert>}
      {!loading && !error && summary && summary.requests === 0 && (
        <p className="mt-4 text-muted">{t("analytics.empty")}</p>
      )}
      {!loading && !error && summary && summary.requests > 0 && (
        <>
          <div className="mt-5 grid gap-3 sm:grid-cols-3 lg:grid-cols-6">
            {cards.map(([label, value]) => (
              <div key={label} className="rounded border border-border p-3">
                <div className="text-xs text-muted">{label}</div>
                <div className="text-xl font-semibold">{value}</div>
              </div>
            ))}
          </div>
          <div className="mt-6 grid gap-4 lg:grid-cols-2">
            <section
              className="rounded border border-border p-4"
              aria-labelledby="analytics-latency-heading"
            >
              <h3 id="analytics-latency-heading" className="mb-3 font-semibold">
                {t("analytics.latencyPercentiles")}
              </h3>
              <div
                className="space-y-3"
                role="group"
                aria-label={t("analytics.requestLatencyPercentiles")}
              >
                {latency.map(([label, value]) => {
                  const width =
                    value == null
                      ? 0
                      : Math.max(4, Math.round((value / latencyMax) * 100));
                  return (
                    <div key={label}>
                      <div className="mb-1 flex items-center justify-between text-sm">
                        <span>{label}</span>
                        <span>
                          {value == null
                            ? t("common.notAvailable")
                            : t("analytics.milliseconds", { value })}
                        </span>
                      </div>
                      <div
                        className="h-2 rounded bg-muted/20"
                        role="progressbar"
                        aria-label={t("analytics.latency", { label })}
                        aria-valuemin={0}
                        aria-valuemax={latencyMax}
                        aria-valuenow={value ?? 0}
                      >
                        <div
                          className="h-2 rounded bg-accent"
                          style={{ width: `${width}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </section>
            <section
              className="rounded border border-border p-4"
              aria-labelledby="analytics-security-heading"
            >
              <h3
                id="analytics-security-heading"
                className="mb-3 font-semibold"
              >
                {t("analytics.securityEvents")}
              </h3>
              <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
                {[
                  [t("analytics.wafBlocks"), summary.waf_blocks],
                  [t("analytics.botBlocks"), summary.bot_blocks],
                  [t("analytics.botChallenges"), summary.bot_challenges],
                  [t("analytics.rateLimited"), summary.rate_limited],
                ].map(([label, value]) => (
                  <div key={label} className="rounded border border-border p-3">
                    <dt className="text-xs text-muted">{label}</dt>
                    <dd className="text-xl font-semibold">{value}</dd>
                  </div>
                ))}
              </dl>
            </section>
          </div>
          <div className="mt-6 overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <caption className="sr-only">{t("analytics.byMinute")}</caption>
              <thead>
                <tr>
                  <th>{t("analytics.time")}</th>
                  <th>{t("analytics.host")}</th>
                  <th>{t("analytics.requests")}</th>
                  <th>{t("analytics.p50")}</th>
                  <th>{t("analytics.p95")}</th>
                  <th>{t("analytics.errors")}</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={`${row.timestamp}-${row.proxy_host_id}`}>
                    <td>{new Date(row.timestamp).toLocaleString()}</td>
                    <td>
                      {hosts.find((h) => h.id === row.proxy_host_id)?.name ??
                        row.proxy_host_id}
                    </td>
                    <td>{row.requests}</td>
                    <td>
                      {row.p50_ms == null
                        ? t("common.notAvailable")
                        : t("analytics.milliseconds", { value: row.p50_ms })}
                    </td>
                    <td>
                      {row.p95_ms == null
                        ? t("common.notAvailable")
                        : t("analytics.milliseconds", { value: row.p95_ms })}
                    </td>
                    <td>{row.status_4xx + row.status_5xx}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}
    </Card>
  );
}

export function BaselineSection({
  hosts,
  refreshToken = 0,
}: {
  hosts: Host[];
  refreshToken?: number;
}) {
  const { t } = useTranslation();
  const [snapshot, setSnapshot] = useState<BaselineSnapshot | null>(null);
  const [host, setHost] = useState("");
  const [window, setWindow] = useState<BaselineWindow>("5m");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const autoSelectedHost = useRef(false);

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const snap = await api.getBaseline({
        ...(host ? { proxy_host_id: Number(host) } : {}),
        window,
      });
      setSnapshot(snap);
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
      setSnapshot(null);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (hosts.length === 0) return;
    if (!autoSelectedHost.current) {
      autoSelectedHost.current = true;
      setHost(String(hosts[0].id));
      return;
    }
    if (host && !hosts.some((candidate) => String(candidate.id) === host))
      setHost(String(hosts[0].id));
  }, [hosts]);

  useEffect(() => {
    void load();
  }, [refreshToken, host, window]);

  return (
    <Card data-testid="baseline-section">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="mr-auto text-xl font-semibold">{t("baseline.title")}</h2>
        {snapshot?.status === "warming_up" ? (
          <span className="rounded-full bg-amber-500/20 px-3 py-1 text-xs text-amber-500 font-medium">
            {t("baseline.warming")}
          </span>
        ) : (
          <span className="rounded-full bg-emerald-500/20 px-3 py-1 text-xs text-emerald-500 font-medium">
            {t("baseline.ready")}
          </span>
        )}
      </div>
      <p className="mt-2 text-sm text-muted">{t("baseline.description")}</p>
      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <SelectField
          id="baseline-proxy-host"
          label={t("common.proxyHost")}
          value={host}
          onChange={(e) => setHost(e.target.value)}
        >
          <option value="">{t("common.allHosts")}</option>
          {hosts.slice(0, 100).map((h) => (
            <option key={h.id} value={h.id}>
              {h.name} ({h.domain})
            </option>
          ))}
        </SelectField>
        <SelectField
          id="baseline-window"
          label={t("baseline.window")}
          value={window}
          onChange={(e) => setWindow(e.target.value as BaselineWindow)}
        >
          <option value="5m">{t("baseline.fiveMinutes")}</option>
          <option value="1h">{t("baseline.oneHour")}</option>
          <option value="24h">{t("baseline.twentyFourHours")}</option>
        </SelectField>
      </div>
      {loading && (
        <p role="status" className="mt-4 text-muted">
          {t("baseline.loading")}
        </p>
      )}
      {!loading && error && <Alert variant="danger">{error}</Alert>}
      {!loading && !error && snapshot && (
        <div className="mt-5 grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted">{t("baseline.reqPerSec")}</div>
            <div className="text-xl font-semibold">
              {snapshot.metrics.req_per_sec.toFixed(2)}
            </div>
          </div>
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted">{t("baseline.errorRate")}</div>
            <div className="text-xl font-semibold">
              {snapshot.metrics.error_rate_percent.toFixed(1)}%
            </div>
          </div>
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted">{t("baseline.p50Latency")}</div>
            <div className="text-xl font-semibold">
              {snapshot.metrics.p50_ms == null
                ? t("common.notAvailable")
                : t("analytics.milliseconds", {
                    value: snapshot.metrics.p50_ms,
                  })}
            </div>
          </div>
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted">{t("baseline.p95Latency")}</div>
            <div className="text-xl font-semibold">
              {snapshot.metrics.p95_ms == null
                ? t("common.notAvailable")
                : t("analytics.milliseconds", {
                    value: snapshot.metrics.p95_ms,
                  })}
            </div>
          </div>
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted">
              {t("baseline.securityBlocks")}
            </div>
            <div className="text-xl font-semibold">
              {snapshot.metrics.waf_blocks +
                snapshot.metrics.bot_blocks +
                snapshot.metrics.bot_challenges +
                snapshot.metrics.rate_limited}
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}

export function AnomalySection({
  user,
  hosts,
  refreshToken = 0,
}: {
  user: User;
  hosts: Host[];
  refreshToken?: number;
}) {
  const { t } = useTranslation();
  const [anomalies, setAnomalies] = useState<AnomalyRecord[]>([]);
  const [host, setHost] = useState("");
  const [severity, setSeverity] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const autoSelectedHost = useRef(false);
  const canAck = user.role === "admin" || user.role === "operator";

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const records = await api.getAnomalies({
        ...(host ? { host_id: Number(host) } : {}),
        ...(severity ? { severity } : {}),
      });
      setAnomalies(records);
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
      setAnomalies([]);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (hosts.length === 0) return;
    if (!autoSelectedHost.current) {
      autoSelectedHost.current = true;
      setHost(String(hosts[0].id));
      return;
    }
    if (host && !hosts.some((candidate) => String(candidate.id) === host))
      setHost(String(hosts[0].id));
  }, [hosts]);

  useEffect(() => {
    void load();
  }, [refreshToken, host, severity]);

  const ack = async (id: number) => {
    try {
      await api.ackAnomaly(id);
      void load();
    } catch {
      setError(t("errors.anomalyAcknowledge"));
    }
  };

  return (
    <Card data-testid="anomaly-section">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="mr-auto text-xl font-semibold">{t("anomaly.title")}</h2>
        <span className="rounded-full border border-border px-3 py-1 text-xs text-muted">
          {t("common.monitorOnly")}
        </span>
      </div>
      <p className="mt-2 text-sm text-muted">{t("anomaly.description")}</p>
      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <SelectField
          id="anomaly-proxy-host"
          label={t("common.proxyHost")}
          value={host}
          onChange={(e) => setHost(e.target.value)}
        >
          <option value="">{t("common.allHosts")}</option>
          {hosts.slice(0, 100).map((h) => (
            <option key={h.id} value={h.id}>
              {h.name} ({h.domain})
            </option>
          ))}
        </SelectField>
        <SelectField
          id="anomaly-severity"
          label={t("waf.severity")}
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
        >
          <option value="">{t("anomaly.allSeverities")}</option>
          <option value="info">{t("anomaly.info")}</option>
          <option value="warning">{t("anomaly.warning")}</option>
          <option value="critical">{t("anomaly.critical")}</option>
        </SelectField>
      </div>
      {loading && (
        <p role="status" className="mt-4 text-muted">
          {t("anomaly.loading")}
        </p>
      )}
      {!loading && error && <Alert variant="danger">{error}</Alert>}
      {!loading && !error && anomalies.length === 0 && (
        <p className="mt-4 text-muted">{t("anomaly.empty")}</p>
      )}
      {!loading && !error && anomalies.length > 0 && (
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <caption>{t("anomaly.table")}</caption>
            <thead>
              <tr>
                <th>{t("anomaly.observed")}</th>
                <th>{t("analytics.host")}</th>
                <th>{t("anomaly.rule")}</th>
                <th>{t("waf.severity")}</th>
                <th>{t("anomaly.score")}</th>
                <th>{t("anomaly.summary")}</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {anomalies.map((item) => (
                <tr key={item.id}>
                  <td>{new Date(item.observed_at).toLocaleString()}</td>
                  <td>
                    {hosts.find((h) => h.id === item.host_id)?.name ??
                      item.host_id}
                  </td>
                  <td className="capitalize">
                    {t(`anomaly.rules.${item.rule}`)}
                  </td>
                  <td>
                    <span
                      className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${
                        item.severity === "critical"
                          ? "bg-rose-500/20 text-rose-500"
                          : item.severity === "warning"
                            ? "bg-amber-500/20 text-amber-500"
                            : "bg-blue-500/20 text-blue-500"
                      }`}
                    >
                      {t(`anomaly.${item.severity}`)}
                    </span>
                  </td>
                  <td>{item.score.toFixed(2)}</td>
                  <td>{item.summary}</td>
                  <td>
                    {canAck && !item.acknowledged && (
                      <Button
                        variant="secondary"
                        onClick={() => void ack(item.id)}
                      >
                        {t("anomaly.acknowledge")}
                      </Button>
                    )}
                    {item.acknowledged && (
                      <span className="text-xs text-muted">
                        {t("anomaly.acknowledged")}
                      </span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </Card>
  );
}

export function AdaptiveTuningSection({
  user,
  hosts,
  refreshToken = 0,
}: {
  user: User;
  hosts: Host[];
  refreshToken?: number;
}) {
  const { t } = useTranslation();
  const [selectedHost, setSelectedHost] = useState("");
  const [policy, setPolicy] = useState<TuningPolicy>({
    mode: "monitor",
    max_delta_percent: 50,
    cooldown_seconds: 300,
    min_confidence: 0.8,
  });
  const [recommendations, setRecommendations] = useState<
    PolicyRecommendation[]
  >([]);
  const [emergencyDisabled, setEmergencyDisabled] = useState(false);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState("");
  const [success, setSuccess] = useState("");
  const isAdmin = user.role === "admin";

  const load = async () => {
    setLoading(true);
    setError("");
    try {
      const hostId = selectedHost ? Number(selectedHost) : (hosts[0]?.id ?? 1);
      const [p, recs] = await Promise.all([
        api.getTuningPolicy(hostId),
        api.getRecommendations(),
      ]);
      setPolicy(p);
      setRecommendations(recs);
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (hosts.length > 0 && !selectedHost) {
      setSelectedHost(String(hosts[0].id));
    }
  }, [hosts]);

  useEffect(() => {
    void load();
  }, [refreshToken, selectedHost]);

  const savePolicy = async (e: FormEvent) => {
    e.preventDefault();
    if (!isAdmin) return;
    setSaving(true);
    setError("");
    setSuccess("");
    try {
      const hostId = selectedHost ? Number(selectedHost) : 1;
      const updated = await api.updateTuningPolicy(hostId, policy);
      setPolicy(updated);
      setSuccess(t("tuning.saved"));
    } catch {
      setError(t("errors.tuningSave"));
    } finally {
      setSaving(false);
    }
  };

  const applyRec = async (id: number) => {
    if (!isAdmin) return;
    try {
      await api.applyRecommendation(id);
      void load();
    } catch {
      setError(t("errors.tuningApply"));
    }
  };

  const rollbackRec = async (id: number) => {
    if (!isAdmin) return;
    try {
      await api.rollbackRecommendation(id);
      void load();
    } catch {
      setError(t("errors.tuningRollback"));
    }
  };

  const toggleEmergency = async () => {
    if (!isAdmin) return;
    try {
      const res = await api.emergencyDisableTuning();
      setEmergencyDisabled(res.emergency_disabled);
      void load();
    } catch {
      setError(t("errors.tuningEmergency"));
    }
  };

  return (
    <Card data-testid="adaptive-tuning-section">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="mr-auto text-xl font-semibold">{t("tuning.title")}</h2>
        <span
          className={`rounded-full px-3 py-1 text-xs font-medium ${
            emergencyDisabled
              ? "bg-rose-500/20 text-rose-500"
              : policy.mode === "enforce"
                ? "bg-emerald-500/20 text-emerald-500"
                : policy.mode === "recommend"
                  ? "bg-blue-500/20 text-blue-500"
                  : "bg-amber-500/20 text-amber-500"
          }`}
        >
          {emergencyDisabled
            ? t("tuning.emergencyDisabled")
            : policy.mode === "enforce"
              ? t("tuning.enforceActive")
              : policy.mode === "recommend"
                ? t("tuning.recommendationsOnly")
                : t("tuning.monitorDefault")}
        </span>
      </div>
      <p className="mt-2 text-sm text-muted">{t("tuning.description")}</p>

      {error && <Alert variant="danger">{error}</Alert>}
      {success && <Alert variant="success">{success}</Alert>}

      <form
        className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4"
        onSubmit={(e) => void savePolicy(e)}
      >
        <SelectField
          id="tuning-proxy-host"
          label={t("common.proxyHost")}
          value={selectedHost}
          onChange={(e) => setSelectedHost(e.target.value)}
        >
          {hosts.slice(0, 100).map((h) => (
            <option key={h.id} value={h.id}>
              {h.name} ({h.domain})
            </option>
          ))}
        </SelectField>

        <SelectField
          label={t("common.mode")}
          value={policy.mode}
          onChange={(e) =>
            setPolicy({ ...policy, mode: e.target.value as TuningMode })
          }
          disabled={!isAdmin || saving}
        >
          <option value="monitor">{t("common.monitorOnly")}</option>
          <option value="recommend">{t("tuning.recommend")}</option>
          <option value="enforce">{t("tuning.enforce")}</option>
        </SelectField>

        <Field
          label={t("tuning.maxDelta")}
          type="number"
          min="1"
          max="100"
          value={String(policy.max_delta_percent)}
          onChange={(e) =>
            setPolicy({ ...policy, max_delta_percent: Number(e.target.value) })
          }
          disabled={!isAdmin || saving}
          required
        />

        <Field
          label={t("tuning.minConfidence")}
          type="number"
          min="0.1"
          max="1.0"
          step="0.05"
          value={String(policy.min_confidence)}
          onChange={(e) =>
            setPolicy({ ...policy, min_confidence: Number(e.target.value) })
          }
          disabled={!isAdmin || saving}
          required
        />

        {isAdmin && (
          <div className="col-span-full flex gap-3">
            <Button type="submit" disabled={saving}>
              {saving ? t("tuning.saving") : t("tuning.save")}
            </Button>
            <Button
              type="button"
              variant={emergencyDisabled ? "secondary" : "danger"}
              onClick={() => void toggleEmergency()}
            >
              {emergencyDisabled
                ? t("tuning.enable")
                : t("tuning.emergencyDisable")}
            </Button>
          </div>
        )}
      </form>

      <div className="mt-6 border-t border-border pt-4">
        <h3 className="text-lg font-semibold mb-2">
          {t("tuning.recommendations")}
        </h3>
        {loading && (
          <p role="status" className="text-muted">
            {t("tuning.loading")}
          </p>
        )}
        {!loading && recommendations.length === 0 && (
          <p className="text-muted text-sm">{t("tuning.empty")}</p>
        )}
        {!loading && recommendations.length > 0 && (
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <caption>{t("tuning.table")}</caption>
              <thead>
                <tr>
                  <th>{t("common.created")}</th>
                  <th>{t("tuning.hostId")}</th>
                  <th>{t("tuning.confidence")}</th>
                  <th>{t("tuning.reason")}</th>
                  <th>{t("common.status")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {recommendations.map((rec) => (
                  <tr key={rec.id}>
                    <td>{new Date(rec.created_at).toLocaleString()}</td>
                    <td>{rec.host_id}</td>
                    <td>{(rec.confidence * 100).toFixed(0)}%</td>
                    <td>{rec.reason}</td>
                    <td>
                      {rec.applied ? (
                        <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-500">
                          {t("tuning.applied")}
                        </span>
                      ) : (
                        <span className="rounded bg-amber-500/20 px-2 py-0.5 text-xs text-amber-500">
                          {t("tuning.pending")}
                        </span>
                      )}
                    </td>
                    <td>
                      {isAdmin && !rec.applied && (
                        <Button
                          variant="secondary"
                          onClick={() => void applyRec(rec.id)}
                        >
                          {t("tuning.apply")}
                        </Button>
                      )}
                      {isAdmin && rec.applied && (
                        <Button
                          variant="danger"
                          onClick={() => void rollbackRec(rec.id)}
                        >
                          {t("tuning.rollback")}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </Card>
  );
}

export function BotChallengePage({
  fingerprint = serverChallengeFingerprint(),
  onComplete,
}: {
  fingerprint?: string;
  onComplete?: () => void;
}) {
  const { t } = useTranslation();
  const [challenge, setChallenge] = useState<BotChallenge | null>(null),
    [busy, setBusy] = useState(false),
    [error, setError] = useState(""),
    [complete, setComplete] = useState(false);
  const requestChallenge = async () => {
    if (!fingerprint) {
      setError(t("errors.challengeContext"));
      return;
    }
    setBusy(true);
    setError("");
    setComplete(false);
    try {
      setChallenge(await api.botChallenge(fingerprint));
    } catch {
      setError(t("errors.challengeUnavailable"));
    } finally {
      setBusy(false);
    }
  };
  useEffect(() => {
    void requestChallenge();
  }, [fingerprint]);
  const verify = async () => {
    if (!challenge) return;
    setBusy(true);
    setError("");
    try {
      const solution = await solveBotChallenge(challenge, fingerprint);
      await api.verifyBotChallenge({
        token: challenge.token,
        fingerprint,
        solution,
      });
      setComplete(true);
      onComplete?.();
    } catch {
      setError(t("errors.challengeVerification"));
    } finally {
      setBusy(false);
    }
  };
  return (
    <main className="min-h-screen bg-page px-4 py-8 text-foreground">
      <Card className="mx-auto max-w-lg">
        <h1 className="mb-2 text-2xl font-semibold">{t("bot.quickCheck")}</h1>
        <p className="mb-6 text-muted">{t("bot.quickCheckDescription")}</p>
        {error && <Alert variant="danger">{error}</Alert>}
        {complete ? (
          <Alert variant="success">{t("bot.verificationComplete")}</Alert>
        ) : (
          <Button disabled={busy || !challenge} onClick={() => void verify()}>
            {busy ? t("bot.verifying") : t("bot.verifyBrowser")}
          </Button>
        )}
        <Button
          className="ml-2"
          variant="secondary"
          disabled={busy}
          onClick={() => void requestChallenge()}
        >
          {t("bot.anotherChallenge")}
        </Button>
      </Card>
    </main>
  );
}

function Dashboard({
  user,
  onLogout,
  onUserRefresh,
}: {
  user: User;
  onLogout: () => void;
  onUserRefresh: (user: User) => void;
}) {
  const { locale, setLocale } = useLocalePreference();
  const { t } = useTranslation();
  const [hosts, setHosts] = useState<Host[]>([]),
    [certs, setCerts] = useState<Certificate[]>([]),
    [users, setUsers] = useState<User[]>([]),
    [roles, setRoles] = useState<RoleRecord[]>([]),
    [error, setError] = useState(""),
    [usersError, setUsersError] = useState("");
  const [wafRefresh, setWafRefresh] = useState(0);
  const [analyticsRefresh, setAnalyticsRefresh] = useState(0);
  const [baselineRefresh, setBaselineRefresh] = useState(0);
  const [anomalyRefresh, setAnomalyRefresh] = useState(0);
  const [adaptiveTuningRefresh, setAdaptiveTuningRefresh] = useState(0);
  const [form, setForm] = useState({
    name: "",
    domain: "",
    upstream_host: "",
    upstream_port: 80,
    tls_mode: "disabled",
    certificate_id: null as number | null,
  });
  const auditReloadRef = useRef<(() => void) | null>(null);
  const canWrite = user.role !== "viewer";
  const loadHosts = async () => {
    try {
      setHosts(await api.hosts());
      setError("");
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
    }
  };
  const loadCertificates = async () => {
    try {
      setCerts(await api.certificates());
      setError("");
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
    }
  };
  const loadUsers = async () => {
    if (user.role !== "admin") return;
    try {
      setUsers(await api.users());
      setUsersError("");
    } catch (e) {
      setUsersError(userError(e));
    }
  };
  const loadRoles = async () => {
    if (user.role !== "admin") return;
    try {
      setRoles(await api.roles());
      setUsersError("");
    } catch (e) {
      setUsersError(userError(e));
    }
  };
  const loadSession = async () => {
    try {
      onUserRefresh(await api.me());
    } catch (e) {
      if ((e as Error & { status?: number }).status === 401) onLogout();
    }
  };
  const realtimeStatus: RealtimeStatus = useRealtimeUpdates({
    hosts: loadHosts,
    certificates: loadCertificates,
    users: loadUsers,
    roles: loadRoles,
    auditLogs: () => auditReloadRef.current?.(),
    sessions: loadSession,
    waf: () => setWafRefresh((value) => value + 1),
    rateLimit: () => setWafRefresh((value) => value + 1),
    analytics: () => setAnalyticsRefresh((value) => value + 1),
    baseline: () => setBaselineRefresh((value) => value + 1),
    anomaly: () => setAnomalyRefresh((value) => value + 1),
    adaptiveTuning: () => setAdaptiveTuningRefresh((value) => value + 1),
  });
  const refresh = async () => {
    try {
      const [h, c] = await Promise.all([api.hosts(), api.certificates()]);
      setHosts(h);
      setCerts(c);
      setError("");
    } catch (e) {
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
      return;
    }
    if (user.role === "admin") {
      try {
        setUsers(await api.users());
        setRoles(await api.roles());
        setUsersError("");
      } catch (e) {
        setUsersError(userError(e));
      }
    }
  };
  useEffect(() => {
    void refresh();
  }, []);
  return (
    <main className="min-h-screen bg-page px-4 py-6 text-foreground sm:px-6 lg:px-8">
      <header className="mx-auto mb-6 flex max-w-7xl flex-wrap items-center gap-4 border-b border-border pb-4">
        <h1 className="mr-auto text-2xl font-bold text-brand">
          {t("dashboard.brand")}
        </h1>
        <span className="text-sm text-muted">
          {user.email} ({user.role})
        </span>
        <LanguageSelect
          value={locale}
          onChange={(nextLocale) => void setLocale(nextLocale)}
        />
        <ThemeSelect />
        <Button variant="secondary" onClick={onLogout}>
          {t("auth.signOut")}
        </Button>
        <span
          className="text-sm text-muted"
          aria-label={t("dashboard.realtimeStatus")}
        >
          {t("dashboard.realtime", { status: realtimeStatus })}
        </span>
      </header>
      <div className="mx-auto grid max-w-7xl gap-6">
        {error && <Alert variant="danger">{error}</Alert>}
        <CertificateTable user={user} onChanged={() => void refresh()} />
        <WafSection user={user} refreshToken={wafRefresh} />
        <BotProtectionSection user={user} refreshToken={wafRefresh} />
        <RateLimitSection user={user} refreshToken={wafRefresh} />
        <AnalyticsSection hosts={hosts} refreshToken={analyticsRefresh} />
        <BaselineSection hosts={hosts} refreshToken={baselineRefresh} />
        <AnomalySection
          user={user}
          hosts={hosts}
          refreshToken={anomalyRefresh}
        />
        <AdaptiveTuningSection
          user={user}
          hosts={hosts}
          refreshToken={adaptiveTuningRefresh}
        />
        {canWrite && (
          <AcmeWizard canWrite={canWrite} onIssued={() => void refresh()} />
        )}
        <Card>
          <h2 className="mb-4 text-xl font-semibold">
            {t("proxyHosts.title")}
          </h2>
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <thead>
                <tr>
                  <th>{t("common.name")}</th>
                  <th>{t("common.domain")}</th>
                  <th>{t("proxyHosts.upstream")}</th>
                  <th>{t("proxyHosts.tls")}</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {hosts.map((h) => (
                  <tr key={h.id}>
                    <td>{h.name}</td>
                    <td>{h.domain}</td>
                    <td>
                      {h.upstream_host}:{h.upstream_port}
                    </td>
                    <td>{h.tls_mode}</td>
                    <td>
                      {canWrite && (
                        <Button
                          variant="danger"
                          onClick={() => api.deleteHost(h.id).then(refresh)}
                        >
                          {t("common.delete")}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {canWrite && (
            <form
              className="mt-6 grid gap-4 sm:grid-cols-2"
              onSubmit={async (e) => {
                e.preventDefault();
                try {
                  await api.createHost(form);
                  setForm({
                    ...form,
                    name: "",
                    domain: "",
                    upstream_host: "",
                    certificate_id: null,
                  });
                  void refresh();
                } catch (x) {
                  setError(sanitizeError((x as Error).message));
                }
              }}
            >
              <h3>{t("proxyHosts.add")}</h3>
              <Field
                label={t("common.name")}
                value={form.name}
                onChange={(e: any) =>
                  setForm({ ...form, name: e.target.value })
                }
              />
              <Field
                label={t("common.domain")}
                value={form.domain}
                onChange={(e: any) =>
                  setForm({ ...form, domain: e.target.value })
                }
              />
              <Field
                label={t("proxyHosts.upstreamHost")}
                value={form.upstream_host}
                onChange={(e: any) =>
                  setForm({ ...form, upstream_host: e.target.value })
                }
              />
              <Field
                label={t("proxyHosts.port")}
                type="number"
                min="1"
                max="65535"
                value={form.upstream_port}
                onChange={(e: any) =>
                  setForm({ ...form, upstream_port: Number(e.target.value) })
                }
              />
              <SelectField
                label={t("proxyHosts.tlsMode")}
                value={form.tls_mode}
                onChange={(e) =>
                  setForm({
                    ...form,
                    tls_mode: e.target.value,
                    certificate_id:
                      e.target.value === "disabled"
                        ? null
                        : form.certificate_id,
                  })
                }
              >
                <option value="disabled">{t("proxyHosts.tlsDisabled")}</option>
                <option value="http">{t("proxyHosts.http")}</option>
                <option value="https">{t("proxyHosts.https")}</option>
              </SelectField>
              {form.tls_mode !== "disabled" && (
                <SelectField
                  label={t("proxyHosts.certificate")}
                  value={form.certificate_id ?? ""}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      certificate_id: e.target.value
                        ? Number(e.target.value)
                        : null,
                    })
                  }
                  required
                >
                  <option value="">{t("proxyHosts.selectCertificate")}</option>
                  {certs.map((c) => (
                    <option value={c.id} key={c.id}>
                      {c.name} ({c.covered_hostnames.join(", ")})
                    </option>
                  ))}
                </SelectField>
              )}
              <Button type="submit">{t("proxyHosts.addHost")}</Button>
            </form>
          )}
        </Card>
        <UsersSection
          user={user}
          users={users}
          roles={roles}
          userErrorMessage={usersError}
          onChanged={() => void refresh()}
        />
        <RolesSection
          user={user}
          roles={roles}
          hosts={hosts}
          onChanged={() => void refresh()}
        />
        <AuditLogSection user={user} reloadRef={auditReloadRef} />
      </div>
    </main>
  );
}
function AppContent() {
  const { t } = useTranslation();
  const [user, setUser] = useState<User | null>(null),
    [initialized, setInitialized] = useState<boolean | null>(null);
  useEffect(() => {
    api
      .status()
      .then((s) => {
        setInitialized(s.initialized);
        if (s.initialized)
          api
            .me()
            .then(setUser)
            .catch(() => {});
      })
      .catch(() => setInitialized(true));
  }, []);
  if (initialized === null)
    return (
      <main className="flex min-h-screen items-center justify-center bg-page px-4 py-8 text-foreground">
        <Alert variant="info">{t("auth.loading")}</Alert>
      </main>
    );
  if (!initialized)
    return (
      <Setup
        onDone={(u) => {
          setUser(u);
          setInitialized(true);
        }}
      />
    );
  if (
    typeof window !== "undefined" &&
    window.location.pathname === "/bot-challenge"
  ) {
    const prefix =
      new URLSearchParams(window.location.search).get("fingerprint_prefix") ??
      "";
    if (/^[a-f0-9]{16}$/.test(prefix))
      sessionStorage.setItem("bearust-bot-fingerprint", prefix);
    return <BotChallengePage />;
  }
  return (
    <LocalePreferenceProvider accountLocale={user?.preferred_locale}>
      {user ? (
        <Dashboard
          user={user}
          onLogout={() => {
            void api
              .logout()
              .catch(() => undefined)
              .finally(() => setUser(null));
          }}
          onUserRefresh={setUser}
        />
      ) : (
        <Login onDone={setUser} />
      )}
    </LocalePreferenceProvider>
  );
}
export default function App() {
  return <AppContent />;
}
export function AuditLogSection({
  user,
  reloadRef,
}: {
  user: User;
  reloadRef?: MutableRefObject<(() => void) | null>;
}) {
  const { t } = useTranslation();
  const [items, setItems] = useState<AuditLogItem[]>([]),
    [total, setTotal] = useState(0),
    [page, setPage] = useState(1),
    [error, setError] = useState(""),
    [loading, setLoading] = useState(false);
  const [event, setEvent] = useState(""),
    [q, setQ] = useState(""),
    [actorId, setActorId] = useState(""),
    [from, setFrom] = useState(""),
    [to, setTo] = useState("");
  const pageSize = 25;
  const requestSeq = useRef(0);
  const load = async () => {
    const requestId = ++requestSeq.current;
    setLoading(true);
    setError("");
    try {
      const query: AuditLogQuery = {
        page,
        page_size: pageSize,
        ...(event ? { event } : {}),
        ...(actorId && Number.isInteger(Number(actorId))
          ? { actor_id: Number(actorId) }
          : {}),
        ...(from ? { from: new Date(from).toISOString() } : {}),
        ...(to ? { to: new Date(to).toISOString() } : {}),
        ...(q ? { q } : {}),
      };
      const result = await api.auditLogs(query);
      if (requestId !== requestSeq.current) return;
      setItems(result.items);
      setTotal(result.total);
    } catch (e) {
      if (requestId !== requestSeq.current) return;
      setError(sanitizeError(e instanceof Error ? e.message : String(e)));
      setItems([]);
      setTotal(0);
    } finally {
      if (requestId === requestSeq.current) setLoading(false);
    }
  };
  useEffect(() => {
    if (!reloadRef) return;
    reloadRef.current = () => void load();
    return () => {
      reloadRef.current = null;
    };
  });
  useEffect(() => {
    void load();
  }, [page, event, q, actorId, from, to]);
  useEffect(() => {
    setPage(1);
  }, [event, q, actorId, from, to]);
  const hasNext = page * pageSize < total;
  return (
    <Card>
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-xl font-semibold">{t("audit.title")}</h2>
        <Button
          variant="secondary"
          onClick={() => void load()}
          disabled={loading}
        >
          {loading ? t("common.refreshing") : t("common.refresh")}
        </Button>
      </div>
      <div className="mb-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Field
          label={t("audit.event")}
          aria-label={t("audit.eventFilter")}
          value={event}
          onChange={(e) => setEvent(e.target.value)}
        />
        <Field
          label={t("audit.text")}
          aria-label={t("audit.textFilter")}
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
        <Field
          label={t("audit.actorId")}
          aria-label={t("audit.actorIdFilter")}
          inputMode="numeric"
          value={actorId}
          onChange={(e) => setActorId(e.target.value)}
        />
        <Field
          label={t("common.from")}
          aria-label={t("audit.fromFilter")}
          type="datetime-local"
          value={from}
          onChange={(e) => setFrom(e.target.value)}
        />
        <Field
          label={t("common.to")}
          aria-label={t("audit.toFilter")}
          type="datetime-local"
          value={to}
          onChange={(e) => setTo(e.target.value)}
        />
      </div>
      {error && <Alert variant="danger">{error}</Alert>}
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead>
            <tr>
              <th>{t("audit.actor")}</th>
              <th>{t("audit.event")}</th>
              <th>{t("audit.details")}</th>
              <th>{t("common.created")}</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item) => (
              <tr key={item.id}>
                <td>{item.actor}</td>
                <td>{item.event}</td>
                <td>{item.details}</td>
                <td>{item.created_at}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      {!loading && !error && items.length === 0 && <p>{t("audit.empty")}</p>}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
        <Button
          variant="secondary"
          onClick={() => setPage((value) => value - 1)}
          disabled={page === 1 || loading}
        >
          {t("common.previous")}
        </Button>
        <span>{t("audit.pageOf", { page, total })}</span>
        <Button
          variant="secondary"
          onClick={() => setPage((value) => value + 1)}
          disabled={!hasNext || loading}
        >
          {t("common.next")}
        </Button>
      </div>
    </Card>
  );
}
