import { useEffect, useRef, useState, type MutableRefObject, type FormEvent } from "react";
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
import { Alert, Button, Card, Field, SelectField, TextareaField, ThemeSelect } from "./ui";

export const sanitizeError = (message: string) => {
  if (/internal stack|database|password\s*[:=]/i.test(message))
    return "Unable to complete the request. Please try again.";
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
    return "You do not have permission to manage users.";
  if (
    status === 400 ||
    status === 422 ||
    /\b400\b|validation|invalid|required/i.test(message)
  )
    return "Please check the submitted user details.";
  if (status === 404) return "The requested user was not found.";
  if (status === 409)
    return "This user change conflicts with the current account state.";
  return "Unable to complete the user request. Please try again.";
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
  const [email, setEmail] = useState(""),
    [password, setPassword] = useState(""),
    [token, setToken] = useState(""),
    [error, setError] = useState("");
  return (
    <main className="min-h-screen bg-page px-4 py-8 text-foreground sm:px-6 lg:px-8">
      <Card className="mx-auto max-w-lg">
      <h1 className="mb-2 text-2xl font-semibold">Bearust Setup</h1>
      <p className="mb-6 text-muted">Create the first administrator account.</p>
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
          label="Email"
          type="email"
          value={email}
          onChange={(e: any) => setEmail(e.target.value)}
        />
        <Field
          label="Password (12+ characters)"
          type="password"
          value={password}
          onChange={(e: any) => setPassword(e.target.value)}
        />
        <Field
          label="Setup token"
          value={token}
          onChange={(e: any) => setToken(e.target.value)}
        />
        {error && <Alert variant="danger">{error}</Alert>}
        <Button type="submit">Create account</Button>
      </form>
      </Card>
    </main>
  );
}
function Login({ onDone }: { onDone: (u: User) => void }) {
  const [email, setEmail] = useState(""),
    [password, setPassword] = useState(""),
    [error, setError] = useState("");
  return (
    <main className="min-h-screen bg-page px-4 py-8 text-foreground sm:px-6 lg:px-8">
      <Card className="mx-auto max-w-lg">
      <h1 className="mb-6 text-2xl font-semibold">Bearust Login</h1>
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
          label="Email"
          type="email"
          value={email}
          onChange={(e: any) => setEmail(e.target.value)}
        />
        <Field
          label="Password"
          type="password"
          value={password}
          onChange={(e: any) => setPassword(e.target.value)}
        />
        {error && <Alert variant="danger">{error}</Alert>}
        <Button type="submit">Sign in</Button>
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
      <h2 className="mb-4 text-xl font-semibold">Issue Let's Encrypt certificate</h2>
      <form
        onSubmit={async (e) => {
          e.preventDefault();
          if (invalid || missingToken || busy) return;
          if (
            environment === "production" &&
            !window.confirm(
              "Production certificates are rate-limited. Continue?",
            )
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
        <SelectField label="Environment"
            value={environment}
            onChange={(e) =>
              setEnvironment(e.target.value as AcmeRequest["environment"])
            }
          >
            <option value="staging">Staging (safe default)</option>
            <option value="production">Production</option>
          </SelectField>
        <SelectField label="Challenge"
            value={challenge}
            onChange={(e) =>
              setChallenge(e.target.value as AcmeRequest["challenge"])
            }
          >
            <option value="http01">HTTP-01</option>
            <option value="cloudflare_dns01">Cloudflare DNS-01</option>
          </SelectField>
        <TextareaField label="Domains (one per line or comma separated)"
            value={domains}
            onChange={(e) => setDomains(e.target.value)}
            required
            rows={3}
            placeholder="example.com\nwww.example.com"
          />
        {invalid && (
          <Alert variant="warning">
            Enter valid hostnames. Wildcards require Cloudflare DNS-01.
          </Alert>
        )}
        {challenge === "cloudflare_dns01" && (
          <Field
            label="Cloudflare API token"
              type="password"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              autoComplete="off"
              placeholder="Required for DNS-01"
              required
            error={missingToken ? "Cloudflare API token is required." : undefined}
          />
        )}
        {error && <Alert variant="danger">{error}</Alert>}
        <Button type="submit"
          disabled={busy || invalid || missingToken || hosts.length === 0}
        >
          {busy ? "Issuing…" : "Issue certificate"}
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
        <h2 className="text-xl font-semibold">Certificates</h2>
        <Button variant="secondary" onClick={() => void refresh()} disabled={refreshing}>
          {refreshing ? "Refreshing…" : "Refresh"}
        </Button>
      </div>
      {error && <Alert variant="danger">{error}</Alert>}
      <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {items.map((c) => (
          <article className="flex flex-col gap-2 rounded-md border border-border bg-surface-muted p-4" key={c.id}>
            <strong className="font-semibold">{c.name}</strong>
            <span className="text-sm text-muted">
              {c.source} · {c.covered_hostnames.join(", ")}
            </span>
            <span className="text-sm text-muted">Expires: {c.expiry}</span>
            <span className="text-sm">
              Status: {c.active ? "Active" : "Inactive"}
              {c.acme && ` · Renewal: ${c.acme.renewal_state}`}
            </span>
            {c.acme?.last_error_code && (
              <span className="text-sm text-danger-foreground">
                Last error: {sanitizeError(c.acme.last_error_code)}
              </span>
            )}
            <div>
              {canWrite && (
                <>
                  <Button variant="secondary"
                    disabled={!!busy[c.id]}
                    onClick={() =>
                      void action(c.id, "renew", () =>
                        api.renewCertificate(c.id),
                      )
                    }
                  >
                    {busy[c.id] === "renew" ? "Renewing…" : "Renew"}
                  </Button>
                  {!c.active && (
                    <Button variant="secondary"
                      disabled={!!busy[c.id]}
                      onClick={() =>
                        void action(c.id, "activate", () =>
                          api.activateCertificate(c.id),
                        )
                      }
                    >
                      {busy[c.id] === "activate" ? "Activating…" : "Activate"}
                    </Button>
                  )}
                </>
              )}
            </div>
          </article>
        ))}
      </div>
      {items.length === 0 && <p>No certificates yet.</p>}
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
  const roleOptions = [...roles, ...["admin", "operator", "viewer"].filter((slug) => !roles.some((role) => role.slug === slug)).map((slug) => ({ slug, name: slug[0].toUpperCase() + slug.slice(1) }))];
  return (
    <Card data-testid="users-section">
      <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
        <h2 className="text-xl font-semibold">Users</h2>
        <Button data-testid="users-refresh" variant="secondary" onClick={() => void run(-2, () => Promise.resolve())}>
          Refresh
        </Button>
      </div>
      {(error || userErrorMessage) && (
        <Alert variant="danger">{error || userErrorMessage}</Alert>
      )}
      <div className="overflow-x-auto"><table className="min-w-full text-left text-sm">
        <thead>
          <tr>
            <th>Email</th>
            <th>Role</th>
            <th>Status</th>
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
                  {self ? " (you)" : ""}
                </td>
                <td>
                  <SelectField label="Role"
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
                    {roleOptions.map((role) => <option value={role.slug} key={role.slug}>{role.name}</option>)}
                  </SelectField>
                </td>
                <td>{item.disabled ? "Disabled" : "Active"}</td>
                <td>
                  {!self && (
                    <>
                      <Button variant="secondary"
                        disabled={busy === item.id}
                        onClick={() => {
                          if (
                            window.confirm(
                              item.disabled
                                ? "Enable this account?"
                                : "Disable this account?",
                            )
                          )
                            void run(item.id, () =>
                              api.updateUser(item.id, {
                                disabled: !item.disabled,
                              }),
                            );
                        }}
                      >
                        {item.disabled ? "Enable" : "Disable"}
                      </Button>{" "}
                      <Button variant="secondary"
                        disabled={busy === item.id}
                        onClick={() => void run(item.id, async () => {
                          const result = await api.revokeUserSessions(item.id);
                          window.alert(`Revoked ${result.revoked} session(s).`);
                        })}
                      >Revoke sessions</Button>{" "}
                      <Button variant="danger"
                        disabled={busy === item.id}
                        onClick={() => {
                          if (window.confirm("Delete this account?"))
                            void run(item.id, () => api.deleteUser(item.id));
                        }}
                      >
                        Delete
                      </Button>
                    </>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table></div>
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
        <h3>Add user</h3>
        <Field
          label="Email"
          type="email"
          value={email}
          onChange={(e: any) => setEmail(e.target.value)}
        />
        <Field
          label="Password (12+ characters)"
          type="password"
          value={password}
          onChange={(e: any) => setPassword(e.target.value)}
        />
        <SelectField label="Role"
            value={role}
            onChange={(e) => setRole(e.target.value as Role)}
          >
            <option value="admin">Admin</option>
            <option value="operator">Operator</option>
            <option value="viewer">Viewer</option>
          </SelectField>
        <Button type="submit" disabled={busy === -1 || !email.trim() || password.length < 12}>
          Create user
        </Button>
      </form>
    </Card>
  );
}

const PERMISSIONS: PermissionKey[] = ["proxy_hosts.read","proxy_hosts.write","certificates.read","certificates.write","users.manage","roles.manage","audit_logs.read","audit_logs.export","system.settings.manage","sessions.revoke"];
type ScopeDraft = Record<number, Record<"proxy_hosts.read" | "proxy_hosts.write", number[]>>;
export function RolesSection({ user, roles, hosts = [], onChanged }: { user: User; roles: RoleRecord[]; hosts?: Host[]; onChanged: () => void | Promise<void> }) {
  const [slug,setSlug]=useState(""), [name,setName]=useState(""), [error,setError]=useState(""), [busy,setBusy]=useState(false);
  const [drafts, setDrafts] = useState<ScopeDraft>(() => Object.fromEntries(roles.map((role) => [role.id, {
    "proxy_hosts.read": role.scopes?.find((s) => s.permission === "proxy_hosts.read")?.proxy_host_ids ?? [],
    "proxy_hosts.write": role.scopes?.find((s) => s.permission === "proxy_hosts.write")?.proxy_host_ids ?? [],
  }])) as ScopeDraft);
  useEffect(() => {
    setDrafts((current) => {
      const next: ScopeDraft = {};
      for (const role of roles) {
        next[role.id] = {
          "proxy_hosts.read": current[role.id]?.["proxy_hosts.read"] ?? role.scopes?.find((s) => s.permission === "proxy_hosts.read")?.proxy_host_ids ?? [],
          "proxy_hosts.write": current[role.id]?.["proxy_hosts.write"] ?? role.scopes?.find((s) => s.permission === "proxy_hosts.write")?.proxy_host_ids ?? [],
        };
      }
      return next;
    });
  }, [roles]);
  if (user.role !== "admin") return null;
  const run=async (action:()=>Promise<unknown>)=>{setBusy(true);setError("");try{await action();await onChanged()}catch(e){setError((e as {status?:number})?.status === 400 || (e as {status?:number})?.status === 422 ? "Please check the submitted role details." : userError(e))}finally{setBusy(false)}};
  const updateScope = (roleId: number, permission: "proxy_hosts.read" | "proxy_hosts.write", hostId: number, checked: boolean) => {
    setDrafts((all) => {
      const current = all[roleId] ?? { "proxy_hosts.read": [], "proxy_hosts.write": [] };
      const ids = checked
        ? [...new Set([...current[permission], hostId])].sort((a, b) => a - b)
        : current[permission].filter((id) => id !== hostId);
      return { ...all, [roleId]: { ...current, [permission]: ids } };
    });
  };
  const scopePayload = (roleId: number) => (["proxy_hosts.read", "proxy_hosts.write"] as const).map((permission) => ({ permission, proxy_host_ids: [...new Set(drafts[roleId]?.[permission] ?? [])].sort((a,b)=>a-b) })).filter((scope) => scope.proxy_host_ids.length);
  return <Card><h2 className="mb-4 text-xl font-semibold">Roles</h2>{error&&<Alert variant="danger">{error}</Alert>}<div className="overflow-x-auto"><table className="min-w-full text-left text-sm"><thead><tr><th>Name</th><th>Slug</th><th>Permissions</th><th /></tr></thead><tbody>{roles.map(role=><tr key={role.id}><td>{role.name}</td><td>{role.slug}</td><td>{role.permissions.join(", ")}<div data-testid={`role-scope-editor-${role.id}`} className="mt-3 grid gap-3 sm:grid-cols-2"><fieldset className="min-w-0"><legend className="font-medium">Proxy host read access</legend>{hosts.map((host)=><label className="flex items-center gap-2 text-sm" key={`read-${host.id}`}><input data-testid={`scope-read-host-${host.id}`} type="checkbox" disabled={role.system_managed || busy} checked={drafts[role.id]?.["proxy_hosts.read"]?.includes(host.id) ?? false} onChange={(e)=>updateScope(role.id,"proxy_hosts.read",host.id,e.target.checked)} /><span className="truncate">{host.domain}</span></label>)}</fieldset><fieldset className="min-w-0"><legend className="font-medium">Proxy host write access</legend>{hosts.map((host)=><label className="flex items-center gap-2 text-sm" key={`write-${host.id}`}><input data-testid={`scope-write-host-${host.id}`} type="checkbox" disabled={role.system_managed || busy} checked={drafts[role.id]?.["proxy_hosts.write"]?.includes(host.id) ?? false} onChange={(e)=>updateScope(role.id,"proxy_hosts.write",host.id,e.target.checked)} /><span className="truncate">{host.domain}</span></label>)}</fieldset>{!role.system_managed&&<div className="flex flex-wrap gap-2 sm:col-span-2"><Button data-testid={`role-scope-save-${role.id}`} variant="secondary" disabled={busy} onClick={()=>void run(()=>api.updateRole(role.id,{description:role.description,scopes:scopePayload(role.id)}))}>Save scopes</Button><Button data-testid={`role-scope-clear-${role.id}`} variant="secondary" disabled={busy} onClick={()=>setDrafts((all)=>({...all,[role.id]:{"proxy_hosts.read":[],"proxy_hosts.write":[]}}))}>Clear scopes</Button></div>}</div></td><td>{!role.system_managed&&<Button variant="danger" disabled={busy} onClick={()=>window.confirm("Delete this role?")&&void run(()=>api.deleteRole(role.id))}>Delete</Button>}</td></tr>)}</tbody></table></div><form className="mt-6 grid gap-4 sm:grid-cols-2" onSubmit={e=>{e.preventDefault();if(!slug.trim()||!name.trim())return;void run(async()=>{await api.createRole({slug:slug.trim(),name:name.trim(),description:"",permissions:["audit_logs.read"],scopes:[]});setSlug("");setName("")})}}><h3 className="sm:col-span-2 font-semibold">Add role</h3><Field label="Slug" value={slug} onChange={(e:any)=>setSlug(e.target.value)}/><Field label="Name" value={name} onChange={(e:any)=>setName(e.target.value)}/><Button type="submit" disabled={busy||!slug.trim()||!name.trim()}>Create role</Button></form><p className="mt-4 text-sm text-muted">Available permissions: {PERMISSIONS.join(", ")}</p></Card>;
}

export function WafSection({ user, refreshToken = 0 }: { user: User; refreshToken?: number }) {
  const [config, setConfig] = useState<WafConfig | null>(null), [rules, setRules] = useState<WafRule[]>([]), [error, setError] = useState(""), [busy, setBusy] = useState(false), [toml, setToml] = useState("");
  const admin = user.role === "admin";
  const reload = async () => { try { const [nextConfig, nextRules] = await Promise.all([api.wafConfig(), api.wafRules()]); setConfig(nextConfig); setRules(nextRules); setError(""); } catch (e) { setError(sanitizeError(e instanceof Error ? e.message : String(e))); } };
  useEffect(() => { void reload(); }, [refreshToken]);
  const changeMode = async () => { if (!config || !admin) return; setBusy(true); try { setConfig(await api.updateWafConfig({ mode: config.mode === "block" ? "monitor-only" : "block" })); } catch (e) { setError(sanitizeError(e instanceof Error ? e.message : String(e))); } finally { setBusy(false); } };
  const importToml = async () => { setBusy(true); try { await api.importWafRules(toml); setToml(""); await reload(); } catch (e) { setError(sanitizeError(e instanceof Error ? e.message : String(e))); } finally { setBusy(false); } };
  const exportToml = async () => { try { setToml(await api.exportWafRules()); } catch (e) { setError(sanitizeError(e instanceof Error ? e.message : String(e))); } };
  return <Card data-testid="waf-section"><div className="flex flex-wrap items-center gap-3"><h2 className="mr-auto text-xl font-semibold">Basic WAF</h2><span className="rounded-full border border-border px-3 py-1 text-sm" data-testid="waf-mode">{config?.mode === "block" ? "Block" : "Monitor-only"}</span>{admin && <Button variant="secondary" disabled={busy || !config} onClick={() => void changeMode()}>{config?.mode === "block" ? "Monitor-only" : "Block"}</Button>}</div>{error && <Alert variant="danger">{error}</Alert>}<div className="mt-4 overflow-x-auto"><table className="min-w-full text-left text-sm"><thead><tr><th>Name</th><th>Category</th><th>Severity</th><th>Action</th><th>Status</th><th /></tr></thead><tbody>{rules.map(rule => <tr key={rule.id}><td>{rule.name}</td><td>{rule.category}</td><td>{rule.severity}</td><td>{rule.action}</td><td>{rule.enabled ? "Enabled" : "Disabled"}</td><td>{admin && rule.source === "custom" && <Button variant="danger" disabled={busy} onClick={() => void api.deleteWafRule(rule.id).then(reload).catch(e => setError(sanitizeError(e instanceof Error ? e.message : String(e))))}>Delete</Button>}</td></tr>)}</tbody></table></div>{admin && <div className="mt-5 grid gap-3"><TextareaField label="WAF TOML import/export" value={toml} onChange={e => setToml(e.target.value)} rows={8} placeholder="version = 1" /><div className="flex flex-wrap gap-2"><Button variant="secondary" disabled={busy || !toml.trim()} onClick={() => void importToml()}>Import TOML</Button><Button variant="secondary" disabled={busy} onClick={() => void exportToml()}>Export TOML</Button></div></div>}</Card>;
}

/** The proxy fingerprint is keyed and must be supplied by the server. Never
 * substitute a browser/user-agent value: it cannot match the data-plane hash. */
const serverChallengeFingerprint = () => {
  if (typeof sessionStorage === "undefined") return "";
  const value = sessionStorage.getItem("bearust-bot-fingerprint") ?? "";
  return /^[a-f0-9]{16}$/.test(value) ? value : "";
};

export async function solveBotChallenge(challenge: BotChallenge, fingerprint: string): Promise<string> {
  if (typeof crypto === "undefined" || !crypto.subtle) throw new Error("Proof-of-work is unavailable in this browser.");
  const encoder = new TextEncoder();
  const prefix = "0".repeat(Math.min(challenge.difficulty, 4));
  for (let nonce = 0; nonce < 1_000_000; nonce += 1) {
    const digest = await crypto.subtle.digest("SHA-256", encoder.encode(`${challenge.token.split(".")[1] ?? ""}${nonce}`));
    const hex = Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
    if (hex.startsWith(prefix)) return String(nonce);
  }
  throw new Error("Unable to complete the challenge.");
}

export function BotProtectionSection({ user, refreshToken = 0 }: { user: User; refreshToken?: number }) {
  const [config, setConfig] = useState<BotConfig | null>(null), [crawlers, setCrawlers] = useState<TrustedCrawler[]>([]);
  const [mode, setMode] = useState<BotMode>("monitor"), [threshold, setThreshold] = useState(""), [ttl, setTtl] = useState(""), [ua, setUa] = useState(""), [domain, setDomain] = useState("");
  const [busy, setBusy] = useState(false), [error, setError] = useState(""), [saved, setSaved] = useState(false);
  const reload = async () => { try { const [nextConfig, nextCrawlers] = await Promise.all([api.botConfig(), api.trustedCrawlers()]); setConfig(nextConfig); setMode(nextConfig.mode); setThreshold(String(nextConfig.threshold)); setTtl(String(nextConfig.ttl_seconds)); setCrawlers(nextCrawlers); setError(""); } catch (e) { setError(sanitizeError(e instanceof Error ? e.message : String(e))); } };
  useEffect(() => { if (user.role === "admin") void reload(); }, [refreshToken, user.role]);
  if (user.role !== "admin") return null;
  const run = async (action: () => Promise<unknown>) => { setBusy(true); setError(""); setSaved(false); try { await action(); setSaved(true); await reload(); } catch (e) { setError(sanitizeError(e instanceof Error ? e.message : String(e))); } finally { setBusy(false); } };
  const validCrawler = ua.trim().length > 0 && ua.trim().length <= 256 && domain.trim().length > 0 && domain.trim().length <= 253 && !/\s/.test(domain);
  return <Card data-testid="bot-protection-section"><h2 className="mb-2 text-xl font-semibold">Bot protection</h2><p className="mb-4 text-sm text-muted">Monitor-only is the safe default. No keys or challenge tokens are displayed here.</p>{error && <Alert variant="danger">{error}</Alert>}{saved && <Alert variant="success">Bot protection policy saved.</Alert>}<form className="grid gap-4 sm:grid-cols-3" onSubmit={(e) => { e.preventDefault(); if (!config || !threshold || !ttl) return; void run(() => api.updateBotConfig({ mode, threshold: Number(threshold), ttl_seconds: Number(ttl) })); }}><SelectField label="Mode" value={mode} onChange={(e) => setMode(e.target.value as BotMode)} disabled={busy}><option value="monitor">Monitor-only</option><option value="challenge">Challenge</option><option value="block">Block</option></SelectField><Field label="Risk threshold" type="number" min="0" max="100" value={threshold} onChange={(e) => setThreshold(e.target.value)} disabled={busy} required /><Field label="Challenge TTL (seconds)" type="number" min="30" max="86400" value={ttl} onChange={(e) => setTtl(e.target.value)} disabled={busy} required /><Button type="submit" disabled={busy || !threshold || !ttl}>Save policy</Button></form><div className="mt-6"><h3 className="mb-3 font-semibold">Trusted crawlers</h3><div className="overflow-x-auto"><table className="min-w-full text-left text-sm"><thead><tr><th>User agent</th><th>Domain</th><th>Status</th><th /></tr></thead><tbody>{crawlers.map((crawler) => <tr key={crawler.id}><td>{crawler.trusted_user_agent ?? "—"}</td><td>{crawler.trusted_domain ?? "—"}</td><td>{crawler.enabled ? "Enabled" : "Disabled"}</td><td><Button variant="secondary" disabled={busy} onClick={() => void run(() => api.updateTrustedCrawler(crawler.id, { user_agent: crawler.trusted_user_agent ?? "", domain: crawler.trusted_domain ?? "", enabled: !crawler.enabled }))}>{crawler.enabled ? "Disable" : "Enable"}</Button> <Button variant="danger" disabled={busy} onClick={() => void run(() => api.deleteTrustedCrawler(crawler.id))}>Delete</Button></td></tr>)}</tbody></table></div><form className="mt-4 grid gap-4 sm:grid-cols-2" onSubmit={(e) => { e.preventDefault(); if (!validCrawler) return; void run(async () => { await api.createTrustedCrawler({ user_agent: ua.trim(), domain: domain.trim(), enabled: true }); setUa(""); setDomain(""); }); }}><Field label="Crawler user agent" value={ua} onChange={(e) => setUa(e.target.value)} maxLength={256} required /><Field label="Crawler domain" value={domain} onChange={(e) => setDomain(e.target.value)} maxLength={253} placeholder="example.com" required /><Button type="submit" disabled={busy || !validCrawler}>Add trusted crawler</Button></form></div></Card>;
}

export function RateLimitSection({ user, refreshToken = 0 }: { user: User; refreshToken?: number }) {
  const [config, setConfig] = useState<RateLimitConfig | null>(null);
  const [error, setError] = useState(""), [busy, setBusy] = useState(false), [saved, setSaved] = useState(false);
  const [enabled, setEnabled] = useState(false), [action, setAction] = useState<RateLimitAction>("monitor"), [capacity, setCapacity] = useState("100"), [refill, setRefill] = useState("10");
  const admin = user.role === "admin";
  const reload = async () => { try { const next = await api.rateLimitConfig(); setConfig(next); setEnabled(next.enabled); setAction(next.action); setCapacity(String(next.capacity)); setRefill(String(next.refill_per_second)); setError(""); } catch (e) { setError("Unable to load rate-limit policy."); } };
  useEffect(() => { void reload(); }, [refreshToken]);
  const save = async (event: FormEvent) => { event.preventDefault(); if (!admin) return; const c = Number(capacity), r = Number(refill); if (!Number.isInteger(c) || c < 1 || c > 1_000_000 || !Number.isFinite(r) || r < 0.001 || r > 100_000) { setError("Capacity must be 1–1,000,000 and refill 0.001–100,000 per second."); return; } setBusy(true); setError(""); setSaved(false); try { const next = await api.updateRateLimitConfig({ enabled, action, capacity: c, refill_per_second: r, key_scope: "proxy_host_ip" }); setConfig(next); setSaved(true); } catch { setError("Unable to save rate-limit policy."); } finally { setBusy(false); } };
  return <Card data-testid="rate-limit-section"><div className="flex flex-wrap items-center gap-3"><h2 className="mr-auto text-xl font-semibold">Rate limiting</h2><span className="rounded-full border border-border px-3 py-1 text-sm">{config?.action === "block" ? "Block" : "Monitor-only"}</span></div><p className="mt-2 text-sm text-muted">Limits each proxy host by client IP. Monitor-only is the safe default; no raw client identifiers are shown.</p>{error && <Alert variant="danger">{error}</Alert>}{saved && <Alert variant="success">Rate-limit policy saved.</Alert>}<form className="mt-4 grid gap-4 sm:grid-cols-2" onSubmit={(e) => void save(e)}><label className="flex min-h-11 items-center gap-3 text-sm font-medium"><input aria-label="Enable rate limiting" type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} disabled={!admin || busy} />Enable rate limiting</label><SelectField label="Action" value={action} onChange={(e) => setAction(e.target.value as RateLimitAction)} disabled={!admin || busy}><option value="monitor">Monitor-only</option><option value="block">Block limited requests</option></SelectField><Field label="Burst capacity" type="number" min="1" max="1000000" value={capacity} onChange={(e) => setCapacity(e.target.value)} disabled={!admin || busy} required /><Field label="Refill per second" type="number" min="0.001" max="100000" step="0.001" value={refill} onChange={(e) => setRefill(e.target.value)} disabled={!admin || busy} required /><SelectField label="Key scope" value="proxy_host_ip" disabled><option value="proxy_host_ip">Proxy host + client IP</option></SelectField>{admin && <Button type="submit" disabled={busy}>{busy ? "Saving…" : "Save policy"}</Button>}</form></Card>;
}

export function AnalyticsSection({ hosts, refreshToken = 0 }: { hosts: Host[]; refreshToken?: number }) {
  const [summary, setSummary] = useState<AnalyticsSummary | null>(null);
  const [rows, setRows] = useState<AnalyticsBucket[]>([]);
  const [host, setHost] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const autoSelectedHost = useRef(false);
  const query = () => ({ ...(host ? { proxy_host_id: Number(host) } : {}), ...(from ? { from: new Date(from).toISOString() } : {}), ...(to ? { to: new Date(to).toISOString() } : {}), limit: 1440 });
  const load = async () => {
    setLoading(true); setError("");
    try { const q = query(); const [s, t] = await Promise.all([api.getAnalyticsSummary(q), api.getAnalyticsTimeseries(q)]); setSummary(s); setRows(t); }
    catch (e) { setError(sanitizeError(e instanceof Error ? e.message : String(e))); setSummary(null); setRows([]); }
    finally { setLoading(false); }
  };
  useEffect(() => {
    if (hosts.length === 0) return;
    if (!autoSelectedHost.current) {
      autoSelectedHost.current = true;
      setHost(String(hosts[0].id));
      return;
    }
    if (host && !hosts.some((candidate) => String(candidate.id) === host)) setHost(String(hosts[0].id));
  }, [hosts]);
  useEffect(() => { const timer = setTimeout(() => void load(), 150); return () => clearTimeout(timer); }, [refreshToken, host, from, to]);
  const cards = summary ? [["Requests", summary.requests], ["2xx", summary.status_2xx], ["4xx", summary.status_4xx], ["5xx", summary.status_5xx], ["p95 latency", summary.p95_ms == null ? "—" : `${summary.p95_ms} ms`], ["Security events", summary.waf_blocks + summary.bot_blocks + summary.bot_challenges + summary.rate_limited]] : [];
  const latency = summary ? [["p50", summary.p50_ms], ["p95", summary.p95_ms], ["p99", summary.p99_ms]] as const : [];
  const latencyMax = Math.max(...latency.map(([, value]) => value ?? 0), 1);
  return <Card data-testid="analytics-section"><div className="flex flex-wrap items-center gap-3"><h2 className="mr-auto text-xl font-semibold">Analytics</h2><span className="text-sm text-muted">Process-local · last 24 hours</span></div>
    <div className="mt-4 grid gap-4 sm:grid-cols-3" role="group" aria-label="Analytics filters"><SelectField id="analytics-proxy-host" label="Proxy host" value={host} onChange={e => setHost(e.target.value)}><option value="">All hosts</option>{hosts.slice(0, 100).map(h => <option key={h.id} value={h.id}>{h.name} ({h.domain})</option>)}</SelectField><Field label="From" type="datetime-local" value={from} onChange={e => setFrom(e.target.value)} /><Field label="To" type="datetime-local" value={to} onChange={e => setTo(e.target.value)} /></div>
    {loading && <p role="status" className="mt-4 text-muted">Loading analytics…</p>}
    {!loading && error && <Alert variant="danger">{error}</Alert>}
    {!loading && !error && summary && summary.requests === 0 && <p className="mt-4 text-muted">No analytics data for the selected range.</p>}
    {!loading && !error && summary && summary.requests > 0 && <><div className="mt-5 grid gap-3 sm:grid-cols-3 lg:grid-cols-6">{cards.map(([label, value]) => <div key={label} className="rounded border border-border p-3"><div className="text-xs text-muted">{label}</div><div className="text-xl font-semibold">{value}</div></div>)}</div>
      <div className="mt-6 grid gap-4 lg:grid-cols-2">
        <section className="rounded border border-border p-4" aria-labelledby="analytics-latency-heading">
          <h3 id="analytics-latency-heading" className="mb-3 font-semibold">Latency percentiles</h3>
          <div className="space-y-3" role="group" aria-label="Request latency percentiles">
            {latency.map(([label, value]) => {
              const width = value == null ? 0 : Math.max(4, Math.round((value / latencyMax) * 100));
              return <div key={label}><div className="mb-1 flex items-center justify-between text-sm"><span>{label}</span><span>{value == null ? "—" : `${value} ms`}</span></div><div className="h-2 rounded bg-muted/20" role="progressbar" aria-label={`${label} latency`} aria-valuemin={0} aria-valuemax={latencyMax} aria-valuenow={value ?? 0}><div className="h-2 rounded bg-accent" style={{ width: `${width}%` }} /></div></div>;
            })}
          </div>
        </section>
        <section className="rounded border border-border p-4" aria-labelledby="analytics-security-heading">
          <h3 id="analytics-security-heading" className="mb-3 font-semibold">Security events</h3>
          <dl className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
            {[["WAF blocks", summary.waf_blocks], ["Bot blocks", summary.bot_blocks], ["Bot challenges", summary.bot_challenges], ["Rate limited", summary.rate_limited]].map(([label, value]) => <div key={label} className="rounded border border-border p-3"><dt className="text-xs text-muted">{label}</dt><dd className="text-xl font-semibold">{value}</dd></div>)}
          </dl>
        </section>
      </div>
      <div className="mt-6 overflow-x-auto"><table className="min-w-full text-left text-sm"><caption className="sr-only">Analytics by minute</caption><thead><tr><th>Time</th><th>Host</th><th>Requests</th><th>p50</th><th>p95</th><th>Errors</th></tr></thead><tbody>{rows.map(row => <tr key={`${row.timestamp}-${row.proxy_host_id}`}><td>{new Date(row.timestamp).toLocaleString()}</td><td>{hosts.find(h => h.id === row.proxy_host_id)?.name ?? row.proxy_host_id}</td><td>{row.requests}</td><td>{row.p50_ms == null ? "—" : `${row.p50_ms} ms`}</td><td>{row.p95_ms == null ? "—" : `${row.p95_ms} ms`}</td><td>{row.status_4xx + row.status_5xx}</td></tr>)}</tbody></table></div></>}
  </Card>;
}

export function BaselineSection({ hosts, refreshToken = 0 }: { hosts: Host[]; refreshToken?: number }) {
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
    if (host && !hosts.some((candidate) => String(candidate.id) === host)) setHost(String(hosts[0].id));
  }, [hosts]);

  useEffect(() => {
    void load();
  }, [refreshToken, host, window]);

  return (
    <Card data-testid="baseline-section">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="mr-auto text-xl font-semibold">Traffic Baseline</h2>
        {snapshot?.status === "warming_up" ? (
          <span className="rounded-full bg-amber-500/20 px-3 py-1 text-xs text-amber-500 font-medium">Warming up</span>
        ) : (
          <span className="rounded-full bg-emerald-500/20 px-3 py-1 text-xs text-emerald-500 font-medium">Baseline ready</span>
        )}
      </div>
      <p className="mt-2 text-sm text-muted">Bounded process-local traffic baselines for anomaly detection reference.</p>
      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <SelectField id="baseline-proxy-host" label="Proxy host" value={host} onChange={(e) => setHost(e.target.value)}>
          <option value="">All hosts</option>
          {hosts.slice(0, 100).map((h) => (
            <option key={h.id} value={h.id}>
              {h.name} ({h.domain})
            </option>
          ))}
        </SelectField>
        <SelectField id="baseline-window" label="Window" value={window} onChange={(e) => setWindow(e.target.value as BaselineWindow)}>
          <option value="5m">5 Minutes</option>
          <option value="1h">1 Hour</option>
          <option value="24h">24 Hours</option>
        </SelectField>
      </div>
      {loading && <p role="status" className="mt-4 text-muted">Loading baseline…</p>}
      {!loading && error && <Alert variant="danger">{error}</Alert>}
      {!loading && !error && snapshot && (
        <div className="mt-5 grid gap-3 sm:grid-cols-3 lg:grid-cols-5">
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted">Req / sec</div>
            <div className="text-xl font-semibold">{snapshot.metrics.req_per_sec.toFixed(2)}</div>
          </div>
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted">Error rate</div>
            <div className="text-xl font-semibold">{snapshot.metrics.error_rate_percent.toFixed(1)}%</div>
          </div>
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted">p50 latency</div>
            <div className="text-xl font-semibold">{snapshot.metrics.p50_ms == null ? "—" : `${snapshot.metrics.p50_ms} ms`}</div>
          </div>
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted">p95 latency</div>
            <div className="text-xl font-semibold">{snapshot.metrics.p95_ms == null ? "—" : `${snapshot.metrics.p95_ms} ms`}</div>
          </div>
          <div className="rounded border border-border p-3">
            <div className="text-xs text-muted">Security blocks</div>
            <div className="text-xl font-semibold">
              {snapshot.metrics.waf_blocks + snapshot.metrics.bot_blocks + snapshot.metrics.bot_challenges + snapshot.metrics.rate_limited}
            </div>
          </div>
        </div>
      )}
    </Card>
  );
}

export function AnomalySection({ user, hosts, refreshToken = 0 }: { user: User; hosts: Host[]; refreshToken?: number }) {
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
    if (host && !hosts.some((candidate) => String(candidate.id) === host)) setHost(String(hosts[0].id));
  }, [hosts]);

  useEffect(() => {
    void load();
  }, [refreshToken, host, severity]);

  const ack = async (id: number) => {
    try {
      await api.ackAnomaly(id);
      void load();
    } catch {
      setError("Unable to acknowledge anomaly.");
    }
  };

  return (
    <Card data-testid="anomaly-section">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="mr-auto text-xl font-semibold">Anomaly Detection</h2>
        <span className="rounded-full border border-border px-3 py-1 text-xs text-muted">Monitor-only</span>
      </div>
      <p className="mt-2 text-sm text-muted">Deterministic traffic deviation detector with severity scoring and deduplication.</p>
      <div className="mt-4 grid gap-4 sm:grid-cols-2">
        <SelectField id="anomaly-proxy-host" label="Proxy host" value={host} onChange={(e) => setHost(e.target.value)}>
          <option value="">All hosts</option>
          {hosts.slice(0, 100).map((h) => (
            <option key={h.id} value={h.id}>
              {h.name} ({h.domain})
            </option>
          ))}
        </SelectField>
        <SelectField id="anomaly-severity" label="Severity" value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">All severities</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="critical">Critical</option>
        </SelectField>
      </div>
      {loading && <p role="status" className="mt-4 text-muted">Loading anomalies…</p>}
      {!loading && error && <Alert variant="danger">{error}</Alert>}
      {!loading && !error && anomalies.length === 0 && (
        <p className="mt-4 text-muted">No traffic anomalies detected for the selected filters.</p>
      )}
      {!loading && !error && anomalies.length > 0 && (
        <div className="mt-4 overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <caption>Traffic anomalies</caption>
            <thead>
              <tr>
                <th>Observed</th>
                <th>Host</th>
                <th>Rule</th>
                <th>Severity</th>
                <th>Score</th>
                <th>Summary</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {anomalies.map((item) => (
                <tr key={item.id}>
                  <td>{new Date(item.observed_at).toLocaleString()}</td>
                  <td>{hosts.find((h) => h.id === item.host_id)?.name ?? item.host_id}</td>
                  <td className="capitalize">{item.rule.replace("_", " ")}</td>
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
                      {item.severity}
                    </span>
                  </td>
                  <td>{item.score.toFixed(2)}</td>
                  <td>{item.summary}</td>
                  <td>
                    {canAck && !item.acknowledged && (
                      <Button variant="secondary" onClick={() => void ack(item.id)}>
                        Acknowledge
                      </Button>
                    )}
                    {item.acknowledged && <span className="text-xs text-muted">Acknowledged</span>}
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

export function AdaptiveTuningSection({ user, hosts, refreshToken = 0 }: { user: User; hosts: Host[]; refreshToken?: number }) {
  const [selectedHost, setSelectedHost] = useState("");
  const [policy, setPolicy] = useState<TuningPolicy>({
    mode: "monitor",
    max_delta_percent: 50,
    cooldown_seconds: 300,
    min_confidence: 0.8,
  });
  const [recommendations, setRecommendations] = useState<PolicyRecommendation[]>([]);
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
      setSuccess("Adaptive tuning policy saved.");
    } catch {
      setError("Unable to save adaptive tuning policy.");
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
      setError("Unable to apply recommendation.");
    }
  };

  const rollbackRec = async (id: number) => {
    if (!isAdmin) return;
    try {
      await api.rollbackRecommendation(id);
      void load();
    } catch {
      setError("Unable to rollback recommendation.");
    }
  };

  const toggleEmergency = async () => {
    if (!isAdmin) return;
    try {
      const res = await api.emergencyDisableTuning();
      setEmergencyDisabled(res.emergency_disabled);
      void load();
    } catch {
      setError("Unable to toggle emergency disable.");
    }
  };

  return (
    <Card data-testid="adaptive-tuning-section">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="mr-auto text-xl font-semibold">Adaptive Tuning</h2>
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
            ? "Emergency Disabled"
            : policy.mode === "enforce"
            ? "Enforce Active"
            : policy.mode === "recommend"
            ? "Recommendations Only"
            : "Monitor-only (Default)"}
        </span>
      </div>
      <p className="mt-2 text-sm text-muted">
        Opt-in policy recommendations and guarded adjustments per host. Defaults to monitor-only with maximum delta guardrails.
      </p>

      {error && <Alert variant="danger">{error}</Alert>}
      {success && <Alert variant="success">{success}</Alert>}

      <form className="mt-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-4" onSubmit={(e) => void savePolicy(e)}>
        <SelectField
          id="tuning-proxy-host"
          label="Proxy Host"
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
          label="Mode"
          value={policy.mode}
          onChange={(e) => setPolicy({ ...policy, mode: e.target.value as TuningMode })}
          disabled={!isAdmin || saving}
        >
          <option value="monitor">Monitor-only</option>
          <option value="recommend">Recommend</option>
          <option value="enforce">Enforce</option>
        </SelectField>

        <Field
          label="Max Delta %"
          type="number"
          min="1"
          max="100"
          value={String(policy.max_delta_percent)}
          onChange={(e) => setPolicy({ ...policy, max_delta_percent: Number(e.target.value) })}
          disabled={!isAdmin || saving}
          required
        />

        <Field
          label="Min Confidence"
          type="number"
          min="0.1"
          max="1.0"
          step="0.05"
          value={String(policy.min_confidence)}
          onChange={(e) => setPolicy({ ...policy, min_confidence: Number(e.target.value) })}
          disabled={!isAdmin || saving}
          required
        />

        {isAdmin && (
          <div className="col-span-full flex gap-3">
            <Button type="submit" disabled={saving}>
              {saving ? "Saving…" : "Save Tuning Policy"}
            </Button>
            <Button
              type="button"
              variant={emergencyDisabled ? "secondary" : "danger"}
              onClick={() => void toggleEmergency()}
            >
              {emergencyDisabled ? "Enable Tuning" : "Emergency Disable"}
            </Button>
          </div>
        )}
      </form>

      <div className="mt-6 border-t border-border pt-4">
        <h3 className="text-lg font-semibold mb-2">Recommendations & History</h3>
        {loading && <p role="status" className="text-muted">Loading recommendations…</p>}
        {!loading && recommendations.length === 0 && (
          <p className="text-muted text-sm">No policy recommendations generated.</p>
        )}
        {!loading && recommendations.length > 0 && (
          <div className="overflow-x-auto">
            <table className="min-w-full text-left text-sm">
              <caption>Tuning recommendations</caption>
              <thead>
                <tr>
                  <th>Created</th>
                  <th>Host ID</th>
                  <th>Confidence</th>
                  <th>Reason</th>
                  <th>Status</th>
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
                        <span className="rounded bg-emerald-500/20 px-2 py-0.5 text-xs text-emerald-500">Applied</span>
                      ) : (
                        <span className="rounded bg-amber-500/20 px-2 py-0.5 text-xs text-amber-500">Pending</span>
                      )}
                    </td>
                    <td>
                      {isAdmin && !rec.applied && (
                        <Button variant="secondary" onClick={() => void applyRec(rec.id)}>
                          Apply
                        </Button>
                      )}
                      {isAdmin && rec.applied && (
                        <Button variant="danger" onClick={() => void rollbackRec(rec.id)}>
                          Rollback
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

export function BotChallengePage({ fingerprint = serverChallengeFingerprint(), onComplete }: { fingerprint?: string; onComplete?: () => void }) {
  const [challenge, setChallenge] = useState<BotChallenge | null>(null), [busy, setBusy] = useState(false), [error, setError] = useState(""), [complete, setComplete] = useState(false);
  const requestChallenge = async () => { if (!fingerprint) { setError("Challenge context unavailable. Please return to the protected page and try again."); return; } setBusy(true); setError(""); setComplete(false); try { setChallenge(await api.botChallenge(fingerprint)); } catch { setError("Challenge unavailable. Please try again."); } finally { setBusy(false); } };
  useEffect(() => { void requestChallenge(); }, [fingerprint]);
  const verify = async () => { if (!challenge) return; setBusy(true); setError(""); try { const solution = await solveBotChallenge(challenge, fingerprint); await api.verifyBotChallenge({ token: challenge.token, fingerprint, solution }); setComplete(true); onComplete?.(); } catch { setError("Challenge verification failed. Please try again."); } finally { setBusy(false); } };
  return <main className="min-h-screen bg-page px-4 py-8 text-foreground"><Card className="mx-auto max-w-lg"><h1 className="mb-2 text-2xl font-semibold">Quick browser check</h1><p className="mb-6 text-muted">Complete a small proof-of-work check to continue. Your challenge token stays in this browser and is never shown.</p>{error && <Alert variant="danger">{error}</Alert>}{complete ? <Alert variant="success">Verification complete. You may continue.</Alert> : <Button disabled={busy || !challenge} onClick={() => void verify()}>{busy ? "Verifying…" : "Verify browser"}</Button>}<Button className="ml-2" variant="secondary" disabled={busy} onClick={() => void requestChallenge()}>Try another challenge</Button></Card></main>;
}

function Dashboard({ user, onLogout, onUserRefresh }: { user: User; onLogout: () => void; onUserRefresh: (user: User) => void }) {
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
    waf: () => setWafRefresh(value => value + 1),
    rateLimit: () => setWafRefresh(value => value + 1),
    analytics: () => setAnalyticsRefresh(value => value + 1),
    baseline: () => setBaselineRefresh(value => value + 1),
    anomaly: () => setAnomalyRefresh(value => value + 1),
    adaptiveTuning: () => setAdaptiveTuningRefresh(value => value + 1),
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
        <h1 className="mr-auto text-2xl font-bold text-brand">Bearust</h1>
        <span className="text-sm text-muted">
          {user.email} ({user.role})
        </span>
        <ThemeSelect />
        <Button variant="secondary" onClick={onLogout}>Sign out</Button>
        <span className="text-sm text-muted" aria-label="Realtime status">
          Realtime: {realtimeStatus}
        </span>
      </header>
      <div className="mx-auto grid max-w-7xl gap-6">{error && <Alert variant="danger">{error}</Alert>}
      <CertificateTable user={user} onChanged={() => void refresh()} />
      <WafSection user={user} refreshToken={wafRefresh} />
      <BotProtectionSection user={user} refreshToken={wafRefresh} />
      <RateLimitSection user={user} refreshToken={wafRefresh} />
      <AnalyticsSection hosts={hosts} refreshToken={analyticsRefresh} />
      <BaselineSection hosts={hosts} refreshToken={baselineRefresh} />
      <AnomalySection user={user} hosts={hosts} refreshToken={anomalyRefresh} />
      <AdaptiveTuningSection user={user} hosts={hosts} refreshToken={adaptiveTuningRefresh} />
      {canWrite && (
        <AcmeWizard canWrite={canWrite} onIssued={() => void refresh()} />
      )}
      <Card>
        <h2 className="mb-4 text-xl font-semibold">Proxy Hosts</h2>
        <div className="overflow-x-auto"><table className="min-w-full text-left text-sm">
          <thead>
            <tr>
              <th>Name</th>
              <th>Domain</th>
              <th>Upstream</th>
              <th>TLS</th>
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
                    <Button variant="danger" onClick={() => api.deleteHost(h.id).then(refresh)}>
                      Delete
                    </Button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table></div>
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
            <h3>Add Proxy Host</h3>
            <Field
              label="Name"
              value={form.name}
              onChange={(e: any) => setForm({ ...form, name: e.target.value })}
            />
            <Field
              label="Domain"
              value={form.domain}
              onChange={(e: any) =>
                setForm({ ...form, domain: e.target.value })
              }
            />
            <Field
              label="Upstream host"
              value={form.upstream_host}
              onChange={(e: any) =>
                setForm({ ...form, upstream_host: e.target.value })
              }
            />
            <Field
              label="Port"
              type="number"
              min="1"
              max="65535"
              value={form.upstream_port}
              onChange={(e: any) =>
                setForm({ ...form, upstream_port: Number(e.target.value) })
              }
            />
            <SelectField label="TLS mode"
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
                <option value="disabled">Disabled</option>
                <option value="http">HTTP</option>
                <option value="https">HTTPS</option>
              </SelectField>
            {form.tls_mode !== "disabled" && (
              <SelectField label="Certificate"
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
                  <option value="">Select certificate</option>
                  {certs.map((c) => (
                    <option value={c.id} key={c.id}>
                      {c.name} ({c.covered_hostnames.join(", ")})
                    </option>
                  ))}
                </SelectField>
            )}
            <Button type="submit">Add host</Button>
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
      <RolesSection user={user} roles={roles} hosts={hosts} onChanged={() => void refresh()} />
      <AuditLogSection user={user} reloadRef={auditReloadRef} />
      </div>
    </main>
  );
}
function AppContent() {
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
        <Alert variant="info">Loading Bearust…</Alert>
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
  if (typeof window !== "undefined" && window.location.pathname === "/bot-challenge") {
    const prefix = new URLSearchParams(window.location.search).get("fingerprint_prefix") ?? "";
    if (/^[a-f0-9]{16}$/.test(prefix)) sessionStorage.setItem("bearust-bot-fingerprint", prefix);
    return <BotChallengePage />;
  }
  return user ? (
    <Dashboard
      user={user}
      onLogout={() => {
        void api.logout().catch(() => undefined).finally(() => setUser(null));
      }}
      onUserRefresh={setUser}
    />
  ) : (
    <Login onDone={setUser} />
  );
}
export default function App() {
  return <AppContent />;
}
export function AuditLogSection({ user, reloadRef }: { user: User; reloadRef?: MutableRefObject<(() => void) | null> }) {
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
        ...(actorId && Number.isInteger(Number(actorId)) ? { actor_id: Number(actorId) } : {}),
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
        <h2 className="text-xl font-semibold">Audit Log</h2>
        <Button variant="secondary" onClick={() => void load()} disabled={loading}>
          {loading ? "Refreshing…" : "Refresh"}
        </Button>
      </div>
      <div className="mb-4 grid gap-4 sm:grid-cols-2 lg:grid-cols-5">
        <Field label="Event"
            aria-label="Event filter"
            value={event}
            onChange={(e) => setEvent(e.target.value)}
          />
        <Field label="Text"
            aria-label="Text filter"
            value={q}
            onChange={(e) => setQ(e.target.value)}
          />
        <Field label="Actor ID" aria-label="Actor ID filter" inputMode="numeric" value={actorId} onChange={(e) => setActorId(e.target.value)} />
        <Field label="From" aria-label="From filter" type="datetime-local" value={from} onChange={(e) => setFrom(e.target.value)} />
        <Field label="To" aria-label="To filter" type="datetime-local" value={to} onChange={(e) => setTo(e.target.value)} />
      </div>
      {error && <Alert variant="danger">{error}</Alert>}
      <div className="overflow-x-auto"><table className="min-w-full text-left text-sm">
        <thead>
          <tr>
            <th>Actor</th>
            <th>Event</th>
            <th>Details</th>
            <th>Created</th>
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
      </table></div>
      {!loading && !error && items.length === 0 && (
        <p>No audit log entries found.</p>
      )}
      <div className="mt-4 flex flex-wrap items-center justify-between gap-3">
        <Button variant="secondary"
          onClick={() => setPage((value) => value - 1)}
          disabled={page === 1 || loading}
        >
          Previous
        </Button>
        <span>
          Page {page} · {total} total
        </span>
        <Button variant="secondary"
          onClick={() => setPage((value) => value + 1)}
          disabled={!hasNext || loading}
        >
          Next
        </Button>
      </div>
    </Card>
  );
}
