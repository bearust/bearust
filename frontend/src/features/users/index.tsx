import { useEffect, useMemo, useState, type FormEvent } from "react";
import { toast } from "sonner";
import { useTranslation } from "react-i18next";
import {
  Ellipsis,
  MailPlus,
  Pencil,
  Plus,
  RefreshCw,
  Search,
  ShieldCheck,
  Trash2,
  UserRound,
  Users as UsersIcon,
} from "lucide-react";
import {
  api,
  type PermissionKey,
  type RolePermissionScope,
  type RoleRecord,
  type User,
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
import { Main } from "@/components/layout/main";
import { PageHeader } from "@/components/page-header";
import { StatusBadge } from "@/components/status-badge";

const permissionOptions: PermissionKey[] = [
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
  "bot_protection.manage",
  "ai_advisor.read",
  "ai_advisor.request",
  "ai_advisor.approve",
  "plugins.read",
  "plugins.manage",
];
const demoUsers: User[] = [
  { id: 1, email: "admin@bearust.local", role: "admin", disabled: false },
  { id: 2, email: "maya@bearust.local", role: "operator", disabled: false },
  { id: 3, email: "dimas@bearust.local", role: "viewer", disabled: false },
  { id: 4, email: "staging@bearust.local", role: "operator", disabled: true },
];
const demoRoles: RoleRecord[] = [
  {
    id: 1,
    slug: "admin",
    name: "Administrator",
    description: "Full control",
    system_managed: true,
    permissions: permissionOptions,
  },
  {
    id: 2,
    slug: "operator",
    name: "Operator",
    description: "Operate edge services",
    system_managed: true,
    permissions: [
      "proxy_hosts.read",
      "proxy_hosts.write",
      "certificates.read",
      "certificates.write",
      "audit_logs.read",
      "ai_advisor.read",
      "ai_advisor.request",
    ],
  },
  {
    id: 3,
    slug: "viewer",
    name: "Viewer",
    description: "Read-only access",
    system_managed: true,
    permissions: ["proxy_hosts.read", "certificates.read", "audit_logs.read"],
  },
];

type UserForm = { email: string; password: string; role: string };
type RoleForm = {
  slug: string;
  name: string;
  description: string;
  permissions: PermissionKey[];
  scopeHostIds: string;
};
type ConfirmTarget =
  { kind: "user"; item: User } | { kind: "role"; item: RoleRecord } | null;
const emptyUser: UserForm = { email: "", password: "", role: "viewer" };
const emptyRole: RoleForm = {
  slug: "",
  name: "",
  description: "",
  permissions: [],
  scopeHostIds: "",
};

export function Users() {
  const { t } = useTranslation();
  const currentUser = useAuthStore((state) => state.user);
  const isAdmin = currentUser?.role === "admin";
  const [users, setUsers] = useState<User[]>(DEMO_MODE ? demoUsers : []);
  const [roles, setRoles] = useState<RoleRecord[]>(DEMO_MODE ? demoRoles : []);
  const [query, setQuery] = useState("");
  const [userOpen, setUserOpen] = useState(false);
  const [roleOpen, setRoleOpen] = useState(false);
  const [editingRoleId, setEditingRoleId] = useState<number | null>(null);
  const [userForm, setUserForm] = useState<UserForm>(emptyUser);
  const [roleForm, setRoleForm] = useState<RoleForm>(emptyRole);
  const [loading, setLoading] = useState(!DEMO_MODE);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [confirmTarget, setConfirmTarget] = useState<ConfirmTarget>(null);

  const refresh = async () => {
    if (DEMO_MODE) return;
    setLoading(true);
    setError("");
    const results = await Promise.allSettled([api.users(), api.roles()]);
    if (results[0].status === "fulfilled") setUsers(results[0].value);
    if (results[1].status === "fulfilled") setRoles(results[1].value);
    const rejected = results.find((result) => result.status === "rejected");
    if (rejected?.status === "rejected")
      setError(sanitizeError(rejected.reason));
    setLoading(false);
  };
  useEffect(() => {
    void refresh();
  }, []);
  useRealtimeRefresh(["users.changed", "roles.changed"], refresh);

  const visibleUsers = useMemo(
    () =>
      users.filter((user) =>
        `${user.email} ${user.role}`
          .toLowerCase()
          .includes(query.toLowerCase()),
      ),
    [users, query],
  );
  const adminCount = users.filter(
    (user) => user.role === "admin" && !user.disabled,
  ).length;
  const roleOptions = DEMO_MODE ? demoRoles : roles;

  const submitUser = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      if (DEMO_MODE)
        setUsers((current) => [
          ...current,
          {
            id: Date.now(),
            email: userForm.email,
            role: userForm.role,
            disabled: false,
          },
        ]);
      else {
        await api.createUser(userForm);
        await refresh();
      }
      setUserOpen(false);
      setUserForm(emptyUser);
      toast.success(t("users.userCreated"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const updateUser = async (
    user: User,
    patch: { role?: string; disabled?: boolean },
  ) => {
    setBusy(true);
    setError("");
    try {
      if (DEMO_MODE)
        setUsers((current) =>
          current.map((item) =>
            item.id === user.id ? { ...item, ...patch } : item,
          ),
        );
      else {
        await api.updateUser(user.id, patch);
        await refresh();
      }
      toast.success(t("users.userUpdated"));
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };
  const deleteUser = (user: User) => {
    if (!isAdmin) return;
    setConfirmTarget({ kind: "user", item: user });
  };
  const deleteRole = (role: RoleRecord) => {
    if (!isAdmin || role.system_managed) return;
    setConfirmTarget({ kind: "role", item: role });
  };
  const confirmDelete = async () => {
    if (!confirmTarget) return;
    const target = confirmTarget;
    setConfirmTarget(null);
    setBusy(true);
    try {
      if (target.kind === "user") {
        if (DEMO_MODE)
          setUsers((current) =>
            current.filter((item) => item.id !== target.item.id),
          );
        else {
          await api.deleteUser(target.item.id);
          await refresh();
        }
        toast.success(t("users.userDeleted"));
      } else {
        if (DEMO_MODE)
          setRoles((current) =>
            current.filter((item) => item.id !== target.item.id),
          );
        else {
          await api.deleteRole(target.item.id);
          await refresh();
        }
        toast.success(t("users.roleDeleted"));
      }
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };
  const revokeSessions = async (user: User) => {
    setBusy(true);
    try {
      const result = DEMO_MODE
        ? { revoked: 1 }
        : await api.revokeUserSessions(user.id);
      toast.success(t("users.sessionsRevoked"), {
        description: t("users.sessionsInvalidated", { count: result.revoked }),
      });
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };

  const openCreateRole = () => {
    setEditingRoleId(null);
    setRoleForm(emptyRole);
    setRoleOpen(true);
  };
  const openEditRole = (role: RoleRecord) => {
    const scopedHostIds =
      role.scopes?.flatMap((scope) => scope.proxy_host_ids) ?? [];
    setEditingRoleId(role.id);
    setRoleForm({
      slug: role.slug,
      name: role.name,
      description: role.description,
      permissions: [...role.permissions],
      scopeHostIds: [...new Set(scopedHostIds)].join(", "),
    });
    setRoleOpen(true);
  };
  const togglePermission = (permission: PermissionKey) =>
    setRoleForm((current) => ({
      ...current,
      permissions: current.permissions.includes(permission)
        ? current.permissions.filter((item) => item !== permission)
        : [...current.permissions, permission],
    }));
  const submitRole = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError("");
    try {
      const hostIds = roleForm.scopeHostIds
        .split(",")
        .map((value) => Number(value.trim()))
        .filter((value) => Number.isInteger(value) && value > 0);
      const scopes: RolePermissionScope[] =
        hostIds.length === 0
          ? []
          : [
              ...(roleForm.permissions.includes("proxy_hosts.read")
                ? [
                    {
                      permission: "proxy_hosts.read" as const,
                      proxy_host_ids: hostIds,
                    },
                  ]
                : []),
              ...(roleForm.permissions.includes("proxy_hosts.write")
                ? [
                    {
                      permission: "proxy_hosts.write" as const,
                      proxy_host_ids: hostIds,
                    },
                  ]
                : []),
            ];
      if (roleForm.scopeHostIds.trim() && hostIds.length === 0) {
        setError(t("users.scopeIdsError"));
        return;
      }
      if (hostIds.length > 0 && scopes.length === 0) {
        setError(t("users.scopePermissionError"));
        return;
      }
      if (DEMO_MODE) {
        const next: RoleRecord = {
          id: editingRoleId ?? Date.now(),
          slug: roleForm.slug,
          name: roleForm.name,
          description: roleForm.description,
          system_managed: false,
          permissions: roleForm.permissions,
          scopes,
        };
        setRoles((current) =>
          editingRoleId == null
            ? [...current, next]
            : current.map((role) => (role.id === editingRoleId ? next : role)),
        );
      } else if (editingRoleId == null) {
        await api.createRole({
          slug: roleForm.slug,
          name: roleForm.name,
          description: roleForm.description,
          permissions: roleForm.permissions,
          scopes,
        });
        await refresh();
      } else {
        await api.updateRole(editingRoleId, {
          name: roleForm.name,
          description: roleForm.description,
          permissions: roleForm.permissions,
          scopes,
        });
        await refresh();
      }
      setRoleOpen(false);
      toast.success(
        editingRoleId == null ? t("users.roleCreated") : t("users.roleUpdated"),
      );
    } catch (exception) {
      setError(sanitizeError(exception));
    } finally {
      setBusy(false);
    }
  };
  return (
    <Main>
      <PageHeader
        title={t("users.title")}
        description={t("users.description")}
        action={
          <>
            <Badge
              variant="outline"
              className="hidden gap-1.5 rounded-full sm:inline-flex"
            >
              <span
                className={`size-1.5 rounded-full ${DEMO_MODE ? "bg-amber-500" : "bg-emerald-500"}`}
              />
              {DEMO_MODE ? t("users.demoData") : t("users.apiConnected")}
            </Badge>
            <Button
              onClick={() => {
                setUserForm(emptyUser);
                setUserOpen(true);
              }}
              disabled={!isAdmin}
            >
              <MailPlus />
              {t("users.invite")}
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
        <Summary
          icon={UsersIcon}
          label={t("users.teamMembers")}
          value={String(users.length)}
          detail={t("users.activeAccounts", {
            count: users.filter((user) => !user.disabled).length,
          })}
        />
        <Summary
          icon={ShieldCheck}
          label={t("users.administrators")}
          value={String(adminCount)}
          detail={t("users.fullControlAccounts")}
        />
        <Summary
          icon={UserRound}
          label={t("users.disabledAccounts")}
          value={String(users.filter((user) => user.disabled).length)}
          detail={t("users.accessSuspended")}
        />
      </div>
      <Card>
        <CardHeader className="gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div>
            <CardTitle>{t("users.teamMembers")}</CardTitle>
            <CardDescription>
              {DEMO_MODE
                ? t("users.demoTeamDescription")
                : t("users.apiTeamDescription")}
            </CardDescription>
          </div>
          <div className="flex w-full gap-2 sm:w-auto">
            <div className="relative w-full sm:w-64">
              <Search className="absolute left-2.5 top-2.5 size-4 text-muted-foreground" />
              <Input
                aria-label={t("users.searchUsers")}
                placeholder={t("users.searchPlaceholder")}
                value={query}
                onChange={(event) => setQuery(event.target.value)}
                className="h-9 pl-8"
              />
            </div>
            <Button
              variant="outline"
              size="icon"
              aria-label={t("users.refreshUsers")}
              onClick={() => void refresh()}
              disabled={loading}
            >
              <RefreshCw className={loading ? "animate-spin" : ""} />
            </Button>
          </div>
        </CardHeader>
        <CardContent>
          {loading ? (
            <div className="space-y-3 py-2">
              {[1, 2, 3].map((item) => (
                <div
                  className="h-12 animate-pulse rounded-md bg-muted"
                  key={item}
                />
              ))}
            </div>
          ) : (
            <Table
              users={visibleUsers}
              roles={roleOptions}
              currentUser={currentUser}
              canWrite={isAdmin}
              busy={busy}
              onRoleChange={updateUser}
              onToggle={(user) =>
                void updateUser(user, { disabled: !user.disabled })
              }
              onRevoke={revokeSessions}
              onDelete={deleteUser}
            />
          )}
          {!loading && visibleUsers.length === 0 && (
            <p className="py-8 text-center text-sm text-muted-foreground">
              {t("users.noMatch")}
            </p>
          )}
        </CardContent>
      </Card>
      <Card className="mt-6">
        <CardHeader className="flex flex-row items-center justify-between">
          <div>
            <CardTitle>{t("users.rolesPermissions")}</CardTitle>
            <CardDescription>{t("users.rolesDescription")}</CardDescription>
          </div>
          <Button
            variant="outline"
            onClick={openCreateRole}
            disabled={!isAdmin}
          >
            <Plus />
            {t("users.createCustomRole")}
          </Button>
        </CardHeader>
        <CardContent>
          <div className="grid gap-3 md:grid-cols-3">
            {roles.map((role) => (
              <div className="rounded-lg border p-4" key={role.id}>
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="font-medium">{role.name}</p>
                    <p className="font-mono text-xs text-muted-foreground">
                      {role.slug}
                    </p>
                  </div>
                  <Badge
                    variant={role.system_managed ? "secondary" : "outline"}
                  >
                    {role.system_managed
                      ? t("users.system")
                      : t("users.custom")}
                  </Badge>
                </div>
                <p className="mt-3 min-h-10 text-sm text-muted-foreground">
                  {role.description || t("users.noDescription")}
                </p>
                <p className="mt-3 text-xs text-muted-foreground">
                  {t("users.permissionCount", {
                    count: role.permissions.length,
                  })}
                  {role.scopes?.length
                    ? ` · ${t("users.scopeCount", { count: role.scopes.length })}`
                    : ""}
                </p>
                <div className="mt-3 flex gap-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    onClick={() => openEditRole(role)}
                    disabled={!isAdmin || role.system_managed}
                  >
                    <Pencil />
                    {t("users.edit")}
                  </Button>
                  <Button
                    variant="ghost"
                    size="icon"
                    aria-label={`Delete ${role.name}`}
                    onClick={() => void deleteRole(role)}
                    disabled={!isAdmin || role.system_managed || busy}
                  >
                    <Trash2 />
                  </Button>
                </div>
              </div>
            ))}
          </div>
          {roles.length === 0 && (
            <p className="py-8 text-center text-sm text-muted-foreground">
              {t("users.noRoles")}
            </p>
          )}
        </CardContent>
      </Card>

      <Dialog open={userOpen} onOpenChange={setUserOpen}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>{t("users.createUserTitle")}</DialogTitle>
            <DialogDescription>
              {t("users.createUserDescription")}
            </DialogDescription>
          </DialogHeader>
          <form
            id="user-form"
            className="space-y-4"
            onSubmit={(event) => void submitUser(event)}
          >
            <Field
              label={t("common.email")}
              type="email"
              value={userForm.email}
              onChange={(value) => setUserForm({ ...userForm, email: value })}
              placeholder="operator@example.com"
            />
            <Field
              label={t("users.temporaryPassword")}
              type="password"
              value={userForm.password}
              onChange={(value) =>
                setUserForm({ ...userForm, password: value })
              }
              autoComplete="new-password"
            />
            <div className="space-y-2">
              <Label htmlFor="user-role">{t("common.role")}</Label>
              <select
                id="user-role"
                value={userForm.role}
                onChange={(event) =>
                  setUserForm({ ...userForm, role: event.target.value })
                }
                className="h-9 w-full rounded-md border border-input bg-background px-3 text-sm"
              >
                {roleOptions.map((role) => (
                  <option key={role.slug} value={role.slug}>
                    {role.name}
                  </option>
                ))}
              </select>
            </div>
          </form>
          <DialogFooter>
            <Button variant="outline" onClick={() => setUserOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" form="user-form" disabled={busy}>
              <MailPlus />
              {t("users.create")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <Dialog open={roleOpen} onOpenChange={setRoleOpen}>
        <DialogContent className="max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>
              {editingRoleId == null
                ? t("users.createCustomRoleTitle")
                : t("users.editRoleTitle")}
            </DialogTitle>
            <DialogDescription>{t("users.roleDescription")}</DialogDescription>
          </DialogHeader>
          <form
            id="role-form"
            className="space-y-4"
            onSubmit={(event) => void submitRole(event)}
          >
            <div className="grid gap-4 sm:grid-cols-2">
              <Field
                label={t("roles.slug")}
                value={roleForm.slug}
                onChange={(value) => setRoleForm({ ...roleForm, slug: value })}
                disabled={editingRoleId != null}
              />
              <Field
                label={t("users.name")}
                value={roleForm.name}
                onChange={(value) => setRoleForm({ ...roleForm, name: value })}
              />
              <div className="sm:col-span-2">
                <Field
                  label={t("users.descriptionField")}
                  value={roleForm.description}
                  onChange={(value) =>
                    setRoleForm({ ...roleForm, description: value })
                  }
                />
              </div>
            </div>
            <div>
              <p className="mb-2 text-sm font-medium">
                {t("roles.permissions")}
              </p>
              <div className="grid gap-2 sm:grid-cols-2">
                {permissionOptions.map((permission) => (
                  <label
                    className="flex items-center gap-2 rounded-md border px-3 py-2 text-xs"
                    key={permission}
                  >
                    <input
                      type="checkbox"
                      checked={roleForm.permissions.includes(permission)}
                      onChange={() => togglePermission(permission)}
                      className="size-4 accent-primary"
                    />
                    {permission}
                  </label>
                ))}
              </div>
            </div>
            <Field
              label={t("users.scopedHostIds")}
              value={roleForm.scopeHostIds}
              onChange={(value) =>
                setRoleForm({ ...roleForm, scopeHostIds: value })
              }
              placeholder="1, 2, 3"
            />
            <p className="-mt-2 text-xs text-muted-foreground">
              {t("users.scopedHint")}
            </p>
          </form>
          <DialogFooter>
            <Button variant="outline" onClick={() => setRoleOpen(false)}>
              {t("common.cancel")}
            </Button>
            <Button type="submit" form="role-form" disabled={busy || !isAdmin}>
              <Plus />
              {t("common.save")}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      <ConfirmDialog
        open={confirmTarget != null}
        onOpenChange={(open) => {
          if (!open && !busy) setConfirmTarget(null);
        }}
        title={
          confirmTarget?.kind === "user"
            ? t("users.deleteUserTitle")
            : t("users.deleteRoleTitle")
        }
        description={
          confirmTarget?.kind === "user"
            ? t("users.deleteUserDescription", {
                value: confirmTarget.item.email,
              })
            : t("users.deleteRoleDescription", {
                value: confirmTarget?.item.name ?? t("users.name"),
              })
        }
        pending={busy}
        onConfirm={() => void confirmDelete()}
      />
    </Main>
  );
}

function Table({
  users,
  roles,
  currentUser,
  canWrite,
  busy,
  onRoleChange,
  onToggle,
  onRevoke,
  onDelete,
}: {
  users: User[];
  roles: RoleRecord[];
  currentUser: User | null;
  canWrite: boolean;
  busy: boolean;
  onRoleChange: (
    user: User,
    patch: { role?: string; disabled?: boolean },
  ) => void;
  onToggle: (user: User) => void;
  onRevoke: (user: User) => void;
  onDelete: (user: User) => void;
}) {
  const { t } = useTranslation();
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b text-left text-xs text-muted-foreground">
            <th className="pb-3 font-medium">{t("users.member")}</th>
            <th className="pb-3 font-medium">{t("common.role")}</th>
            <th className="pb-3 font-medium">{t("users.status")}</th>
            <th className="pb-3 text-right font-medium">
              {t("users.actions")}
            </th>
          </tr>
        </thead>
        <tbody>
          {users.map((user) => {
            const self = user.id === currentUser?.id;
            return (
              <tr className="border-b last:border-0" key={user.id}>
                <td className="py-4">
                  <div className="font-medium">
                    {user.email.split("@")[0]}
                    {self ? ` ${t("users.self")}` : ""}
                  </div>
                  <div className="text-xs text-muted-foreground">
                    {user.email}
                  </div>
                </td>
                <td className="py-4">
                  <select
                    aria-label={t("users.roleFor", { value: user.email })}
                    value={user.role}
                    onChange={(event) =>
                      onRoleChange(user, { role: event.target.value })
                    }
                    disabled={!canWrite || self || busy}
                    className="h-8 rounded-md border border-input bg-background px-2 text-xs"
                  >
                    {roles.map((role) => (
                      <option key={role.slug} value={role.slug}>
                        {role.name}
                      </option>
                    ))}
                  </select>
                </td>
                <td className="py-4">
                  <StatusBadge status={user.disabled ? "warning" : "healthy"}>
                    {user.disabled ? t("users.disabled") : t("users.active")}
                  </StatusBadge>
                </td>
                <td className="py-4 text-right">
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        aria-label={t("users.actionsFor", {
                          value: user.email,
                        })}
                      >
                        <Ellipsis />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="end">
                      <DropdownMenuItem
                        onClick={() => onToggle(user)}
                        disabled={!canWrite || self || busy}
                      >
                        {user.disabled
                          ? t("users.enableAccount")
                          : t("users.disableAccount")}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onRevoke(user)}
                        disabled={!canWrite || busy}
                      >
                        {t("users.revokeSessions")}
                      </DropdownMenuItem>
                      <DropdownMenuSeparator />
                      <DropdownMenuItem
                        variant="destructive"
                        onClick={() => onDelete(user)}
                        disabled={!canWrite || self || busy}
                      >
                        <Trash2 />
                        {t("users.deleteUser")}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function Field({
  label,
  value,
  onChange,
  type = "text",
  placeholder,
  disabled = false,
  autoComplete,
}: {
  label: string;
  value: string;
  onChange: (value: string) => void;
  type?: string;
  placeholder?: string;
  disabled?: boolean;
  autoComplete?: string;
}) {
  return (
    <div className="space-y-2">
      <Label>{label}</Label>
      <Input
        type={type}
        value={value}
        onChange={(event) => onChange(event.target.value)}
        placeholder={placeholder}
        disabled={disabled}
        autoComplete={autoComplete}
        required
      />
    </div>
  );
}
function Summary({
  icon: Icon,
  label,
  value,
  detail,
}: {
  icon: typeof UsersIcon;
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
