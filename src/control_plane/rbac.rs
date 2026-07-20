use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role { Admin, Operator, Viewer }
impl Role {
    pub fn parse(s: &str) -> Option<Self> { match s { "admin" => Some(Self::Admin), "operator" => Some(Self::Operator), "viewer" => Some(Self::Viewer), _ => None } }
    pub fn as_str(self) -> &'static str { match self { Self::Admin => "admin", Self::Operator => "operator", Self::Viewer => "viewer" } }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Permission { ProxyHostsRead, ProxyHostsWrite, CertificatesRead, CertificatesWrite, UsersManage, RolesManage, AuditLogsRead, AuditLogsExport, SystemSettingsManage, SessionsRevoke }
impl Permission { pub const fn key(self) -> &'static str { match self { Self::ProxyHostsRead => "proxy_hosts.read", Self::ProxyHostsWrite => "proxy_hosts.write", Self::CertificatesRead => "certificates.read", Self::CertificatesWrite => "certificates.write", Self::UsersManage => "users.manage", Self::RolesManage => "roles.manage", Self::AuditLogsRead => "audit_logs.read", Self::AuditLogsExport => "audit_logs.export", Self::SystemSettingsManage => "system.settings.manage", Self::SessionsRevoke => "sessions.revoke" } } }
pub type PermissionKey = Permission;
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceContext;
impl ResourceContext { pub const GLOBAL: Self = Self; }

pub fn allowed(role: Role, permission: Permission) -> bool { match permission { Permission::ProxyHostsRead | Permission::CertificatesRead | Permission::AuditLogsRead => true, Permission::ProxyHostsWrite | Permission::CertificatesWrite => matches!(role, Role::Admin | Role::Operator), Permission::UsersManage | Permission::RolesManage | Permission::AuditLogsExport | Permission::SystemSettingsManage | Permission::SessionsRevoke => matches!(role, Role::Admin) } }

pub async fn authorize(pool: &SqlitePool, user: &crate::control_plane::models::User, permission: PermissionKey, _context: ResourceContext) -> Result<bool, sqlx::Error> { if Role::parse(&user.role).is_none() { return Ok(false); } crate::control_plane::repository::user_has_permission(pool, user.id, permission.key(), None).await }
