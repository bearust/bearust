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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ResourceContext {
    Global,
    ProxyHost(i64),
}
impl ResourceContext {
    /// Backwards-compatible spelling for handlers that authorize global resources.
    pub const GLOBAL: Self = Self::Global;
}

pub fn allowed(role: Role, permission: Permission) -> bool { match permission { Permission::ProxyHostsRead | Permission::CertificatesRead | Permission::AuditLogsRead => true, Permission::ProxyHostsWrite | Permission::CertificatesWrite => matches!(role, Role::Admin | Role::Operator), Permission::UsersManage | Permission::RolesManage | Permission::AuditLogsExport | Permission::SystemSettingsManage | Permission::SessionsRevoke => matches!(role, Role::Admin) } }

pub async fn authorize(pool: &SqlitePool, user: &crate::control_plane::models::User, permission: PermissionKey, context: ResourceContext) -> Result<bool, sqlx::Error> {
    let scope = match context {
        ResourceContext::Global => None,
        ResourceContext::ProxyHost(id) => Some(("proxy_host", id)),
    };
    crate::control_plane::repository::user_has_permission(pool, user.id, permission.key(), scope).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::repository;
    use sqlx::{sqlite::SqlitePoolOptions, Row, SqlitePool};

    async fn pool() -> SqlitePool {
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite");
        repository::migrate(&pool).await.expect("migrate");
        pool
    }

    async fn scoped_user(pool: &SqlitePool, scope_id: i64) -> crate::control_plane::models::User {
        sqlx::query("INSERT INTO roles(slug,name,created_at,updated_at) VALUES('scoped','Scoped',datetime('now'),datetime('now'))")
            .execute(pool).await.expect("role");
        sqlx::query("INSERT INTO users(email,password_hash,role,created_at,disabled) VALUES('scoped@example.test','hash','scoped',datetime('now'),0)")
            .execute(pool).await.expect("user");
        let permission_id: i64 = sqlx::query("SELECT id FROM permissions WHERE key=?")
            .bind(Permission::ProxyHostsRead.key()).fetch_one(pool).await.expect("permission").get("id");
        let role_id: i64 = sqlx::query("SELECT id FROM roles WHERE slug='scoped'")
            .fetch_one(pool).await.expect("role id").get("id");
        sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) VALUES(?,?,?,?)")
            .bind(role_id).bind(permission_id).bind("proxy_host").bind(scope_id).execute(pool).await.expect("scope");
        repository::find_user(pool, "scoped@example.test")
            .await
            .expect("find")
            .map(|(user, _)| user)
            .expect("user")
    }

    #[tokio::test]
    async fn global_grant_authorizes_global_and_host_contexts() {
        let pool = pool().await;
        let user = repository::insert_user(&pool, "admin@example.test", "hash", "admin").await.expect("user");
        assert!(authorize(&pool, &user, Permission::ProxyHostsRead, ResourceContext::Global).await.expect("auth"));
        assert!(authorize(&pool, &user, Permission::ProxyHostsRead, ResourceContext::ProxyHost(42)).await.expect("auth"));
    }

    #[tokio::test]
    async fn exact_host_grant_only_authorizes_assigned_host() {
        let pool = pool().await;
        let user = scoped_user(&pool, 42).await;
        assert!(authorize(&pool, &user, Permission::ProxyHostsRead, ResourceContext::ProxyHost(42)).await.expect("auth"));
        assert!(!authorize(&pool, &user, Permission::ProxyHostsRead, ResourceContext::ProxyHost(43)).await.expect("auth"));
        assert!(!authorize(&pool, &user, Permission::ProxyHostsRead, ResourceContext::Global).await.expect("auth"));
    }

    #[tokio::test]
    async fn unknown_scope_is_denied() {
        let pool = pool().await;
        let user = repository::insert_user(&pool, "admin@example.test", "hash", "admin").await.expect("user");
        assert!(!repository::user_has_permission(&pool, user.id, Permission::ProxyHostsRead.key(), Some(("unknown", 42))).await.expect("auth"));
    }
}
