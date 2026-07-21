use crate::control_plane::models::{
    AcmeChallenge, AcmeEnvironment, AcmeRequest, AcmeStatus, AuditLogItem, AuditLogPage,
    AuditLogQuery, CertificateMetadata, ProxyHost, RoleDetail, RolePermissionScope, User,
};
use crate::control_plane::rbac::Role;
use sqlx::{any::AnyPoolOptions, Row, SqlitePool};
use std::sync::Once;
use uuid::Uuid;

/// Database pool type used by the control plane once all repositories have
/// been migrated to SQLx's backend-agnostic driver.
pub type DbPool = sqlx::AnyPool;

static ANY_DRIVERS: Once = Once::new();

/// Validate a database URL without including credentials in the resulting
/// error.  Only the backends supported by the application are accepted.
pub fn validate_database_url(url: &str) -> Result<(), sqlx::Error> {
    let scheme = url
        .split_once("://")
        .map(|(scheme, _)| scheme)
        .or_else(|| url.split_once(':').map(|(scheme, _)| scheme))
        .unwrap_or("");
    if url.is_empty()
        || !matches!(
            scheme.to_ascii_lowercase().as_str(),
            "sqlite" | "postgres" | "postgresql" | "mysql"
        )
    {
        return Err(sqlx::Error::Configuration(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "unsupported database URL",
        ))));
    }
    Ok(())
}

pub async fn connect(url: &str) -> Result<DbPool, sqlx::Error> {
    validate_database_url(url)?;
    ANY_DRIVERS.call_once(sqlx::any::install_default_drivers);
    AnyPoolOptions::new()
        .max_connections(8)
        .connect(url)
        .await
}
pub async fn migrate(pool: &DbPool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("./migrations").run(pool).await?;

    // The first release created these columns inline. Add them for those
    // databases without dropping or rewriting existing rows. Each backend
    // reports a duplicate-column error differently, so only that error is
    // ignored; all other failures abort startup.
    for statement in [
        "ALTER TABLE users ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0",
        "ALTER TABLE acme_certificates ADD COLUMN secret_ref TEXT",
    ] {
        match sqlx::query(statement).execute(pool).await {
            Ok(_) => {}
            Err(error) if is_duplicate_column(&error) => {}
            Err(error) => return Err(error),
        }
    }
    // Normalize nullable scope values left by the pre-migration schema. Fresh
    // databases use the non-null ('', 0) global representation.
    // Legacy schemas allow either scope column to be NULL. Normalize both
    // columns together so a partially-null row cannot remain ambiguous.
    let _ = sqlx::query("UPDATE role_permissions SET scope_type='', scope_id=0 WHERE scope_type IS NULL OR scope_id IS NULL")
        .execute(pool).await?;

    let permissions = [
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
    for key in permissions {
            sqlx::query(
                "INSERT INTO permissions(id,key) SELECT ?,? WHERE NOT EXISTS (SELECT 1 FROM permissions WHERE key=?)",
            )
        .bind(deterministic_id(key))
        .bind(key)
        .bind(key)
        .execute(pool)
        .await?;
    }

    let now = chrono::Utc::now().to_rfc3339();
    for (slug, name) in [("admin", "Administrator"), ("operator", "Operator"), ("viewer", "Viewer")] {
        sqlx::query(
            "INSERT INTO roles(id,slug,name,system_managed,created_at,updated_at) SELECT ?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM roles WHERE slug=?)",
        )
        .bind(deterministic_id(slug))
        .bind(slug)
        .bind(name)
        .bind(1_i64)
        .bind(&now)
        .bind(&now)
        .bind(slug)
        .execute(pool)
        .await?;
    }

    let assignments: [(&str, &[&str]); 3] = [
        ("admin", &permissions),
        (
            "operator",
            &["proxy_hosts.read", "proxy_hosts.write", "certificates.read", "certificates.write", "audit_logs.read"],
        ),
        ("viewer", &["proxy_hosts.read", "certificates.read", "audit_logs.read"]),
    ];
    for (slug, keys) in assignments {
        for key in keys {
            sqlx::query(
                "INSERT INTO role_permissions(role_id,permission_id) SELECT r.id,p.id FROM roles r,permissions p WHERE r.slug=? AND p.key=? AND NOT EXISTS (SELECT 1 FROM role_permissions rp WHERE rp.role_id=r.id AND rp.permission_id=p.id AND rp.scope_type='' AND rp.scope_id=0)",
            )
            .bind(slug)
            .bind(*key)
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

fn deterministic_id(value: &str) -> i64 {
    let bytes = *Uuid::new_v5(&Uuid::NAMESPACE_OID, value.as_bytes()).as_bytes();
    let mut raw = [0u8; 8]; raw.copy_from_slice(&bytes[..8]);
    (i64::from_be_bytes(raw) & i64::MAX).max(1)
}

fn generated_id() -> i64 {
    let bytes = *Uuid::new_v4().as_bytes();
    let mut raw = [0u8; 8]; raw.copy_from_slice(&bytes[..8]);
    (i64::from_be_bytes(raw) & i64::MAX).max(1)
}

fn is_duplicate_column(error: &sqlx::Error) -> bool {
    let message = error.to_string().to_ascii_lowercase();
    message.contains("duplicate column") || message.contains("already exists") || message.contains("1060") || message.contains("42701")
}

pub async fn set_acme_secret_ref(pool: &SqlitePool, certificate_id: i64, secret_ref: &str) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("UPDATE acme_certificates SET secret_ref=? WHERE certificate_id=?").bind(secret_ref).bind(certificate_id).execute(pool).await?.rows_affected())
}
pub async fn acme_secret_ref(pool: &SqlitePool, certificate_id: i64) -> Result<Option<String>, sqlx::Error> {
    Ok(sqlx::query("SELECT secret_ref FROM acme_certificates WHERE certificate_id=?").bind(certificate_id).fetch_optional(pool).await?.and_then(|r| r.get::<Option<String>, _>("secret_ref")))
}

fn acme_status_from_row(r: &sqlx::sqlite::SqliteRow) -> Result<AcmeStatus, sqlx::Error> {
    let environment = match r.get::<String, _>("environment").as_str() {
        "staging" => AcmeEnvironment::Staging,
        "production" => AcmeEnvironment::Production,
        value => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid ACME environment: {value}"
            )))
        }
    };
    let challenge = match r.get::<String, _>("challenge").as_str() {
        "http01" => AcmeChallenge::Http01,
        "cloudflare_dns01" => AcmeChallenge::CloudflareDns01,
        value => {
            return Err(sqlx::Error::Protocol(format!(
                "invalid ACME challenge: {value}"
            )))
        }
    };
    let hostnames = serde_json::from_str(&r.get::<String, _>("hostnames"))
        .map_err(|e| sqlx::Error::Protocol(format!("invalid certificate hostnames: {e}")))?;
    Ok(AcmeStatus {
        certificate_id: r.get("certificate_id"),
        environment,
        challenge,
        hostnames,
        renewal_state: r.get("renewal_state"),
        next_renewal_at: r.get("next_renewal_at"),
        last_attempt_at: r.get("last_attempt_at"),
        last_error_code: r.get("last_error_code"),
    })
}

pub async fn insert_acme_certificate(
    pool: &SqlitePool,
    certificate_id: i64,
    request: &AcmeRequest,
) -> Result<AcmeStatus, sqlx::Error> {
    let request = request
        .clone()
        .normalized()
        .map_err(|e| sqlx::Error::Protocol(e))?;
    let environment = match request.environment {
        AcmeEnvironment::Staging => "staging",
        AcmeEnvironment::Production => "production",
    };
    let challenge = match request.challenge {
        AcmeChallenge::Http01 => "http01",
        AcmeChallenge::CloudflareDns01 => "cloudflare_dns01",
    };
    let hosts = serde_json::to_string(&request.hostnames)
        .map_err(|e| sqlx::Error::Protocol(e.to_string()))?;
    let mut tx = pool.begin().await?;
    let exists = sqlx::query("SELECT id FROM certificates WHERE id=?")
        .bind(certificate_id)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(sqlx::Error::RowNotFound);
    }
    sqlx::query("INSERT INTO acme_certificates(certificate_id,environment,challenge,renewal_state,next_renewal_at,last_attempt_at,last_error_code) VALUES(?,?,?, 'pending', NULL, NULL, NULL)")
        .bind(certificate_id).bind(environment).bind(challenge).execute(&mut *tx).await?;
    sqlx::query("UPDATE certificates SET covered_hostnames=? WHERE id=?")
        .bind(hosts)
        .bind(certificate_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    get_acme_status(pool, certificate_id)
        .await?
        .ok_or_else(|| sqlx::Error::RowNotFound)
}

pub async fn update_acme_status(
    pool: &SqlitePool,
    certificate_id: i64,
    renewal_state: &str,
    next_renewal_at: Option<&str>,
    last_attempt_at: Option<&str>,
    last_error_code: Option<&str>,
) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("UPDATE acme_certificates SET renewal_state=?,next_renewal_at=?,last_attempt_at=?,last_error_code=? WHERE certificate_id=?")
        .bind(renewal_state).bind(next_renewal_at).bind(last_attempt_at).bind(last_error_code).bind(certificate_id).execute(pool).await?.rows_affected())
}

pub async fn get_acme_status(
    pool: &SqlitePool,
    certificate_id: i64,
) -> Result<Option<AcmeStatus>, sqlx::Error> {
    let row = sqlx::query("SELECT a.certificate_id,a.environment,a.challenge,c.covered_hostnames AS hostnames,a.renewal_state,a.next_renewal_at,a.last_attempt_at,a.last_error_code FROM acme_certificates a JOIN certificates c ON c.id=a.certificate_id WHERE a.certificate_id=?")
        .bind(certificate_id).fetch_optional(pool).await?;
    row.as_ref().map(acme_status_from_row).transpose()
}

pub async fn list_due_acme_certificates(
    pool: &SqlitePool,
    at: &str,
) -> Result<Vec<AcmeStatus>, sqlx::Error> {
    let rows = sqlx::query("SELECT a.certificate_id,a.environment,a.challenge,c.covered_hostnames AS hostnames,a.renewal_state,a.next_renewal_at,a.last_attempt_at,a.last_error_code FROM acme_certificates a JOIN certificates c ON c.id=a.certificate_id WHERE a.next_renewal_at IS NOT NULL AND a.next_renewal_at<=? ORDER BY a.next_renewal_at,a.certificate_id")
        .bind(at).fetch_all(pool).await?;
    rows.iter().map(acme_status_from_row).collect()
}
pub async fn user_count(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query("SELECT COUNT(*) c FROM users")
        .fetch_one(pool)
        .await?
        .get("c"))
}
pub async fn insert_user(
    pool: &SqlitePool,
    email: &str,
    hash: &str,
    role: &str,
) -> Result<User, sqlx::Error> {
    let role_name = role;
    if Role::parse(role_name).is_none()
        && sqlx::query("SELECT 1 FROM roles WHERE slug=?")
            .bind(role_name)
            .fetch_optional(pool)
            .await?
            .is_none()
    {
        return Err(sqlx::Error::Protocol("invalid role".into()));
    }
    let now = chrono::Utc::now().to_rfc3339();
    let id = generated_id();
    sqlx::query("INSERT INTO users(id,email,password_hash,role,created_at,disabled) VALUES(?,?,?,?,?,0)")
    .bind(id)
    .bind(email)
    .bind(hash)
    .bind(role_name)
    .bind(&now)
    .execute(pool).await?;
    Ok(User {
        id,
        email: email.into(),
        role: role_name.into(),
        created_at: now,
        disabled: false,
    })
}

/// Create the first administrator while holding SQLite's write lock.
/// Returning `Ok(None)` means another request completed setup first.
pub async fn insert_initial_admin(
    pool: &SqlitePool,
    email: &str,
    hash: &str,
) -> Result<Option<User>, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let count = sqlx::query("SELECT COUNT(*) c FROM users")
        .fetch_one(&mut *conn).await?.get::<i64, _>("c");
    if count != 0 {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return Ok(None);
    }
    let role = "admin";
    let now = chrono::Utc::now().to_rfc3339();
    let id = generated_id();
    let result = sqlx::query("INSERT INTO users(id,email,password_hash,role,created_at,disabled) VALUES(?,?,?,?,?,0)")
    .bind(id).bind(email).bind(hash).bind(role).bind(&now)
    .execute(&mut *conn).await;
    match result {
        Ok(_) => {},
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(error);
        }
    };
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(Some(User {
        id, email: email.into(), role: role.into(),
        created_at: now, disabled: false,
    }))
}
pub async fn find_user(
    pool: &SqlitePool,
    email: &str,
) -> Result<Option<(User, String)>, sqlx::Error> {
    let r = sqlx::query("SELECT id,email,password_hash,role,created_at,disabled FROM users WHERE email=? AND disabled=0")
        .bind(email)
        .fetch_optional(pool)
        .await?;
    Ok(r.map(|x| {
        (
            User {
                id: x.get("id"),
                email: x.get("email"),
                role: x.get("role"),
                created_at: x.get("created_at"),
                disabled: x.get::<i64, _>("disabled") != 0,
            },
            x.get("password_hash"),
        )
    }))
}
pub async fn find_user_by_session(
    pool: &SqlitePool,
    hash: &str,
) -> Result<Option<User>, sqlx::Error> {
    let r=sqlx::query("SELECT u.id,u.email,u.role,u.created_at,u.disabled FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>? AND u.disabled=0").bind(hash).bind(chrono::Utc::now().to_rfc3339()).fetch_optional(pool).await?;
    Ok(r.map(|x| User {
        id: x.get("id"),
        email: x.get("email"),
        role: x.get("role"),
        created_at: x.get("created_at"),
        disabled: x.get::<i64, _>("disabled") != 0,
    }))
}

pub async fn list_users(pool: &SqlitePool) -> Result<Vec<User>, sqlx::Error> {
    let rows = sqlx::query("SELECT id,email,role,created_at,disabled FROM users ORDER BY id")
        .fetch_all(pool).await?;
    Ok(rows.into_iter().map(|x| User {
        id: x.get("id"), email: x.get("email"), role: x.get("role"),
        created_at: x.get("created_at"), disabled: x.get::<i64, _>("disabled") != 0,
    }).collect())
}

fn role_detail_from_row(row: &sqlx::sqlite::SqliteRow, permissions: Vec<String>, scopes: Vec<RolePermissionScope>) -> RoleDetail {
    RoleDetail { id: row.get("id"), slug: row.get("slug"), name: row.get("name"), description: row.get("description"), system_managed: row.get::<i64, _>("system_managed") != 0, permissions, scopes }
}

async fn role_detail(pool: &SqlitePool, row: sqlx::sqlite::SqliteRow) -> Result<RoleDetail, sqlx::Error> {
    let permissions = role_permissions(pool, row.get("id")).await?;
    let scopes = role_permission_scopes(pool, row.get("id")).await?;
    Ok(role_detail_from_row(&row, permissions, scopes))
}

pub async fn role_permissions(pool: &SqlitePool, role_id: i64) -> Result<Vec<String>, sqlx::Error> {
    Ok(sqlx::query_scalar("SELECT p.key FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=? AND rp.scope_type='' AND rp.scope_id=0 ORDER BY p.key").bind(role_id).fetch_all(pool).await?)
}

pub async fn role_permission_scopes(pool: &SqlitePool, role_id: i64) -> Result<Vec<RolePermissionScope>, sqlx::Error> {
    let rows = sqlx::query("SELECT p.key AS permission, rp.scope_id FROM role_permissions rp JOIN permissions p ON p.id=rp.permission_id WHERE rp.role_id=? AND rp.scope_type='proxy_host' ORDER BY p.key,rp.scope_id")
        .bind(role_id).fetch_all(pool).await?;
    let mut scopes = Vec::new();
    for row in rows {
        let permission: String = row.get("permission");
        let host_id: i64 = row.get("scope_id");
        if let Some(index) = scopes.iter().position(|s| s.permission == permission) {
            scopes[index].proxy_host_ids.push(host_id);
        } else {
            scopes.push(RolePermissionScope { permission, proxy_host_ids: vec![host_id] });
        }
    }
    Ok(scopes)
}

fn normalize_scopes(scopes: &[RolePermissionScope]) -> Result<Vec<RolePermissionScope>, sqlx::Error> {
    let mut normalized = Vec::with_capacity(scopes.len());
    for scope in scopes {
        if !matches!(scope.permission.as_str(), "proxy_hosts.read" | "proxy_hosts.write") || scope.proxy_host_ids.is_empty() {
            return Err(sqlx::Error::Protocol("invalid role scope permission".into()));
        }
        let mut ids = scope.proxy_host_ids.clone();
        ids.sort_unstable();
        ids.dedup();
        if ids.iter().any(|id| *id <= 0) {
            return Err(sqlx::Error::Protocol("invalid role scope host id".into()));
        }
        normalized.push(RolePermissionScope { permission: scope.permission.clone(), proxy_host_ids: ids });
    }
    normalized.sort_by(|a, b| a.permission.cmp(&b.permission));
    if normalized.windows(2).any(|pair| pair[0].permission == pair[1].permission) {
        return Err(sqlx::Error::Protocol("duplicate role scope permission".into()));
    }
    Ok(normalized)
}

async fn replace_scopes_tx<'a>(tx: &mut sqlx::Transaction<'a, sqlx::Sqlite>, role_id: i64, scopes: &[RolePermissionScope]) -> Result<(), sqlx::Error> {
    let scopes = normalize_scopes(scopes)?;
    for scope in &scopes {
        let exists: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM proxy_hosts WHERE id IN (SELECT value FROM json_each(?))")
            .bind(serde_json::to_string(&scope.proxy_host_ids).unwrap()).fetch_one(&mut **tx).await?;
        if exists != scope.proxy_host_ids.len() as i64 { return Err(sqlx::Error::Protocol("unknown proxy host id".into())); }
        for host_id in &scope.proxy_host_ids {
            sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) SELECT ?,id,'proxy_host',? FROM permissions WHERE key=?")
                .bind(role_id).bind(host_id).bind(&scope.permission).execute(&mut **tx).await?;
        }
    }
    Ok(())
}

pub async fn replace_role_scopes(pool: &SqlitePool, role_id: i64, scopes: &[RolePermissionScope]) -> Result<RoleDetail, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let row = sqlx::query("SELECT system_managed FROM roles WHERE id=?").bind(role_id).fetch_optional(&mut *tx).await?.ok_or(sqlx::Error::RowNotFound)?;
    if row.get::<i64, _>("system_managed") != 0 { return Err(sqlx::Error::Protocol("system-managed role cannot be mutated".into())); }
    normalize_scopes(scopes)?;
    sqlx::query("DELETE FROM role_permissions WHERE role_id=? AND scope_type='proxy_host'").bind(role_id).execute(&mut *tx).await?;
    replace_scopes_tx(&mut tx, role_id, scopes).await?;
    tx.commit().await?;
    get_role(pool, role_id).await?.ok_or(sqlx::Error::RowNotFound)
}

pub async fn list_roles(pool: &SqlitePool) -> Result<Vec<RoleDetail>, sqlx::Error> {
    let rows = sqlx::query("SELECT id,slug,name,description,system_managed FROM roles ORDER BY id").fetch_all(pool).await?;
    let mut result = Vec::with_capacity(rows.len());
    for row in rows { result.push(role_detail(pool, row).await?); }
    Ok(result)
}

pub async fn role_by_slug(pool: &SqlitePool, slug: &str) -> Result<Option<RoleDetail>, sqlx::Error> {
    match sqlx::query("SELECT id,slug,name,description,system_managed FROM roles WHERE slug=?").bind(slug).fetch_optional(pool).await? { Some(row) => Ok(Some(role_detail(pool, row).await?)), None => Ok(None) }
}

pub async fn get_role(pool: &SqlitePool, id: i64) -> Result<Option<RoleDetail>, sqlx::Error> {
    match sqlx::query("SELECT id,slug,name,description,system_managed FROM roles WHERE id=?").bind(id).fetch_optional(pool).await? { Some(row) => Ok(Some(role_detail(pool, row).await?)), None => Ok(None) }
}

pub async fn insert_role(pool: &SqlitePool, slug: &str, name: &str, description: &str) -> Result<RoleDetail, sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let id = generated_id();
    sqlx::query("INSERT INTO roles(id,slug,name,description,created_at,updated_at) VALUES(?,?,?,?,?,?)").bind(id).bind(slug).bind(name).bind(description).bind(&now).bind(&now).execute(pool).await?;
    get_role(pool, id).await?.ok_or(sqlx::Error::RowNotFound)
}

/// Atomically creates a role and installs its global permissions.
pub async fn insert_role_with_permissions(pool: &SqlitePool, slug: &str, name: &str, description: &str, keys: &[&str]) -> Result<RoleDetail, sqlx::Error> {
    insert_role_with_permissions_and_scopes(pool, slug, name, description, keys, &[]).await
}

pub async fn insert_role_with_permissions_and_scopes(pool: &SqlitePool, slug: &str, name: &str, description: &str, keys: &[&str], scopes: &[RolePermissionScope]) -> Result<RoleDetail, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let now = chrono::Utc::now().to_rfc3339();
    let id = generated_id();
    sqlx::query("INSERT INTO roles(id,slug,name,description,created_at,updated_at) VALUES(?,?,?,?,?,?)")
        .bind(id).bind(slug).bind(name).bind(description).bind(&now).bind(&now).execute(&mut *tx).await?;
    for key in keys {
        if sqlx::query("SELECT 1 FROM permissions WHERE key=?").bind(key).fetch_optional(&mut *tx).await?.is_none() {
            return Err(sqlx::Error::Protocol("invalid permission".into()));
        }
        sqlx::query("INSERT INTO role_permissions(role_id,permission_id) SELECT ?,id FROM permissions WHERE key=?")
            .bind(id).bind(key).execute(&mut *tx).await?;
    }
    replace_scopes_tx(&mut tx, id, scopes).await?;
    tx.commit().await?;
    get_role(pool, id).await?.ok_or(sqlx::Error::RowNotFound)
}

/// Atomically updates role metadata and replaces its global permissions.
pub async fn update_role_with_permissions(pool: &SqlitePool, id: i64, name: Option<&str>, description: Option<&str>, keys: Option<&[&str]>) -> Result<Option<RoleDetail>, sqlx::Error> {
    update_role_with_permissions_and_scopes(pool, id, name, description, keys, None).await
}

pub async fn update_role_with_permissions_and_scopes(pool: &SqlitePool, id: i64, name: Option<&str>, description: Option<&str>, keys: Option<&[&str]>, scopes: Option<&[RolePermissionScope]>) -> Result<Option<RoleDetail>, sqlx::Error> {
    let mut tx = pool.begin().await?;
    let current = sqlx::query("SELECT system_managed FROM roles WHERE id=?").bind(id).fetch_optional(&mut *tx).await?;
    let Some(current) = current else { tx.rollback().await?; return Ok(None); };
    if current.get::<i64, _>("system_managed") != 0 { tx.rollback().await?; return Err(sqlx::Error::Protocol("system-managed role cannot be mutated".into())); }
    sqlx::query("UPDATE roles SET name=COALESCE(?,name),description=COALESCE(?,description),updated_at=? WHERE id=?")
        .bind(name).bind(description).bind(chrono::Utc::now().to_rfc3339()).bind(id).execute(&mut *tx).await?;
    if let Some(keys) = keys {
        for key in keys {
            if sqlx::query("SELECT 1 FROM permissions WHERE key=?").bind(key).fetch_optional(&mut *tx).await?.is_none() {
                return Err(sqlx::Error::Protocol("invalid permission".into()));
            }
        }
        sqlx::query("DELETE FROM role_permissions WHERE role_id=? AND scope_type='' AND scope_id=0").bind(id).execute(&mut *tx).await?;
        for key in keys {
            sqlx::query("INSERT INTO role_permissions(role_id,permission_id) SELECT ?,id FROM permissions WHERE key=?").bind(id).bind(key).execute(&mut *tx).await?;
        }
    }
    if let Some(scopes) = scopes {
        normalize_scopes(scopes)?;
        sqlx::query("DELETE FROM role_permissions WHERE role_id=? AND scope_type='proxy_host'").bind(id).execute(&mut *tx).await?;
        replace_scopes_tx(&mut tx, id, scopes).await?;
    }
    tx.commit().await?;
    get_role(pool, id).await
}

pub async fn update_role(pool: &SqlitePool, id: i64, name: Option<&str>, description: Option<&str>) -> Result<Option<RoleDetail>, sqlx::Error> {
    let current = sqlx::query("SELECT system_managed FROM roles WHERE id=?").bind(id).fetch_optional(pool).await?;
    let Some(current) = current else { return Ok(None); };
    if current.get::<i64, _>("system_managed") != 0 { return Err(sqlx::Error::Protocol("system-managed role cannot be mutated".into())); }
    sqlx::query("UPDATE roles SET name=COALESCE(?,name),description=COALESCE(?,description),updated_at=? WHERE id=?").bind(name).bind(description).bind(chrono::Utc::now().to_rfc3339()).bind(id).execute(pool).await?;
    get_role(pool, id).await
}

pub async fn set_role_permissions(pool: &SqlitePool, role_id: i64, keys: &[&str]) -> Result<RoleDetail, sqlx::Error> {
    let current = sqlx::query("SELECT system_managed FROM roles WHERE id=?").bind(role_id).fetch_optional(pool).await?.ok_or(sqlx::Error::RowNotFound)?;
    if current.get::<i64, _>("system_managed") != 0 { return Err(sqlx::Error::Protocol("system-managed role cannot be mutated".into())); }
    let mut tx = pool.begin().await?;
    for key in keys { if sqlx::query("SELECT 1 FROM permissions WHERE key=?").bind(key).fetch_optional(&mut *tx).await?.is_none() { return Err(sqlx::Error::Protocol(format!("invalid permission: {key}"))); } }
    sqlx::query("DELETE FROM role_permissions WHERE role_id=? AND scope_type='' AND scope_id=0").bind(role_id).execute(&mut *tx).await?;
    for key in keys { sqlx::query("INSERT INTO role_permissions(role_id,permission_id) SELECT ?,id FROM permissions WHERE key=?").bind(role_id).bind(key).execute(&mut *tx).await?; }
    tx.commit().await?;
    get_role(pool, role_id).await?.ok_or(sqlx::Error::RowNotFound)
}

pub async fn delete_role(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;

    let row = match sqlx::query("SELECT slug,system_managed FROM roles WHERE id=?")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
    {
        Ok(row) => row,
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(error);
        }
    };
    let Some(row) = row else {
        if let Err(error) = sqlx::query("COMMIT").execute(&mut *conn).await {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(error);
        }
        return Ok(0);
    };
    if row.get::<i64, _>("system_managed") != 0 {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return Err(sqlx::Error::Protocol("system-managed role cannot be deleted".into()));
    }
    let slug: String = row.get("slug");
    let assigned = match sqlx::query("SELECT 1 FROM users WHERE role=? LIMIT 1")
        .bind(&slug)
        .fetch_optional(&mut *conn)
        .await
    {
        Ok(row) => row.is_some(),
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(error);
        }
    };
    if assigned {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return Err(sqlx::Error::Protocol("role is assigned to users".into()));
    }
    let changed = match sqlx::query("DELETE FROM roles WHERE id=?")
        .bind(id)
        .execute(&mut *conn)
        .await
    {
        Ok(result) => result.rows_affected(),
        Err(error) => {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(error);
        }
    };
    if let Err(error) = sqlx::query("COMMIT").execute(&mut *conn).await {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return Err(error);
    }
    Ok(changed)
}

pub async fn user_has_permission(pool: &SqlitePool, user_id: i64, key: &str, scope: Option<(&str, i64)>) -> Result<bool, sqlx::Error> {
    let allowed = match scope {
        None => sqlx::query(
            "SELECT 1 FROM users u JOIN roles r ON r.slug=u.role JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id WHERE u.id=? AND u.disabled=0 AND p.key=? AND rp.scope_type='' AND rp.scope_id=0 LIMIT 1",
        )
        .bind(user_id)
        .bind(key)
        .fetch_optional(pool)
        .await?
        .is_some(),
        Some(("proxy_host", host_id)) => sqlx::query(
            "SELECT 1 FROM users u JOIN roles r ON r.slug=u.role JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id WHERE u.id=? AND u.disabled=0 AND p.key=? AND ((rp.scope_type='' AND rp.scope_id=0) OR (rp.scope_type=? AND rp.scope_id=?)) LIMIT 1",
        )
        .bind(user_id)
        .bind(key)
        .bind("proxy_host")
        .bind(host_id)
        .fetch_optional(pool)
        .await?
        .is_some(),
        // Scope types are an allow-list. Unknown values must never broaden access.
        Some(_) => false,
    };
    Ok(allowed)
}

pub async fn user_has_scoped_permission(pool: &SqlitePool, user_id: i64, key: &str) -> Result<bool, sqlx::Error> {
    Ok(sqlx::query("SELECT 1 FROM users u JOIN roles r ON r.slug=u.role JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id WHERE u.id=? AND u.disabled=0 AND p.key=? AND rp.scope_type='proxy_host' AND rp.scope_id IS NOT NULL LIMIT 1")
        .bind(user_id).bind(key).fetch_optional(pool).await?.is_some())
}

enum AuditFilter {
    Text(String),
    Actor(i64),
}

fn sensitive_audit_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase().replace(['-', ' '], "_");
    ["password", "token", "secret", "private_key", "privatekey", "credential", "request_body", "requestbody"]
        .iter()
        .any(|needle| key.contains(needle))
}

fn redact_json(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Object(object) => {
            for (key, value) in object.iter_mut() {
                if sensitive_audit_key(key) {
                    *value = serde_json::Value::String("[REDACTED]".into());
                } else {
                    redact_json(value);
                }
            }
        }
        serde_json::Value::Array(values) => values.iter_mut().for_each(redact_json),
        _ => {}
    }
}

/// Sanitize legacy/free-form audit details at the read boundary. Audit rows
/// may have been written by older callers, so API serialization must remain
/// safe even when storage contains credentials or request bodies.
pub fn sanitize_audit_details(details: &str) -> String {
    if let Ok(mut value) = serde_json::from_str::<serde_json::Value>(details) {
        redact_json(&mut value);
        return serde_json::to_string(&value).unwrap_or_else(|_| "[REDACTED]".into());
    }
    let mut output = details.to_owned();
    let lower = output.to_ascii_lowercase();
    let mut replacements = Vec::new();
    for key in ["password", "token", "secret", "private_key", "private-key", "credential", "request_body", "request-body"] {
        let mut start = 0;
        while let Some(relative) = lower[start..].find(key) {
            let key_start = start + relative;
            let after_key = key_start + key.len();
            let bytes = lower.as_bytes();
            if after_key < bytes.len() && (bytes[after_key] == b'=' || bytes[after_key] == b':') {
                let value_start = after_key + 1;
                let value_end = output[value_start..]
                    .find([';', '&', '\n', ',', '}'])
                    .map(|offset| value_start + offset)
                    .unwrap_or(output.len());
                replacements.push((value_start, value_end));
            }
            start = after_key;
            if start >= lower.len() { break; }
        }
    }
    // A value may itself contain another sensitive key (for example
    // `password=password=...`). Coalesce ranges first so reverse replacement
    // never attempts to edit an already-replaced/overlapping span.
    replacements.sort_unstable_by_key(|(start, _)| *start);
    let mut merged = Vec::with_capacity(replacements.len());
    for (start, end) in replacements {
        if let Some((_, previous_end)) = merged.last_mut() {
            if start <= *previous_end {
                *previous_end = (*previous_end).max(end);
                continue;
            }
        }
        merged.push((start, end));
    }
    for (start, end) in merged.into_iter().rev() {
        output.replace_range(start..end, "[REDACTED]");
    }
    output
}

fn audit_where(query: &AuditLogQuery) -> (String, Vec<AuditFilter>) {
    let mut predicates = Vec::new();
    let mut filters = Vec::new();
    if let Some(event) = query.event.as_deref() {
        predicates.push("a.event = ?");
        filters.push(AuditFilter::Text(event.to_owned()));
    }
    if let Some(actor_id) = query.actor_id {
        predicates.push("a.user_id = ?");
        filters.push(AuditFilter::Actor(actor_id));
    }
    if let Some(from) = query.from.as_deref() {
        predicates.push("a.created_at >= ?");
        filters.push(AuditFilter::Text(from.to_owned()));
    }
    if let Some(to) = query.to.as_deref() {
        predicates.push("a.created_at <= ?");
        filters.push(AuditFilter::Text(to.to_owned()));
    }
    if let Some(q) = query.q.as_deref() {
        predicates.push("(a.event LIKE ? OR a.details LIKE ?)");
        let pattern = format!("%{q}%");
        filters.push(AuditFilter::Text(pattern.clone()));
        filters.push(AuditFilter::Text(pattern));
    }
    let where_clause = if predicates.is_empty() {
        String::new()
    } else {
        format!(" WHERE {}", predicates.join(" AND "))
    };
    (where_clause, filters)
}

pub async fn list_audit_logs(
    pool: &SqlitePool,
    query: &AuditLogQuery,
) -> Result<AuditLogPage, sqlx::Error> {
    let (where_clause, filters) = audit_where(query);
    let count_sql = format!("SELECT COUNT(*) AS c FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id{where_clause}");
    let mut count = sqlx::query(&count_sql);
    for filter in &filters {
        count = match filter {
            AuditFilter::Text(value) => count.bind(value),
            AuditFilter::Actor(value) => count.bind(*value),
        };
    }
    let total = count.fetch_one(pool).await?.get::<i64, _>("c");

    let page = query.page.max(1);
    let page_size = query.page_size;
    let offset = (page as i64 - 1).saturating_mul(page_size as i64);
    let select_sql = format!(
        "SELECT a.id, COALESCE(u.email, CASE WHEN a.user_id IS NULL THEN 'system' ELSE 'deleted-user' END) AS actor, a.event, a.details, a.created_at FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id{where_clause} ORDER BY a.created_at DESC, a.id DESC LIMIT ? OFFSET ?"
    );
    let mut select = sqlx::query(&select_sql);
    for filter in &filters {
        select = match filter {
            AuditFilter::Text(value) => select.bind(value),
            AuditFilter::Actor(value) => select.bind(*value),
        };
    }
    let rows = select
        .bind(page_size as i64)
        .bind(offset)
        .fetch_all(pool)
        .await?;
    let items = rows
        .into_iter()
        .map(|row| AuditLogItem {
            id: row.get("id"),
            actor: row.get("actor"),
            event: row.get("event"),
            details: sanitize_audit_details(&row.get::<String, _>("details")),
            created_at: row.get("created_at"),
        })
        .collect();
    Ok(AuditLogPage { items, page, page_size, total })
}

pub async fn count_active_admins(pool: &SqlitePool) -> Result<i64, sqlx::Error> {
    Ok(sqlx::query("SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0")
        .fetch_one(pool).await?.get("c"))
}

/// Atomically apply a user's role and disabled state.  The last-active-admin
/// invariant is checked while holding SQLite's write lock so a combined PATCH
/// can never leave a partially updated account behind.
pub async fn update_user(
    pool: &SqlitePool,
    id: i64,
    role: Option<&str>,
    disabled: Option<bool>,
) -> Result<Option<User>, sqlx::Error> {
    if let Some(value) = role {
        if Role::parse(value).is_none()
            && sqlx::query("SELECT 1 FROM roles WHERE slug=?")
                .bind(value)
                .fetch_optional(pool)
                .await?
                .is_none()
        {
            return Err(sqlx::Error::Protocol("invalid role".into()));
        }
    }
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let current = sqlx::query("SELECT id,email,role,created_at,disabled FROM users WHERE id=?")
        .bind(id).fetch_optional(&mut *conn).await?;
    let Some(current) = current else {
        let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
        return Ok(None);
    };
    let current_role: String = current.get("role");
    let current_disabled: bool = current.get::<i64, _>("disabled") != 0;
    let next_role = role.unwrap_or(current_role.as_str());
    let next_disabled = disabled.unwrap_or(current_disabled);
    if current_role == "admin" && !current_disabled
        && (next_role != "admin" || next_disabled)
    {
        let admins: i64 = sqlx::query("SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0")
            .fetch_one(&mut *conn).await?.get("c");
        if admins <= 1 {
            let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
            return Err(last_admin_error());
        }
    }
    sqlx::query("UPDATE users SET role=?,disabled=? WHERE id=?")
        .bind(next_role).bind(next_disabled as i64).bind(id)
        .execute(&mut *conn).await?;
    if next_disabled && !current_disabled {
        sqlx::query("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL")
            .bind(chrono::Utc::now().to_rfc3339()).bind(id).execute(&mut *conn).await?;
    }
    let updated = sqlx::query("SELECT id,email,role,created_at,disabled FROM users WHERE id=?")
        .bind(id).fetch_one(&mut *conn).await?;
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(Some(User {
        id: updated.get("id"), email: updated.get("email"), role: updated.get("role"),
        created_at: updated.get("created_at"), disabled: updated.get::<i64, _>("disabled") != 0,
    }))
}

fn last_admin_error() -> sqlx::Error {
    sqlx::Error::Protocol("cannot remove the last active administrator".into())
}

pub async fn update_user_role(pool: &SqlitePool, id: i64, role: &str) -> Result<u64, sqlx::Error> {
    if Role::parse(role).is_none()
        && sqlx::query("SELECT 1 FROM roles WHERE slug=?")
            .bind(role)
            .fetch_optional(pool)
            .await?
            .is_none()
    {
        return Err(sqlx::Error::Protocol("invalid role".into()));
    }
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let current = sqlx::query("SELECT role,disabled FROM users WHERE id=?").bind(id).fetch_optional(&mut *conn).await?;
    if let Some(row) = current {
        let was_admin = row.get::<String, _>("role") == "admin" && row.get::<i64, _>("disabled") == 0;
        if was_admin && role != "admin" {
            let admins: i64 = sqlx::query("SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0").fetch_one(&mut *conn).await?.get("c");
            if admins <= 1 {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(last_admin_error());
            }
        }
    }
    let changed = sqlx::query("UPDATE users SET role=? WHERE id=?").bind(role).bind(id).execute(&mut *conn).await?.rows_affected();
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(changed)
}

pub async fn revoke_user_sessions(pool: &SqlitePool, user_id: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL")
        .bind(chrono::Utc::now().to_rfc3339()).bind(user_id).execute(pool).await?.rows_affected())
}

pub async fn set_user_disabled(pool: &SqlitePool, id: i64, disabled: bool) -> Result<u64, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let current = sqlx::query("SELECT role,disabled FROM users WHERE id=?").bind(id).fetch_optional(&mut *conn).await?;
    if let Some(row) = current {
        let was_active_admin = row.get::<String, _>("role") == "admin" && row.get::<i64, _>("disabled") == 0;
        if disabled && was_active_admin {
            let admins: i64 = sqlx::query("SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0").fetch_one(&mut *conn).await?.get("c");
            if admins <= 1 {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(last_admin_error());
            }
        }
    }
    let changed = sqlx::query("UPDATE users SET disabled=? WHERE id=?").bind(disabled as i64).bind(id).execute(&mut *conn).await?.rows_affected();
    if disabled && changed > 0 {
        sqlx::query("UPDATE sessions SET revoked_at=? WHERE user_id=? AND revoked_at IS NULL").bind(chrono::Utc::now().to_rfc3339()).bind(id).execute(&mut *conn).await?;
    }
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(changed)
}

pub async fn delete_user(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let current = sqlx::query("SELECT role,disabled FROM users WHERE id=?").bind(id).fetch_optional(&mut *conn).await?;
    if let Some(row) = current {
        if row.get::<String, _>("role") == "admin" && row.get::<i64, _>("disabled") == 0 {
            let admins: i64 = sqlx::query("SELECT COUNT(*) c FROM users WHERE role='admin' AND disabled=0").fetch_one(&mut *conn).await?.get("c");
            if admins <= 1 {
                let _ = sqlx::query("ROLLBACK").execute(&mut *conn).await;
                return Err(last_admin_error());
            }
        }
    }
    sqlx::query("DELETE FROM sessions WHERE user_id=?").bind(id).execute(&mut *conn).await?;
    let changed = sqlx::query("DELETE FROM users WHERE id=?").bind(id).execute(&mut *conn).await?.rows_affected();
    sqlx::query("COMMIT").execute(&mut *conn).await?;
    Ok(changed)
}
pub async fn create_session(
    pool: &SqlitePool,
    user_id: i64,
    hash: &str,
    expires: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)")
        .bind(generated_id())
        .bind(user_id)
        .bind(hash)
        .bind(expires)
        .execute(pool)
        .await?;
    Ok(())
}
pub async fn revoke_session(pool: &SqlitePool, hash: &str) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE sessions SET revoked_at=? WHERE token_hash=?")
        .bind(chrono::Utc::now().to_rfc3339())
        .bind(hash)
        .execute(pool)
        .await?;
    Ok(())
}
pub async fn list_hosts(pool: &SqlitePool) -> Result<Vec<ProxyHost>, sqlx::Error> {
    let rows=sqlx::query("SELECT id,name,domain,upstream_host,upstream_port,tls_mode,certificate_id,enabled FROM proxy_hosts ORDER BY id").fetch_all(pool).await?;
    Ok(rows.into_iter().map(proxy_host_from_row).collect())
}

fn proxy_host_from_row(x: sqlx::sqlite::SqliteRow) -> ProxyHost {
    ProxyHost {
            id: x.get("id"),
            name: x.get("name"),
            domain: x.get("domain"),
            upstream_host: x.get("upstream_host"),
            upstream_port: x.get::<i64, _>("upstream_port") as u16,
            tls_mode: x.get("tls_mode"),
            certificate_id: x.get("certificate_id"),
            enabled: x.get::<i64, _>("enabled") != 0,
    }
}

/// Lists only hosts visible through a user's global or per-host read grants.
pub async fn list_hosts_for_user(pool: &SqlitePool, user_id: i64) -> Result<Vec<ProxyHost>, sqlx::Error> {
    let rows = sqlx::query("SELECT DISTINCT h.id,h.name,h.domain,h.upstream_host,h.upstream_port,h.tls_mode,h.certificate_id,h.enabled FROM proxy_hosts h JOIN users u ON u.id=? JOIN roles r ON r.slug=u.role JOIN role_permissions rp ON rp.role_id=r.id JOIN permissions p ON p.id=rp.permission_id WHERE u.disabled=0 AND p.key='proxy_hosts.read' AND ((rp.scope_type='' AND rp.scope_id=0) OR (rp.scope_type='proxy_host' AND rp.scope_id=h.id)) ORDER BY h.id")
        .bind(user_id).fetch_all(pool).await?;
    Ok(rows.into_iter().map(proxy_host_from_row).collect())
}
pub async fn insert_host(pool: &SqlitePool, h: &ProxyHost) -> Result<ProxyHost, sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let id = if h.id > 0 { h.id } else { generated_id() };
    sqlx::query("INSERT INTO proxy_hosts(id,name,domain,upstream_host,upstream_port,tls_mode,certificate_id,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)").bind(id).bind(&h.name).bind(&h.domain).bind(&h.upstream_host).bind(h.upstream_port as i64).bind(&h.tls_mode).bind(h.certificate_id).bind(h.enabled as i64).bind(&now).bind(&now).execute(pool).await?;
    let mut x = h.clone();
    x.id = id;
    Ok(x)
}
pub async fn delete_host(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM proxy_hosts WHERE id=?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected())
}

/// Removes a proxy host and every per-host role assignment in one transaction.
/// Callers can safely restore the host if the transaction fails; no partial
/// cleanup is committed.
pub async fn delete_host_and_scopes(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
    let mut conn = pool.acquire().await?;
    sqlx::query("BEGIN IMMEDIATE").execute(&mut *conn).await?;
    let result = async {
        let changed = sqlx::query("DELETE FROM proxy_hosts WHERE id=?")
            .bind(id).execute(&mut *conn).await?.rows_affected();
        sqlx::query("DELETE FROM role_permissions WHERE scope_type='proxy_host' AND scope_id=?")
            .bind(id).execute(&mut *conn).await?;
        Ok::<u64, sqlx::Error>(changed)
    }.await;
    match result {
        Ok(changed) => { sqlx::query("COMMIT").execute(&mut *conn).await?; Ok(changed) }
        Err(error) => {
            if let Err(rollback_error) = sqlx::query("ROLLBACK").execute(&mut *conn).await {
                eprintln!("proxy host deletion rollback failed: {rollback_error}");
            }
            Err(error)
        }
    }
}

pub async fn host_scope_rows(pool: &SqlitePool, id: i64) -> Result<Vec<(i64, i64, String)>, sqlx::Error> {
    let rows = sqlx::query("SELECT role_id,permission_id,scope_type FROM role_permissions WHERE scope_type='proxy_host' AND scope_id=?")
        .bind(id).fetch_all(pool).await?;
    Ok(rows.into_iter().map(|row| (row.get("role_id"), row.get("permission_id"), row.get("scope_type"))).collect())
}

pub async fn restore_host_scopes(pool: &SqlitePool, id: i64, rows: &[(i64, i64, String)]) -> Result<(), sqlx::Error> {
    for (role_id, permission_id, scope_type) in rows {
        sqlx::query("INSERT OR IGNORE INTO role_permissions(role_id,permission_id,scope_type,scope_id) VALUES(?,?,?,?)")
            .bind(role_id).bind(permission_id).bind(scope_type).bind(id).execute(pool).await?;
    }
    Ok(())
}

pub async fn get_host(pool: &SqlitePool, id: i64) -> Result<Option<ProxyHost>, sqlx::Error> {
    let row = sqlx::query("SELECT id,name,domain,upstream_host,upstream_port,tls_mode,certificate_id,enabled FROM proxy_hosts WHERE id=?")
        .bind(id).fetch_optional(pool).await?;
    Ok(row.map(|x| ProxyHost {
        id: x.get("id"),
        name: x.get("name"),
        domain: x.get("domain"),
        upstream_host: x.get("upstream_host"),
        upstream_port: x.get::<i64, _>("upstream_port") as u16,
        tls_mode: x.get("tls_mode"),
        certificate_id: x.get("certificate_id"),
        enabled: x.get::<i64, _>("enabled") != 0,
    }))
}

pub async fn update_host(pool: &SqlitePool, id: i64, h: &ProxyHost) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("UPDATE proxy_hosts SET name=?,domain=?,upstream_host=?,upstream_port=?,tls_mode=?,certificate_id=?,enabled=?,updated_at=? WHERE id=?")
        .bind(&h.name).bind(&h.domain).bind(&h.upstream_host).bind(h.upstream_port as i64)
        .bind(&h.tls_mode).bind(h.certificate_id).bind(h.enabled as i64)
        .bind(chrono::Utc::now().to_rfc3339()).bind(id).execute(pool).await?.rows_affected())
}
pub async fn insert_certificate(
    pool: &SqlitePool,
    name: &str,
    source: &str,
    hosts: &str,
    expiry: &str,
    cert_path: &str,
    key_path: &str,
) -> Result<i64, sqlx::Error> {
    let id = generated_id();
    sqlx::query("INSERT INTO certificates(id,name,source,covered_hostnames,expiry,certificate_path,key_path,created_at) VALUES(?,?,?,?,?,?,?,?)").bind(id).bind(name).bind(source).bind(hosts).bind(expiry).bind(cert_path).bind(key_path).bind(chrono::Utc::now().to_rfc3339()).execute(pool).await?;
    Ok(id)
}

pub async fn list_certificates(pool: &SqlitePool) -> Result<Vec<CertificateMetadata>, sqlx::Error> {
    let rows = sqlx::query(
        "SELECT id,name,source,covered_hostnames,expiry,active FROM certificates ORDER BY id",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows
        .into_iter()
        .map(|r| CertificateMetadata {
            id: r.get("id"),
            name: r.get("name"),
            source: r.get("source"),
            covered_hostnames: serde_json::from_str(&r.get::<String, _>("covered_hostnames"))
                .unwrap_or_default(),
            expiry: r.get("expiry"),
            active: r.get::<i64, _>("active") != 0,
        })
        .collect())
}

pub async fn certificate_name(pool: &SqlitePool, id: i64) -> Result<Option<String>, sqlx::Error> {
    Ok(sqlx::query("SELECT name FROM certificates WHERE id=?")
        .bind(id)
        .fetch_optional(pool)
        .await?
        .map(|r| r.get("name")))
}

/// Return the certificate storage paths for activation validation.
pub async fn certificate_paths(
    pool: &SqlitePool,
    id: i64,
) -> Result<Option<(String, String, String)>, sqlx::Error> {
    Ok(
        sqlx::query("SELECT name,certificate_path,key_path FROM certificates WHERE id=?")
            .bind(id)
            .fetch_optional(pool)
            .await?
            .map(|r| (r.get("name"), r.get("certificate_path"), r.get("key_path"))),
    )
}

pub async fn active_certificate_id(pool: &SqlitePool) -> Result<Option<i64>, sqlx::Error> {
    Ok(
        sqlx::query("SELECT id FROM certificates WHERE active=1 ORDER BY id LIMIT 1")
            .fetch_optional(pool)
            .await?
            .map(|r| r.get("id")),
    )
}

/// Set exactly one active certificate (or none), in one transaction.
pub async fn set_active_certificate(
    pool: &SqlitePool,
    id: Option<i64>,
) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE certificates SET active=0")
        .execute(&mut *tx)
        .await?;
    let changed = if let Some(id) = id {
        sqlx::query("UPDATE certificates SET active=1 WHERE id=?")
            .bind(id)
            .execute(&mut *tx)
            .await?
            .rows_affected()
    } else {
        0
    };
    tx.commit().await?;
    Ok(changed)
}

pub async fn activate_certificate(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
    set_active_certificate(pool, Some(id)).await
}
