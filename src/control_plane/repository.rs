use crate::control_plane::models::{CertificateMetadata, ProxyHost, User};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row, SqlitePool,
};
use std::str::FromStr;

pub async fn connect(url: &str) -> Result<SqlitePool, sqlx::Error> {
    let opts = SqliteConnectOptions::from_str(url)?
        .create_if_missing(true)
        .foreign_keys(true);
    SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(opts)
        .await
}
pub async fn migrate(pool: &SqlitePool) -> Result<(), sqlx::Error> {
    sqlx::query("PRAGMA foreign_keys=ON").execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT,email TEXT NOT NULL UNIQUE,password_hash TEXT NOT NULL,role TEXT NOT NULL,created_at TEXT NOT NULL)").execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS sessions (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER NOT NULL,token_hash TEXT NOT NULL UNIQUE,expires_at TEXT NOT NULL,revoked_at TEXT,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE)").execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS proxy_hosts (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL,domain TEXT NOT NULL UNIQUE,upstream_host TEXT NOT NULL,upstream_port INTEGER NOT NULL,tls_mode TEXT NOT NULL,certificate_id INTEGER,enabled INTEGER NOT NULL DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL)").execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS certificates (id INTEGER PRIMARY KEY AUTOINCREMENT,name TEXT NOT NULL UNIQUE,source TEXT NOT NULL,covered_hostnames TEXT NOT NULL,expiry TEXT NOT NULL,certificate_path TEXT NOT NULL,key_path TEXT NOT NULL,active INTEGER NOT NULL DEFAULT 0,created_at TEXT NOT NULL)").execute(pool).await?;
    sqlx::query("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,event TEXT NOT NULL,details TEXT NOT NULL,created_at TEXT NOT NULL)").execute(pool).await?;
    Ok(())
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
    let now = chrono::Utc::now().to_rfc3339();
    let r = sqlx::query(
        "INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?) RETURNING id",
    )
    .bind(email)
    .bind(hash)
    .bind(role)
    .bind(&now)
    .fetch_one(pool)
    .await?;
    Ok(User {
        id: r.get("id"),
        email: email.into(),
        role: role.into(),
        created_at: now,
    })
}
pub async fn find_user(
    pool: &SqlitePool,
    email: &str,
) -> Result<Option<(User, String)>, sqlx::Error> {
    let r = sqlx::query("SELECT id,email,password_hash,role,created_at FROM users WHERE email=?")
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
            },
            x.get("password_hash"),
        )
    }))
}
pub async fn find_user_by_session(
    pool: &SqlitePool,
    hash: &str,
) -> Result<Option<User>, sqlx::Error> {
    let r=sqlx::query("SELECT u.id,u.email,u.role,u.created_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>?").bind(hash).bind(chrono::Utc::now().to_rfc3339()).fetch_optional(pool).await?;
    Ok(r.map(|x| User {
        id: x.get("id"),
        email: x.get("email"),
        role: x.get("role"),
        created_at: x.get("created_at"),
    }))
}
pub async fn create_session(
    pool: &SqlitePool,
    user_id: i64,
    hash: &str,
    expires: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO sessions(user_id,token_hash,expires_at) VALUES(?,?,?)")
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
    Ok(rows
        .into_iter()
        .map(|x| ProxyHost {
            id: x.get("id"),
            name: x.get("name"),
            domain: x.get("domain"),
            upstream_host: x.get("upstream_host"),
            upstream_port: x.get::<i64, _>("upstream_port") as u16,
            tls_mode: x.get("tls_mode"),
            certificate_id: x.get("certificate_id"),
            enabled: x.get::<i64, _>("enabled") != 0,
        })
        .collect())
}
pub async fn insert_host(pool: &SqlitePool, h: &ProxyHost) -> Result<ProxyHost, sqlx::Error> {
    let now = chrono::Utc::now().to_rfc3339();
    let r=sqlx::query("INSERT INTO proxy_hosts(name,domain,upstream_host,upstream_port,tls_mode,certificate_id,enabled,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?) RETURNING id").bind(&h.name).bind(&h.domain).bind(&h.upstream_host).bind(h.upstream_port as i64).bind(&h.tls_mode).bind(h.certificate_id).bind(h.enabled as i64).bind(&now).bind(&now).fetch_one(pool).await?;
    let mut x = h.clone();
    x.id = r.get("id");
    Ok(x)
}
pub async fn delete_host(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
    Ok(sqlx::query("DELETE FROM proxy_hosts WHERE id=?")
        .bind(id)
        .execute(pool)
        .await?
        .rows_affected())
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
    let r=sqlx::query("INSERT INTO certificates(name,source,covered_hostnames,expiry,certificate_path,key_path) VALUES(?,?,?,?,?,?) RETURNING id").bind(name).bind(source).bind(hosts).bind(expiry).bind(cert_path).bind(key_path).fetch_one(pool).await?;
    Ok(r.get("id"))
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

pub async fn activate_certificate(pool: &SqlitePool, id: i64) -> Result<u64, sqlx::Error> {
    let mut tx = pool.begin().await?;
    sqlx::query("UPDATE certificates SET active=0")
        .execute(&mut *tx)
        .await?;
    let changed = sqlx::query("UPDATE certificates SET active=1 WHERE id=?")
        .bind(id)
        .execute(&mut *tx)
        .await?
        .rows_affected();
    tx.commit().await?;
    Ok(changed)
}
