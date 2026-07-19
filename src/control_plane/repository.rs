use crate::control_plane::models::{
    AcmeChallenge, AcmeEnvironment, AcmeRequest, AcmeStatus, CertificateMetadata, ProxyHost, User,
};
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
    sqlx::query("CREATE TABLE IF NOT EXISTS acme_certificates (certificate_id INTEGER PRIMARY KEY,environment TEXT NOT NULL CHECK(environment IN ('staging','production')),challenge TEXT NOT NULL CHECK(challenge IN ('http01','cloudflare_dns01')),renewal_state TEXT NOT NULL,next_renewal_at TEXT,last_attempt_at TEXT,last_error_code TEXT,FOREIGN KEY(certificate_id) REFERENCES certificates(id) ON DELETE CASCADE)").execute(pool).await?;
    let _ = sqlx::query("ALTER TABLE acme_certificates ADD COLUMN secret_ref TEXT").execute(pool).await;
    sqlx::query("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY AUTOINCREMENT,user_id INTEGER,event TEXT NOT NULL,details TEXT NOT NULL,created_at TEXT NOT NULL)").execute(pool).await?;
    Ok(())
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
    let r=sqlx::query("INSERT INTO certificates(name,source,covered_hostnames,expiry,certificate_path,key_path,created_at) VALUES(?,?,?,?,?,?,?) RETURNING id").bind(name).bind(source).bind(hosts).bind(expiry).bind(cert_path).bind(key_path).bind(chrono::Utc::now().to_rfc3339()).fetch_one(pool).await?;
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
