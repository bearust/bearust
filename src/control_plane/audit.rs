use sqlx::SqlitePool;

/// Writes a deliberately small, redacted audit record. Callers must pass only
/// identifiers and safe metadata; secrets and request bodies are never stored.
pub async fn record(pool: &SqlitePool, user_id: Option<i64>, event: &str, details: &str) {
    let _ = sqlx::query("INSERT INTO audit_logs(user_id,event,details,created_at) VALUES(?,?,?,?)")
        .bind(user_id)
        .bind(event)
        .bind(details)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(pool)
        .await;
}
