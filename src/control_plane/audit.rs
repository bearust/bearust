use sqlx::SqlitePool;
use uuid::Uuid;
use super::AppState;

/// Writes a deliberately small, redacted audit record. Callers must pass only
/// identifiers and safe metadata; secrets and request bodies are never stored.
pub async fn record(pool: &SqlitePool, user_id: Option<i64>, event: &str, details: &str) {
    let id = (Uuid::new_v4().as_u128() as i64).abs().max(1);
    let _ = sqlx::query("INSERT INTO audit_logs(id,user_id,event,details,created_at) VALUES(?,?,?,?,?)")
        .bind(id)
        .bind(user_id)
        .bind(event)
        .bind(details)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(pool)
        .await;
}

/// Records an audit row and emits a redacted audit invalidation event.
/// Publication is best-effort and never changes the mutation result.
pub async fn record_state(state: &AppState, user_id: Option<i64>, event: &str, details: &str) {
    record(&state.db, user_id, event, details).await;
    state.realtime.publish("audit");
}
