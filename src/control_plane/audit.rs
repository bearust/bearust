use super::AppState;
use crate::control_plane::repository::DbPool;
use crate::plugin_runtime::{PluginAuditEvent, PluginAuditSink};
use std::sync::Arc;
use uuid::Uuid;

/// Writes a deliberately small, redacted audit record. Callers must pass only
/// identifiers and safe metadata; secrets and request bodies are never stored.
pub async fn record(pool: &DbPool, user_id: Option<i64>, event: &str, details: &str) {
    let id = ((Uuid::new_v4().as_u128() as i64) & i64::MAX).max(1);
    let _ = sqlx::query(
        "INSERT INTO audit_logs(id,user_id,event,details,created_at) VALUES(?,?,?,?,?)",
    )
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

fn plugin_details(event: &PluginAuditEvent) -> String {
    serde_json::json!({
        "plugin_id": event.plugin_id(),
        "operation": event.operation(),
        "outcome": event.outcome(),
        "error_code": event.error_code(),
    })
    .to_string()
}

/// Audit sink used by direct and startup plugin-manager calls. Manager hooks
/// are synchronous, so persistence is dispatched onto the active Tokio
/// runtime; the mutation result never depends on audit availability.
pub struct PluginAuditDbSink {
    pool: DbPool,
    realtime: Arc<crate::control_plane::realtime::RealtimeHub>,
}

impl PluginAuditDbSink {
    pub fn new(pool: DbPool, realtime: Arc<crate::control_plane::realtime::RealtimeHub>) -> Self {
        Self { pool, realtime }
    }
}

impl PluginAuditSink for PluginAuditDbSink {
    fn record(&self, event: &PluginAuditEvent) {
        let pool = self.pool.clone();
        let realtime = Arc::clone(&self.realtime);
        let details = plugin_details(event);
        let task = async move {
            record(&pool, None, "plugin_lifecycle", &details).await;
            realtime.publish("audit");
        };
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            handle.spawn(task);
        }
    }
}

/// Records a plugin lifecycle operation using only bounded identifiers and
/// stable error codes. Paths, digests, manifests, and module contents never
/// enter audit details.
pub async fn record_plugin_state(
    state: &AppState,
    user_id: Option<i64>,
    plugin_id: &str,
    operation: &str,
    outcome: &str,
    error_code: Option<&str>,
) {
    let event =
        crate::plugin_runtime::PluginAuditEvent::new(plugin_id, operation, outcome, error_code);
    let details = plugin_details(&event);
    record_state(state, user_id, "plugin_lifecycle", &details).await;
}
