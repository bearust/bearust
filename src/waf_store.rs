use crate::{
    control_plane::{
        audit,
        realtime::RealtimeHub,
        repository::{self, DbPool},
    },
    waf::{compile_snapshot, redacted_telemetry, Evaluation, WafSnapshot},
};
use arc_swap::ArcSwap;
use std::sync::{Arc, RwLock};

#[derive(Clone)]
struct WafAuditSink {
    db: DbPool,
    realtime: Arc<RealtimeHub>,
}

pub struct WafStore {
    current: ArcSwap<WafSnapshot>,
    audit: RwLock<Option<WafAuditSink>>,
}

impl WafStore {
    pub async fn load(db: &DbPool) -> Result<Self, String> {
        let config = repository::get_waf_config(db)
            .await
            .map_err(|_| "unable to load waf configuration")?;
        let rules = repository::list_waf_rules(db)
            .await
            .map_err(|_| "unable to load waf rules")?;
        let snapshot = compile_snapshot(config, rules).map_err(|_| "invalid waf configuration")?;
        Ok(Self {
            current: ArcSwap::from_pointee(snapshot),
            audit: RwLock::new(None),
        })
    }

    pub fn snapshot(&self) -> Arc<WafSnapshot> {
        self.current.load_full()
    }

    pub fn configure_audit_sink(&self, db: DbPool, realtime: Arc<RealtimeHub>) {
        if let Ok(mut sink) = self.audit.write() {
            *sink = Some(WafAuditSink { db, realtime });
        }
    }

    /// Persist only the bounded WAF metadata and publish the existing redacted
    /// audit invalidation event. Failures never affect proxy decisions.
    pub fn record_detection(&self, evaluation: &Evaluation) {
        let Ok(sink) = self.audit.read() else { return };
        let Some(sink) = sink.clone() else { return };
        let details = redacted_telemetry(evaluation);
        let details = format!(
            "category={};score={};severity={};reason_ids={}",
            details.category, details.score, details.severity, details.reason_ids
        );
        tokio::spawn(async move {
            audit::record(&sink.db, None, "waf_detection", &details).await;
            sink.realtime.publish("audit");
        });
    }

    pub async fn reload(&self, db: &DbPool) -> Result<(), String> {
        let config = repository::get_waf_config(db)
            .await
            .map_err(|_| "unable to load waf configuration")?;
        let rules = repository::list_waf_rules(db)
            .await
            .map_err(|_| "unable to load waf rules")?;
        let snapshot = compile_snapshot(config, rules).map_err(|_| "invalid waf configuration")?;
        self.current.store(Arc::new(snapshot));
        Ok(())
    }
}
