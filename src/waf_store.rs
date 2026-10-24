use crate::{
    control_plane::{
        audit,
        realtime::RealtimeHub,
        repository::{self, DbPool},
    },
    waf::{compile_snapshot, redacted_telemetry, Evaluation, SecLangRuntime, WafSnapshot},
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

/// Compile SecLang rules unless the settings are unchanged from `previous`,
/// in which case it is reused: compiling the CRS takes a noticeable moment
/// and ordinary WAF rule edits must not pay for it. A compile failure keeps
/// the previous runtime (settings are validated before they are stored).
fn seclang_runtime(
    config: Option<crate::control_plane::models::SecLangConfig>,
    previous: Option<Arc<SecLangRuntime>>,
) -> Option<Arc<SecLangRuntime>> {
    let config = config?;
    let same = |runtime: &SecLangRuntime| {
        let mut a = runtime.config.clone();
        let mut b = config.clone();
        a.updated_at.clear();
        b.updated_at.clear();
        a == b
    };
    if let Some(previous) = previous.as_ref().filter(|runtime| same(runtime)) {
        return Some(previous.clone());
    }
    match SecLangRuntime::compile(&config) {
        Ok(runtime) => runtime.map(Arc::new),
        Err(error) => {
            tracing::error!(event = "waf_seclang_compile_failed", error = %error);
            previous
        }
    }
}

impl WafStore {
    pub async fn load(db: &DbPool) -> Result<Self, String> {
        let config = repository::get_waf_config(db)
            .await
            .map_err(|_| "unable to load waf configuration")?;
        let rules = repository::list_waf_rules(db)
            .await
            .map_err(|_| "unable to load waf rules")?;
        let mut snapshot =
            compile_snapshot(config, rules).map_err(|_| "invalid waf configuration")?;
        snapshot.seclang = seclang_runtime(repository::get_seclang_config(db).await.ok(), None);
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
        let mut snapshot =
            compile_snapshot(config, rules).map_err(|_| "invalid waf configuration")?;
        snapshot.seclang = seclang_runtime(
            repository::get_seclang_config(db).await.ok(),
            self.current.load().seclang.clone(),
        );
        self.current.store(Arc::new(snapshot));
        Ok(())
    }
}
