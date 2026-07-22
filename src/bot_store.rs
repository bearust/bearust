use crate::{
    bot_protection::{compile_snapshot, BotEvaluation, BotSnapshot},
    control_plane::{
        audit,
        realtime::RealtimeHub,
        repository::{self, DbPool},
    },
};
use arc_swap::ArcSwap;
use std::sync::{Arc, RwLock};
use tokio::sync::Semaphore;

pub const MAX_IN_FLIGHT_DETECTIONS: usize = 64;

#[derive(Clone)]
struct Sink {
    db: DbPool,
    realtime: Arc<RealtimeHub>,
}
pub struct BotStore {
    current: ArcSwap<BotSnapshot>,
    audit: RwLock<Option<Sink>>,
    telemetry_slots: Arc<Semaphore>,
}
impl BotStore {
    pub async fn load(db: &DbPool) -> Result<Self, String> {
        let config = repository::get_bot_config(db)
            .await
            .map_err(|_| "unable to load bot configuration")?;
        let rules = repository::list_bot_rules(db)
            .await
            .map_err(|_| "unable to load bot rules")?;
        let snapshot = compile_snapshot(config, rules).map_err(|_| "invalid bot configuration")?;
        Ok(Self {
            current: ArcSwap::from_pointee(snapshot),
            audit: RwLock::new(None),
            telemetry_slots: Arc::new(Semaphore::new(MAX_IN_FLIGHT_DETECTIONS)),
        })
    }
    pub fn snapshot(&self) -> Arc<BotSnapshot> {
        self.current.load_full()
    }
    pub fn configure_audit_sink(&self, db: DbPool, realtime: Arc<RealtimeHub>) {
        if let Ok(mut sink) = self.audit.write() {
            *sink = Some(Sink { db, realtime });
        }
    }
    pub fn record_detection(&self, evaluation: &BotEvaluation) {
        let Ok(guard) = self.audit.read() else { return };
        let Some(sink) = guard.clone() else { return };
        let Ok(slot) = self.telemetry_slots.clone().try_acquire_owned() else {
            return;
        };
        let categories = evaluation
            .categories
            .iter()
            .take(8)
            .map(|s| s.chars().take(32).collect::<String>())
            .collect::<Vec<_>>()
            .join(",");
        let fingerprint = evaluation.fingerprint.chars().take(16).collect::<String>();
        let details = format!(
            "action={:?};score={};trusted={};categories={};fingerprint_prefix={}",
            evaluation.action, evaluation.score, evaluation.trusted, categories, fingerprint
        );
        tokio::spawn(async move {
            audit::record(&sink.db, None, "bot_detection", &details).await;
            sink.realtime.publish("audit");
            drop(slot);
        });
    }
    pub async fn reload(&self, db: &DbPool) -> Result<(), String> {
        let config = repository::get_bot_config(db)
            .await
            .map_err(|_| "unable to load bot configuration")?;
        let rules = repository::list_bot_rules(db)
            .await
            .map_err(|_| "unable to load bot rules")?;
        let snapshot = compile_snapshot(config, rules).map_err(|_| "invalid bot configuration")?;
        self.current.store(Arc::new(snapshot));
        Ok(())
    }
}
