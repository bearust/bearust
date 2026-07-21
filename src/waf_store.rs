use crate::{control_plane::repository::{self, DbPool}, waf::{compile_snapshot, WafSnapshot}};
use arc_swap::ArcSwap;
use std::sync::Arc;

pub struct WafStore {
    current: ArcSwap<WafSnapshot>,
}

impl WafStore {
    pub async fn load(db: &DbPool) -> Result<Self, String> {
        let config = repository::get_waf_config(db).await.map_err(|_| "unable to load waf configuration")?;
        let rules = repository::list_waf_rules(db).await.map_err(|_| "unable to load waf rules")?;
        let snapshot = compile_snapshot(config, rules).map_err(|_| "invalid waf configuration")?;
        Ok(Self { current: ArcSwap::from_pointee(snapshot) })
    }

    pub fn snapshot(&self) -> Arc<WafSnapshot> { self.current.load_full() }

    pub async fn reload(&self, db: &DbPool) -> Result<(), String> {
        let config = repository::get_waf_config(db).await.map_err(|_| "unable to load waf configuration")?;
        let rules = repository::list_waf_rules(db).await.map_err(|_| "unable to load waf rules")?;
        let snapshot = compile_snapshot(config, rules).map_err(|_| "invalid waf configuration")?;
        self.current.store(Arc::new(snapshot));
        Ok(())
    }
}
