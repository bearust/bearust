//! Guarded adaptive tuning engine and policy recommendation generator.
use crate::anomaly::{AnomalyRecord, AnomalyRule, AnomalySeverity};
use crate::rate_limit::RateLimitPolicy;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum TuningMode {
    #[default]
    Monitor,
    Recommend,
    Enforce,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TuningPolicy {
    pub mode: TuningMode,
    pub max_delta_percent: u8,
    pub cooldown_seconds: u64,
    pub min_confidence: f64,
}

impl TuningPolicy {
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.max_delta_percent == 0 || self.max_delta_percent > 100 {
            return Err("max_delta_percent must be between 1 and 100");
        }
        if !(10..=86400).contains(&self.cooldown_seconds) {
            return Err("cooldown_seconds must be between 10 and 86400");
        }
        if self.min_confidence.is_nan()
            || self.min_confidence.is_infinite()
            || !(0.1..=1.0).contains(&self.min_confidence)
        {
            return Err("min_confidence must be a number between 0.1 and 1.0");
        }
        Ok(())
    }
}

impl Default for TuningPolicy {
    fn default() -> Self {
        Self {
            mode: TuningMode::Monitor,
            max_delta_percent: 50,
            cooldown_seconds: 300,
            min_confidence: 0.8,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct PolicyPatch {
    pub capacity: Option<u32>,
    pub refill_per_second: Option<f64>,
    pub waf_mode: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyRecommendation {
    pub id: i64,
    pub host_id: i64,
    pub patch: PolicyPatch,
    pub confidence: f64,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub applied: bool,
    pub applied_at: Option<DateTime<Utc>>,
    pub previous_config_json: Option<String>,
}

pub struct AdaptiveTuningEngine {
    emergency_disabled: AtomicBool,
}

impl Default for AdaptiveTuningEngine {
    fn default() -> Self {
        Self {
            emergency_disabled: AtomicBool::new(false),
        }
    }
}

impl AdaptiveTuningEngine {
    pub fn is_emergency_disabled(&self) -> bool {
        self.emergency_disabled.load(Ordering::SeqCst)
    }

    pub fn set_emergency_disabled(&self, disabled: bool) {
        self.emergency_disabled.store(disabled, Ordering::SeqCst);
    }

    pub fn recommend(
        &self,
        anomaly: &AnomalyRecord,
        current_rl: &RateLimitPolicy,
        policy: &TuningPolicy,
    ) -> Option<PolicyRecommendation> {
        let confidence = match anomaly.severity {
            AnomalySeverity::Critical => 0.95,
            AnomalySeverity::Warning => 0.85,
            AnomalySeverity::Info => 0.60,
        };

        if confidence < policy.min_confidence {
            return None;
        }

        let max_delta = (policy.max_delta_percent as f64) / 100.0;

        let mut patch = PolicyPatch::default();
        let mut reason_parts = Vec::new();

        match anomaly.rule {
            AnomalyRule::RequestRate | AnomalyRule::SecurityEvents => {
                let new_cap = (current_rl.capacity as f64 * (1.0 - max_delta * 0.5)).round() as u32;
                let new_cap = new_cap.max(10).min(current_rl.capacity);
                patch.capacity = Some(new_cap);

                let new_refill = (current_rl.refill_per_second * (1.0 - max_delta * 0.5)).round();
                let new_refill = new_refill.max(1.0).min(current_rl.refill_per_second);
                patch.refill_per_second = Some(new_refill);

                reason_parts.push(format!("Adjust rate-limit capacity to {}", new_cap));
            }
            AnomalyRule::ErrorRate | AnomalyRule::Latency => {
                reason_parts.push(format!(
                    "Investigate backend regression on host {}",
                    anomaly.host_id
                ));
            }
        }

        let reason = format!(
            "Recommendation for {} ({:?}) on host {}: {}",
            anomaly.summary,
            anomaly.severity,
            anomaly.host_id,
            reason_parts.join("; ")
        );

        Some(PolicyRecommendation {
            id: 0,
            host_id: anomaly.host_id,
            patch,
            confidence,
            reason,
            created_at: Utc::now(),
            applied: false,
            applied_at: None,
            previous_config_json: None,
        })
    }
}
