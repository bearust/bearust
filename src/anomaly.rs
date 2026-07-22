//! Deterministic, process-local anomaly detection engine.
use crate::analytics::AnalyticsSnapshot;
use crate::baseline::{BaselineSnapshot, BaselineStatus};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;

pub const DEFAULT_MAX_ANOMALY_RECORDS: usize = 500;
pub const DEFAULT_COOLDOWN_SECONDS: i64 = 300;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalyRule {
    RequestRate,
    ErrorRate,
    Latency,
    SecurityEvents,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AnomalySeverity {
    Info,
    Warning,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnomalyRecord {
    pub id: u64,
    pub host_id: i64,
    pub rule: AnomalyRule,
    pub severity: AnomalySeverity,
    pub score: f64,
    pub summary: String,
    pub observed_at: DateTime<Utc>,
    pub acknowledged: bool,
}

struct CooldownState {
    last_emitted: DateTime<Utc>,
    last_severity: AnomalySeverity,
}

struct State {
    records: VecDeque<AnomalyRecord>,
    cooldowns: HashMap<(i64, AnomalyRule), CooldownState>,
}

pub struct AnomalyDetector {
    state: Mutex<State>,
    max_records: usize,
    next_id: AtomicU64,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_ANOMALY_RECORDS)
    }
}

impl AnomalyDetector {
    pub fn with_limits(max_records: usize) -> Self {
        Self {
            state: Mutex::new(State {
                records: VecDeque::new(),
                cooldowns: HashMap::new(),
            }),
            max_records: max_records.clamp(10, DEFAULT_MAX_ANOMALY_RECORDS),
            next_id: AtomicU64::new(1),
        }
    }

    pub fn evaluate(
        &self,
        baseline: &BaselineSnapshot,
        observed: &AnalyticsSnapshot,
        now: DateTime<Utc>,
    ) -> Vec<AnomalyRecord> {
        let mut candidates = Vec::new();

        // Calculate observed metrics per host in the observed snapshot
        let mut host_stats: HashMap<i64, (u64, u64, u64, Vec<u64>)> = HashMap::new(); // (total_reqs, errors, security_blocks, p95_list)
        for b in &observed.timeseries {
            let entry = host_stats.entry(b.proxy_host_id).or_insert((0, 0, 0, Vec::new()));
            entry.0 += b.requests;
            entry.1 += b.status_4xx + b.status_5xx;
            entry.2 += b.waf_blocks + b.bot_blocks + b.bot_challenges + b.rate_limited;
            if let Some(v) = b.p95_ms {
                entry.3.push(v);
            }
        }

        let target_host = baseline.host_id;

        for (&host_id, &(obs_reqs, obs_errors, obs_sec, ref obs_p95_samples)) in &host_stats {
            if target_host.is_some_and(|target| target != host_id) {
                continue;
            }

            let obs_req_per_sec = obs_reqs as f64 / 60.0;
            let obs_error_rate = if obs_reqs > 0 {
                (obs_errors as f64 / obs_reqs as f64) * 100.0
            } else {
                0.0
            };

            let obs_p95 = if obs_p95_samples.is_empty() {
                None
            } else {
                Some(obs_p95_samples.iter().sum::<u64>() / obs_p95_samples.len() as u64)
            };

            // Rule 1: Request Rate Spike
            let base_req_rate = baseline.metrics.req_per_sec.max(0.1);
            let rate_ratio = obs_req_per_sec / base_req_rate;

            if rate_ratio >= 2.0 && obs_reqs >= 10 {
                let (sev, score) = if rate_ratio >= 5.0 {
                    (AnomalySeverity::Critical, rate_ratio)
                } else if rate_ratio >= 3.0 {
                    (AnomalySeverity::Warning, rate_ratio)
                } else {
                    (AnomalySeverity::Info, rate_ratio)
                };

                let summary = format!(
                    "Request rate spike of {:.1} req/s vs baseline {:.1} req/s",
                    obs_req_per_sec, baseline.metrics.req_per_sec
                );
                candidates.push((host_id, AnomalyRule::RequestRate, sev, score, summary));
            }

            // Rule 2: Error Rate Spike
            let error_delta = obs_error_rate - baseline.metrics.error_rate_percent;
            if obs_error_rate >= 10.0 && error_delta >= 5.0 && obs_reqs >= 10 {
                let (sev, score) = if obs_error_rate >= 25.0 && error_delta >= 15.0 {
                    (AnomalySeverity::Critical, obs_error_rate)
                } else if obs_error_rate >= 15.0 {
                    (AnomalySeverity::Warning, obs_error_rate)
                } else {
                    (AnomalySeverity::Info, obs_error_rate)
                };

                let summary = format!(
                    "Error rate spike of {:.1}% vs baseline {:.1}%",
                    obs_error_rate, baseline.metrics.error_rate_percent
                );
                candidates.push((host_id, AnomalyRule::ErrorRate, sev, score, summary));
            }

            // Rule 3: Latency Regression
            if let (Some(obs_lat), Some(base_lat)) = (obs_p95, baseline.metrics.p95_ms) {
                if base_lat > 0 {
                    let lat_ratio = obs_lat as f64 / base_lat as f64;
                    if lat_ratio >= 2.5 && obs_lat >= 100 {
                        let (sev, score) = if lat_ratio >= 5.0 {
                            (AnomalySeverity::Critical, lat_ratio)
                        } else if lat_ratio >= 3.0 {
                            (AnomalySeverity::Warning, lat_ratio)
                        } else {
                            (AnomalySeverity::Info, lat_ratio)
                        };

                        let summary = format!(
                            "Latency p95 regression to {} ms vs baseline {} ms",
                            obs_lat, base_lat
                        );
                        candidates.push((host_id, AnomalyRule::Latency, sev, score, summary));
                    }
                }
            }

            // Rule 4: Security Events Spike
            let base_sec = baseline.metrics.waf_blocks
                + baseline.metrics.bot_blocks
                + baseline.metrics.bot_challenges
                + baseline.metrics.rate_limited;
            let sec_ratio = if base_sec > 0 {
                obs_sec as f64 / base_sec as f64
            } else if obs_sec >= 10 {
                10.0
            } else {
                1.0
            };

            if obs_sec >= 10 && sec_ratio >= 2.5 {
                let (sev, score) = if sec_ratio >= 5.0 {
                    (AnomalySeverity::Critical, sec_ratio)
                } else if sec_ratio >= 3.0 {
                    (AnomalySeverity::Warning, sec_ratio)
                } else {
                    (AnomalySeverity::Info, sec_ratio)
                };

                let summary = format!(
                    "Security events spike of {} blocks vs baseline {}",
                    obs_sec, base_sec
                );
                candidates.push((host_id, AnomalyRule::SecurityEvents, sev, score, summary));
            }
        }

        let Ok(mut state) = self.state.lock() else {
            return Vec::new();
        };

        let is_warming_up = baseline.status == BaselineStatus::WarmingUp;
        let mut produced = Vec::new();

        for (host_id, rule, mut severity, raw_score, summary) in candidates {
            // Constraint: WarmingUp status MUST NOT produce Critical severity
            if is_warming_up && severity == AnomalySeverity::Critical {
                severity = AnomalySeverity::Warning;
            }

            // Reject NaN or Inf floats, round cleanly to 2 decimal places
            let score = if raw_score.is_nan() || raw_score.is_infinite() {
                1.0
            } else {
                (raw_score * 100.0).round() / 100.0
            };

            // Cooldown check
            let key = (host_id, rule);
            if let Some(cd) = state.cooldowns.get(&key) {
                let elapsed = (now - cd.last_emitted).num_seconds();
                if elapsed < DEFAULT_COOLDOWN_SECONDS && severity <= cd.last_severity {
                    continue;
                }
            }

            state.cooldowns.insert(
                key,
                CooldownState {
                    last_emitted: now,
                    last_severity: severity,
                },
            );

            let record = AnomalyRecord {
                id: self.next_id.fetch_add(1, Ordering::SeqCst),
                host_id,
                rule,
                severity,
                score,
                summary,
                observed_at: now,
                acknowledged: false,
            };

            state.records.push_back(record.clone());
            produced.push(record);

            while state.records.len() > self.max_records {
                state.records.pop_front();
            }
        }

        produced
    }

    pub fn get_anomalies(
        &self,
        host_id: Option<i64>,
        severity: Option<AnomalySeverity>,
        rule: Option<AnomalyRule>,
    ) -> Vec<AnomalyRecord> {
        let Ok(state) = self.state.lock() else {
            return Vec::new();
        };

        state
            .records
            .iter()
            .filter(|r| {
                if host_id.is_some_and(|target| target != r.host_id) {
                    return false;
                }
                if severity.is_some_and(|target| target != r.severity) {
                    return false;
                }
                if rule.is_some_and(|target| target != r.rule) {
                    return false;
                }
                true
            })
            .cloned()
            .collect()
    }

    pub fn acknowledge(&self, id: u64) -> Option<AnomalyRecord> {
        let Ok(mut state) = self.state.lock() else {
            return None;
        };

        for r in state.records.iter_mut() {
            if r.id == id {
                r.acknowledged = true;
                return Some(r.clone());
            }
        }
        None
    }
}
