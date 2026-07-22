//! Bounded per-host traffic baseline aggregation.
use crate::analytics::{AnalyticsBucket, AnalyticsSnapshot};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

pub const DEFAULT_MAX_BASELINE_HOSTS: usize = 100;
pub const DEFAULT_MAX_BASELINE_BUCKETS: usize = 1440; // 24 hours of 1-minute buckets
pub const MIN_READY_SAMPLES: usize = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineWindow {
    FiveMinutes,
    OneHour,
    TwentyFourHours,
}

impl BaselineWindow {
    pub fn duration_seconds(&self) -> i64 {
        match self {
            BaselineWindow::FiveMinutes => 300,
            BaselineWindow::OneHour => 3600,
            BaselineWindow::TwentyFourHours => 86400,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineStatus {
    WarmingUp,
    Ready,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct BaselineMetrics {
    pub req_per_sec: f64,
    pub total_requests: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub error_rate_percent: f64,
    pub p50_ms: Option<u64>,
    pub p95_ms: Option<u64>,
    pub p99_ms: Option<u64>,
    pub waf_blocks: u64,
    pub bot_blocks: u64,
    pub bot_challenges: u64,
    pub rate_limited: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BaselineSnapshot {
    pub host_id: Option<i64>,
    pub status: BaselineStatus,
    pub window: BaselineWindow,
    pub sample_count: usize,
    pub metrics: BaselineMetrics,
    pub calculated_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
struct StoredBucket {
    timestamp: DateTime<Utc>,
    requests: u64,
    status_2xx: u64,
    status_3xx: u64,
    status_4xx: u64,
    status_5xx: u64,
    waf_blocks: u64,
    bot_blocks: u64,
    bot_challenges: u64,
    rate_limited: u64,
    p50_ms: Option<u64>,
    p95_ms: Option<u64>,
    p99_ms: Option<u64>,
}

impl From<&AnalyticsBucket> for StoredBucket {
    fn from(b: &AnalyticsBucket) -> Self {
        Self {
            timestamp: b.timestamp,
            requests: b.requests,
            status_2xx: b.status_2xx,
            status_3xx: b.status_3xx,
            status_4xx: b.status_4xx,
            status_5xx: b.status_5xx,
            waf_blocks: b.waf_blocks,
            bot_blocks: b.bot_blocks,
            bot_challenges: b.bot_challenges,
            rate_limited: b.rate_limited,
            p50_ms: b.p50_ms,
            p95_ms: b.p95_ms,
            p99_ms: b.p99_ms,
        }
    }
}

struct State {
    hosts: BTreeMap<i64, VecDeque<StoredBucket>>,
}

pub struct BaselineCollector {
    state: Mutex<State>,
    max_hosts: usize,
    max_buckets: usize,
}

impl Default for BaselineCollector {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_BASELINE_HOSTS, DEFAULT_MAX_BASELINE_BUCKETS)
    }
}

impl BaselineCollector {
    pub fn new(max_hosts: usize) -> Self {
        Self::with_limits(max_hosts, DEFAULT_MAX_BASELINE_BUCKETS)
    }

    pub fn with_limits(max_hosts: usize, max_buckets: usize) -> Self {
        Self {
            state: Mutex::new(State {
                hosts: BTreeMap::new(),
            }),
            max_hosts: max_hosts.clamp(1, DEFAULT_MAX_BASELINE_HOSTS),
            max_buckets: max_buckets.clamp(1, DEFAULT_MAX_BASELINE_BUCKETS),
        }
    }

    pub fn host_count(&self) -> usize {
        self.state.lock().map(|s| s.hosts.len()).unwrap_or(0)
    }

    pub fn record(&self, snapshot: &AnalyticsSnapshot, _now: DateTime<Utc>) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };

        for b in &snapshot.timeseries {
            let host_id = b.proxy_host_id;
            if !state.hosts.contains_key(&host_id) {
                if state.hosts.len() >= self.max_hosts {
                    if let Some((&evict_host, _)) = state
                        .hosts
                        .iter()
                        .min_by_key(|(_, q)| q.back().map(|bucket| bucket.timestamp))
                    {
                        state.hosts.remove(&evict_host);
                    }
                }
                state.hosts.insert(host_id, VecDeque::new());
            }

            let q = state.hosts.get_mut(&host_id).expect("host present");
            let bucket = StoredBucket::from(b);

            // Upsert bucket into deque maintaining timestamp order
            match q.iter().position(|item| item.timestamp == bucket.timestamp) {
                Some(idx) => {
                    q[idx] = bucket;
                }
                None => {
                    let insert_pos = q
                        .iter()
                        .position(|item| item.timestamp > bucket.timestamp)
                        .unwrap_or(q.len());
                    q.insert(insert_pos, bucket);
                }
            }

            while q.len() > self.max_buckets {
                q.pop_front();
            }
        }
    }

    pub fn snapshot(
        &self,
        host_id: Option<i64>,
        window: BaselineWindow,
        from: DateTime<Utc>,
        to: DateTime<Utc>,
    ) -> BaselineSnapshot {
        let Ok(state) = self.state.lock() else {
            return BaselineSnapshot {
                host_id,
                status: BaselineStatus::WarmingUp,
                window,
                sample_count: 0,
                metrics: BaselineMetrics::default(),
                calculated_at: Utc::now(),
            };
        };

        let mut matching_buckets = Vec::new();
        for (&h, q) in &state.hosts {
            if host_id.is_some_and(|target| target != h) {
                continue;
            }
            for b in q {
                if b.timestamp >= from && b.timestamp <= to {
                    matching_buckets.push(b.clone());
                }
            }
        }

        matching_buckets.sort_by_key(|b| b.timestamp);

        let sample_count = matching_buckets.len();
        let status = if sample_count >= MIN_READY_SAMPLES {
            BaselineStatus::Ready
        } else {
            BaselineStatus::WarmingUp
        };

        let mut total_requests = 0u64;
        let mut status_2xx = 0u64;
        let mut status_3xx = 0u64;
        let mut status_4xx = 0u64;
        let mut status_5xx = 0u64;
        let mut waf_blocks = 0u64;
        let mut bot_blocks = 0u64;
        let mut bot_challenges = 0u64;
        let mut rate_limited = 0u64;
        let mut p50_samples = Vec::new();
        let mut p95_samples = Vec::new();
        let mut p99_samples = Vec::new();

        for b in &matching_buckets {
            total_requests += b.requests;
            status_2xx += b.status_2xx;
            status_3xx += b.status_3xx;
            status_4xx += b.status_4xx;
            status_5xx += b.status_5xx;
            waf_blocks += b.waf_blocks;
            bot_blocks += b.bot_blocks;
            bot_challenges += b.bot_challenges;
            rate_limited += b.rate_limited;
            if let Some(v) = b.p50_ms {
                p50_samples.push(v);
            }
            if let Some(v) = b.p95_ms {
                p95_samples.push(v);
            }
            if let Some(v) = b.p99_ms {
                p99_samples.push(v);
            }
        }

        let duration_secs = window.duration_seconds().max(1) as f64;
        let req_per_sec = total_requests as f64 / duration_secs;

        let total_errors = status_4xx + status_5xx;
        let error_rate_percent = if total_requests > 0 {
            (total_errors as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };

        let calc_avg = |samples: &[u64]| -> Option<u64> {
            if samples.is_empty() {
                None
            } else {
                let sum: u64 = samples.iter().sum();
                Some(sum / samples.len() as u64)
            }
        };

        let metrics = BaselineMetrics {
            req_per_sec,
            total_requests,
            status_2xx,
            status_3xx,
            status_4xx,
            status_5xx,
            error_rate_percent,
            p50_ms: calc_avg(&p50_samples),
            p95_ms: calc_avg(&p95_samples),
            p99_ms: calc_avg(&p99_samples),
            waf_blocks,
            bot_blocks,
            bot_challenges,
            rate_limited,
        };

        BaselineSnapshot {
            host_id,
            status,
            window,
            sample_count,
            metrics,
            calculated_at: Utc::now(),
        }
    }
}
