//! Bounded, process-local request analytics.
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::sync::Mutex;

pub const DEFAULT_MAX_BUCKETS: usize = 1_440;
pub const DEFAULT_MAX_HOSTS: usize = 100;

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SecurityCounters {
    pub waf_blocks: u64,
    /// Requests blocked by bot policy (distinct from challenge responses).
    pub bot_blocks: u64,
    pub bot_challenges: u64,
    pub rate_limited: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalyticsEvent {
    pub proxy_host_id: i64,
    pub timestamp: DateTime<Utc>,
    pub status_code: u16,
    pub latency_ms: u64,
    pub security: SecurityCounters,
}

#[derive(Clone, Debug, Default)]
pub struct AnalyticsFilter {
    pub proxy_host_id: Option<i64>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub limit: usize,
}

impl AnalyticsFilter {
    fn limit(&self) -> usize {
        if self.limit == 0 {
            DEFAULT_MAX_BUCKETS
        } else {
            self.limit.min(DEFAULT_MAX_BUCKETS)
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AnalyticsSummary {
    pub requests: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub waf_blocks: u64,
    pub bot_blocks: u64,
    pub bot_challenges: u64,
    pub rate_limited: u64,
    pub p50_ms: Option<u64>,
    pub p95_ms: Option<u64>,
    pub p99_ms: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnalyticsBucket {
    pub timestamp: DateTime<Utc>,
    pub proxy_host_id: i64,
    pub requests: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    pub waf_blocks: u64,
    pub bot_blocks: u64,
    pub bot_challenges: u64,
    pub rate_limited: u64,
    pub p50_ms: Option<u64>,
    pub p95_ms: Option<u64>,
    pub p99_ms: Option<u64>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct AnalyticsSnapshot {
    pub summary: AnalyticsSummary,
    pub timeseries: Vec<AnalyticsBucket>,
}

#[derive(Default)]
struct Bucket {
    timestamp: DateTime<Utc>,
    requests: u64,
    status: [u64; 5],
    security: SecurityCounters,
    histogram: [u64; 14],
}

struct State {
    hosts: BTreeMap<i64, VecDeque<Bucket>>,
}

pub struct AnalyticsCollector {
    state: Mutex<State>,
    max_hosts: usize,
    max_buckets: usize,
}

impl Default for AnalyticsCollector {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_HOSTS, DEFAULT_MAX_BUCKETS)
    }
}

impl AnalyticsCollector {
    pub fn new(max_hosts: usize) -> Self {
        Self::with_limits(max_hosts, DEFAULT_MAX_BUCKETS)
    }
    pub fn with_limits(max_hosts: usize, max_buckets: usize) -> Self {
        Self {
            state: Mutex::new(State {
                hosts: BTreeMap::new(),
            }),
            max_hosts: max_hosts.clamp(1, DEFAULT_MAX_HOSTS),
            max_buckets: max_buckets.clamp(1, DEFAULT_MAX_BUCKETS),
        }
    }
    pub fn host_count(&self) -> usize {
        self.state.lock().map(|s| s.hosts.len()).unwrap_or(0)
    }

    pub fn record(&self, event: AnalyticsEvent) {
        let minute = event.timestamp.timestamp().div_euclid(60) * 60;
        let ts = DateTime::<Utc>::from_timestamp(minute, 0).unwrap_or(event.timestamp);
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if !state.hosts.contains_key(&event.proxy_host_id) {
            if state.hosts.len() >= self.max_hosts {
                if let Some((&host, _)) = state
                    .hosts
                    .iter()
                    .min_by_key(|(_, q)| q.back().map(|b| b.timestamp))
                {
                    state.hosts.remove(&host);
                }
            }
            state.hosts.insert(event.proxy_host_id, VecDeque::new());
        }
        let q = state
            .hosts
            .get_mut(&event.proxy_host_id)
            .expect("inserted host");
        let window = Duration::minutes(self.max_buckets as i64 - 1);
        if q.back()
            .is_some_and(|latest| ts < latest.timestamp - window)
        {
            return;
        }
        if q.back().is_none_or(|latest| ts > latest.timestamp) {
            while q.front().is_some_and(|b| b.timestamp < ts - window) {
                q.pop_front();
            }
        }
        let index = match q.iter().position(|b| b.timestamp == ts) {
            Some(index) => index,
            None => {
                let index = q.iter().position(|b| b.timestamp > ts).unwrap_or(q.len());
                q.insert(
                    index,
                    Bucket {
                        timestamp: ts,
                        ..Default::default()
                    },
                );
                index
            }
        };
        let bucket = q.get_mut(index).expect("bucket inserted or found");
        bucket.requests += 1;
        let class = match event.status_code {
            200..=299 => 0,
            300..=399 => 1,
            400..=499 => 2,
            500..=599 => 3,
            _ => 4,
        };
        bucket.status[class] += 1;
        bucket.security.waf_blocks += event.security.waf_blocks;
        bucket.security.bot_blocks += event.security.bot_blocks;
        bucket.security.bot_challenges += event.security.bot_challenges;
        bucket.security.rate_limited += event.security.rate_limited;
        let idx = HISTOGRAM_BOUNDS
            .iter()
            .position(|b| event.latency_ms <= *b)
            .unwrap_or(HISTOGRAM_BOUNDS.len() - 1);
        bucket.histogram[idx] += 1;
        while q.len() > self.max_buckets {
            q.pop_front();
        }
    }

    pub fn summary(&self, filter: AnalyticsFilter) -> AnalyticsSummary {
        summary_from_buckets(&self.filtered(&filter))
    }
    pub fn timeseries(&self, filter: AnalyticsFilter) -> Vec<AnalyticsBucket> {
        timeseries_from_buckets(self.filtered(&filter), &filter)
    }
    pub fn snapshot(&self) -> AnalyticsSnapshot {
        let filter = AnalyticsFilter::default();
        let buckets = self.filtered(&filter);
        AnalyticsSnapshot {
            summary: summary_from_buckets(&buckets),
            timeseries: timeseries_from_buckets(buckets, &filter),
        }
    }
    fn filtered(&self, f: &AnalyticsFilter) -> Vec<BucketView> {
        let mut out = if let Ok(state) = self.state.lock() {
            let mut captured = Vec::new();
            for (host, q) in &state.hosts {
                if f.proxy_host_id.is_some_and(|h| h != *host) {
                    continue;
                }
                for b in q {
                    if f.from.is_some_and(|x| b.timestamp < x)
                        || f.to.is_some_and(|x| b.timestamp > x)
                    {
                        continue;
                    }
                    captured.push(BucketView::from(((*host), b)));
                }
            }
            captured
        } else {
            Vec::new()
        };
        out.sort_by_key(|b| b.timestamp);
        out
    }
}

const HISTOGRAM_BOUNDS: [u64; 14] = [
    1,
    5,
    10,
    25,
    50,
    100,
    250,
    500,
    1_000,
    2_500,
    5_000,
    10_000,
    60_000,
    u64::MAX,
];
#[derive(Clone)]
struct BucketView {
    host: i64,
    timestamp: DateTime<Utc>,
    requests: u64,
    status: [u64; 5],
    security: SecurityCounters,
    histogram: [u64; 14],
}
impl<'a> From<(i64, &'a Bucket)> for BucketView {
    fn from((host, b): (i64, &'a Bucket)) -> Self {
        Self {
            host,
            timestamp: b.timestamp,
            requests: b.requests,
            status: b.status,
            security: b.security.clone(),
            histogram: b.histogram,
        }
    }
}
fn merge(s: &mut AnalyticsSummary, st: &[u64; 5], sec: &SecurityCounters, h: &[u64; 14]) {
    s.requests += st.iter().sum::<u64>();
    s.status_2xx += st[0];
    s.status_3xx += st[1];
    s.status_4xx += st[2];
    s.status_5xx += st[3];
    s.waf_blocks += sec.waf_blocks;
    s.bot_blocks += sec.bot_blocks;
    s.bot_challenges += sec.bot_challenges;
    s.rate_limited += sec.rate_limited;
    let _ = h;
}
fn summary_from_buckets(buckets: &[BucketView]) -> AnalyticsSummary {
    let mut s = AnalyticsSummary::default();
    let mut hist = [0u64; 14];
    for b in buckets {
        merge(&mut s, &b.status, &b.security, &b.histogram);
        for (i, n) in b.histogram.iter().enumerate() {
            hist[i] += n;
        }
    }
    let n = s.requests;
    s.p50_ms = percentile(&hist, n, 0.50);
    s.p95_ms = percentile(&hist, n, 0.95);
    s.p99_ms = percentile(&hist, n, 0.99);
    s
}
fn timeseries_from_buckets(
    buckets: Vec<BucketView>,
    filter: &AnalyticsFilter,
) -> Vec<AnalyticsBucket> {
    buckets
        .into_iter()
        .take(filter.limit())
        .map(|b| to_bucket(b, filter.proxy_host_id.unwrap_or(0)))
        .collect()
}
fn percentile(h: &[u64; 14], n: u64, p: f64) -> Option<u64> {
    if n == 0 {
        return None;
    }
    let rank = ((n as f64 * p).ceil() as u64).max(1);
    let mut c = 0;
    for (i, v) in h.iter().enumerate() {
        c += v;
        if c >= rank {
            return Some(HISTOGRAM_BOUNDS[i]);
        }
    }
    None
}
fn to_bucket(b: BucketView, host: i64) -> AnalyticsBucket {
    let mut s = AnalyticsSummary::default();
    merge(&mut s, &b.status, &b.security, &b.histogram);
    s.p50_ms = percentile(&b.histogram, b.requests, 0.5);
    s.p95_ms = percentile(&b.histogram, b.requests, 0.95);
    s.p99_ms = percentile(&b.histogram, b.requests, 0.99);
    AnalyticsBucket {
        timestamp: b.timestamp,
        proxy_host_id: if host == 0 { b.host } else { host },
        requests: b.requests,
        status_2xx: b.status[0],
        status_3xx: b.status[1],
        status_4xx: b.status[2],
        status_5xx: b.status[3],
        waf_blocks: b.security.waf_blocks,
        bot_blocks: b.security.bot_blocks,
        bot_challenges: b.security.bot_challenges,
        rate_limited: b.security.rate_limited,
        p50_ms: s.p50_ms,
        p95_ms: s.p95_ms,
        p99_ms: s.p99_ms,
    }
}
