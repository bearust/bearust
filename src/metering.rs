//! Per-host usage metering for a managing control plane (Bearust Cloud).
//!
//! Counters are keyed by the host of the matched route, kept in memory with
//! atomics, and monotonic since process start. A random `boot_id` identifies
//! the process so a poller can tell a counter reset (restart) from traffic.
//! Recording never blocks on I/O and the number of hosts is capped, so
//! metering cannot grow without bound or slow the data plane.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock, RwLock};
use uuid::Uuid;

/// Default cap on distinct metered hosts.
pub const DEFAULT_MAX_HOSTS: usize = 10_000;

/// Path prefix of ACME HTTP-01 challenges, which are never metered.
const ACME_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

#[derive(Default)]
struct HostCounters {
    requests: AtomicU64,
    bytes_in: AtomicU64,
    bytes_out: AtomicU64,
    status_2xx: AtomicU64,
    status_3xx: AtomicU64,
    status_4xx: AtomicU64,
    status_5xx: AtomicU64,
    waf_logged: AtomicU64,
    waf_blocked: AtomicU64,
    /// Most recent WAF events, oldest first, at most `MAX_WAF_EVENTS_PER_HOST`.
    waf_events: Mutex<VecDeque<WafEvent>>,
}

/// Recent WAF events kept per host.
pub const MAX_WAF_EVENTS_PER_HOST: usize = 50;
const MAX_EVENT_PATH_BYTES: usize = 256;
const MAX_EVENT_RULE_IDS: usize = 8;
const MAX_EVENT_CATEGORIES: usize = 4;
const MAX_EVENT_CATEGORY_BYTES: usize = 64;

/// What the WAF did with a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum WafEventAction {
    Log,
    Block,
}

/// One redacted WAF detection: no query string, headers, cookies or body.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WafEvent {
    pub at: chrono::DateTime<chrono::Utc>,
    pub action: WafEventAction,
    pub rule_ids: Vec<i64>,
    pub categories: Vec<String>,
    pub method: String,
    /// Request path without the query string, truncated.
    pub path: String,
    pub client_ip: Option<IpAddr>,
}

/// One WAF detection as seen by the meter.
pub struct WafSample<'a> {
    /// Host of the route whose policy decided.
    pub host: &'a str,
    pub action: WafEventAction,
    pub rule_ids: &'a [i64],
    pub categories: &'a [String],
    pub method: &'a str,
    pub path: &'a str,
    pub client_ip: Option<IpAddr>,
}

/// Response body of `GET /api/usage/waf-events`: newest event first.
#[derive(Clone, Debug, Serialize)]
pub struct WafEventsReport {
    pub boot_id: Uuid,
    pub hosts: BTreeMap<String, Vec<WafEvent>>,
}

/// Counters of one host, as served by `GET /api/usage`.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct HostUsage {
    pub requests: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub status_2xx: u64,
    pub status_3xx: u64,
    pub status_4xx: u64,
    pub status_5xx: u64,
    /// Requests a route WAF policy logged (monitor mode or `log` rules).
    pub waf_logged: u64,
    /// Requests a route WAF policy blocked.
    pub waf_blocked: u64,
}

/// Response body of `GET /api/usage`.
#[derive(Clone, Debug, Serialize)]
pub struct UsageReport {
    pub boot_id: Uuid,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub hosts: BTreeMap<String, HostUsage>,
}

/// One completed request as seen by the meter.
pub struct UsageSample<'a> {
    /// Host of the matched route; requests without a route are not metered.
    pub host: Option<&'a str>,
    pub path: &'a str,
    pub status: u16,
    pub bytes_in: u64,
    pub bytes_out: u64,
}

pub struct UsageMeter {
    boot_id: Uuid,
    started_at: chrono::DateTime<chrono::Utc>,
    max_hosts: usize,
    hosts: RwLock<HashMap<String, Arc<HostCounters>>>,
}

impl Default for UsageMeter {
    fn default() -> Self {
        Self::new(DEFAULT_MAX_HOSTS)
    }
}

impl UsageMeter {
    pub fn new(max_hosts: usize) -> Self {
        Self {
            boot_id: Uuid::new_v4(),
            started_at: chrono::Utc::now(),
            max_hosts,
            hosts: RwLock::new(HashMap::new()),
        }
    }

    pub fn boot_id(&self) -> Uuid {
        self.boot_id
    }

    /// Count one completed request. Requests without a matched route, ACME
    /// challenges, and new hosts beyond the cap are ignored.
    pub fn record(&self, sample: UsageSample<'_>) {
        let Some(host) = sample.host.map(normalize).filter(|h| !h.is_empty()) else {
            return;
        };
        if sample.path.starts_with(ACME_CHALLENGE_PREFIX) {
            return;
        }
        let Some(counters) = self.counters(&host) else {
            return;
        };
        counters.requests.fetch_add(1, Ordering::Relaxed);
        counters
            .bytes_in
            .fetch_add(sample.bytes_in, Ordering::Relaxed);
        counters
            .bytes_out
            .fetch_add(sample.bytes_out, Ordering::Relaxed);
        let class = match sample.status {
            200..=299 => Some(&counters.status_2xx),
            300..=399 => Some(&counters.status_3xx),
            400..=499 => Some(&counters.status_4xx),
            500..=599 => Some(&counters.status_5xx),
            _ => None,
        };
        if let Some(class) = class {
            class.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Count one WAF detection and keep a redacted sample of it. ACME
    /// challenges and new hosts beyond the cap are ignored.
    pub fn record_waf(&self, sample: WafSample<'_>) {
        let host = normalize(sample.host);
        if host.is_empty() || sample.path.starts_with(ACME_CHALLENGE_PREFIX) {
            return;
        }
        let Some(counters) = self.counters(&host) else {
            return;
        };
        match sample.action {
            WafEventAction::Log => &counters.waf_logged,
            WafEventAction::Block => &counters.waf_blocked,
        }
        .fetch_add(1, Ordering::Relaxed);
        let event = WafEvent {
            at: chrono::Utc::now(),
            action: sample.action,
            rule_ids: sample
                .rule_ids
                .iter()
                .copied()
                .take(MAX_EVENT_RULE_IDS)
                .collect(),
            categories: sample
                .categories
                .iter()
                .take(MAX_EVENT_CATEGORIES)
                .map(|category| clean(category, MAX_EVENT_CATEGORY_BYTES))
                .collect(),
            method: clean(sample.method, 16),
            path: clean(sample.path, MAX_EVENT_PATH_BYTES),
            client_ip: sample.client_ip,
        };
        if let Ok(mut events) = counters.waf_events.lock() {
            if events.len() >= MAX_WAF_EVENTS_PER_HOST {
                events.pop_front();
            }
            events.push_back(event);
        };
    }

    /// Recent WAF events for the given hosts only, newest first.
    pub fn waf_events<'a>(&self, hosts: impl IntoIterator<Item = &'a str>) -> WafEventsReport {
        let wanted: HashSet<String> = hosts.into_iter().map(normalize).collect();
        let map = self.hosts.read().map(|h| h.clone()).unwrap_or_default();
        let hosts = wanted
            .into_iter()
            .filter(|h| !h.is_empty())
            .map(|host| {
                let events = map
                    .get(&host)
                    .and_then(|c| {
                        c.waf_events
                            .lock()
                            .ok()
                            .map(|e| e.iter().rev().cloned().collect())
                    })
                    .unwrap_or_default();
                (host, events)
            })
            .collect();
        WafEventsReport {
            boot_id: self.boot_id,
            hosts,
        }
    }

    fn counters(&self, host: &str) -> Option<Arc<HostCounters>> {
        if let Some(found) = self.hosts.read().ok()?.get(host) {
            return Some(Arc::clone(found));
        }
        let mut hosts = self.hosts.write().ok()?;
        if let Some(found) = hosts.get(host) {
            return Some(Arc::clone(found));
        }
        if hosts.len() >= self.max_hosts {
            return None;
        }
        let created = Arc::new(HostCounters::default());
        hosts.insert(host.to_owned(), Arc::clone(&created));
        Some(created)
    }

    /// Counters for the given hosts only (the hosts of the desired state).
    /// Hosts with no traffic yet are reported as zero.
    pub fn report<'a>(&self, hosts: impl IntoIterator<Item = &'a str>) -> UsageReport {
        let wanted: HashSet<String> = hosts.into_iter().map(normalize).collect();
        let map = self.hosts.read().map(|h| h.clone()).unwrap_or_default();
        let hosts = wanted
            .into_iter()
            .filter(|h| !h.is_empty())
            .map(|host| {
                let usage = map.get(&host).map(|c| snapshot(c)).unwrap_or_default();
                (host, usage)
            })
            .collect();
        UsageReport {
            boot_id: self.boot_id,
            started_at: self.started_at,
            hosts,
        }
    }
}

fn snapshot(c: &HostCounters) -> HostUsage {
    HostUsage {
        requests: c.requests.load(Ordering::Relaxed),
        bytes_in: c.bytes_in.load(Ordering::Relaxed),
        bytes_out: c.bytes_out.load(Ordering::Relaxed),
        status_2xx: c.status_2xx.load(Ordering::Relaxed),
        status_3xx: c.status_3xx.load(Ordering::Relaxed),
        status_4xx: c.status_4xx.load(Ordering::Relaxed),
        status_5xx: c.status_5xx.load(Ordering::Relaxed),
        waf_logged: c.waf_logged.load(Ordering::Relaxed),
        waf_blocked: c.waf_blocked.load(Ordering::Relaxed),
    }
}

/// Drop control characters and cut to `max` bytes at a char boundary.
fn clean(value: &str, max: usize) -> String {
    let mut out = String::new();
    for ch in value.chars().filter(|ch| !ch.is_control()) {
        if out.len() + ch.len_utf8() > max {
            break;
        }
        out.push(ch);
    }
    out
}

fn normalize(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// The process-wide meter shared by the proxy and the control plane.
pub fn global() -> &'static UsageMeter {
    static METER: OnceLock<UsageMeter> = OnceLock::new();
    METER.get_or_init(UsageMeter::default)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample<'a>(host: &'a str, path: &'static str, status: u16) -> UsageSample<'a> {
        UsageSample {
            host: Some(host),
            path,
            status,
            bytes_in: 10,
            bytes_out: 100,
        }
    }

    #[test]
    fn counts_requests_bytes_and_status_classes_per_host() {
        let meter = UsageMeter::new(10);
        meter.record(sample("a.example", "/", 200));
        meter.record(sample("A.example.", "/x", 304));
        meter.record(sample("a.example", "/", 404));
        meter.record(sample("a.example", "/", 502));
        meter.record(sample("b.example", "/", 201));
        let report = meter.report(["a.example", "b.example"]);
        assert_eq!(
            report.hosts["a.example"],
            HostUsage {
                requests: 4,
                bytes_in: 40,
                bytes_out: 400,
                status_2xx: 1,
                status_3xx: 1,
                status_4xx: 1,
                status_5xx: 1,
                waf_logged: 0,
                waf_blocked: 0,
            }
        );
        assert_eq!(report.hosts["b.example"].requests, 1);
    }

    #[test]
    fn excludes_acme_challenges_and_unmatched_requests() {
        let meter = UsageMeter::new(10);
        meter.record(sample("a.example", "/.well-known/acme-challenge/tok", 200));
        meter.record(UsageSample {
            host: None,
            path: "/",
            status: 200,
            bytes_in: 1,
            bytes_out: 1,
        });
        assert_eq!(meter.report(["a.example"]).hosts["a.example"].requests, 0);
    }

    #[test]
    fn host_cardinality_is_bounded() {
        let meter = UsageMeter::new(2);
        meter.record(sample("a.example", "/", 200));
        meter.record(sample("b.example", "/", 200));
        meter.record(sample("c.example", "/", 200));
        meter.record(sample("a.example", "/", 200));
        assert_eq!(meter.hosts.read().unwrap().len(), 2);
        let report = meter.report(["a.example", "c.example"]);
        assert_eq!(report.hosts["a.example"].requests, 2);
        assert_eq!(report.hosts["c.example"].requests, 0);
    }

    #[test]
    fn report_is_limited_to_requested_hosts() {
        let meter = UsageMeter::new(10);
        meter.record(sample("a.example", "/", 200));
        meter.record(sample("secret.example", "/", 200));
        let report = meter.report(["a.example"]);
        assert_eq!(report.hosts.len(), 1);
        assert!(!report.hosts.contains_key("secret.example"));
    }

    #[test]
    fn each_process_has_its_own_boot_id_for_reset_detection() {
        let first = UsageMeter::new(10);
        let second = UsageMeter::new(10);
        assert_ne!(first.boot_id(), second.boot_id());
        assert_eq!(first.report([]).boot_id, first.boot_id());
    }

    fn waf<'a>(host: &'a str, action: WafEventAction, path: &'a str) -> WafSample<'a> {
        WafSample {
            host,
            action,
            rule_ids: &[-1, 7],
            categories: &[],
            method: "GET",
            path,
            client_ip: Some("203.0.113.9".parse().unwrap()),
        }
    }

    #[test]
    fn counts_waf_detections_per_host() {
        let meter = UsageMeter::new(10);
        meter.record_waf(waf("a.example", WafEventAction::Log, "/"));
        meter.record_waf(waf("A.example.", WafEventAction::Block, "/"));
        meter.record_waf(waf("a.example", WafEventAction::Block, "/"));
        meter.record_waf(waf("b.example", WafEventAction::Block, "/"));
        meter.record_waf(waf(
            "a.example",
            WafEventAction::Block,
            "/.well-known/acme-challenge/t",
        ));
        let report = meter.report(["a.example", "b.example"]);
        assert_eq!(report.hosts["a.example"].waf_logged, 1);
        assert_eq!(report.hosts["a.example"].waf_blocked, 2);
        assert_eq!(report.hosts["b.example"].waf_blocked, 1);
        assert_eq!(report.hosts["a.example"].requests, 0);
    }

    #[test]
    fn waf_events_are_bounded_redacted_and_newest_first() {
        let meter = UsageMeter::new(10);
        let long = format!("/{}\u{7}", "x".repeat(400));
        for i in 0..(MAX_WAF_EVENTS_PER_HOST + 5) {
            let path = if i == MAX_WAF_EVENTS_PER_HOST + 4 {
                long.as_str()
            } else {
                "/old"
            };
            meter.record_waf(waf("a.example", WafEventAction::Block, path));
        }
        meter.record_waf(waf("secret.example", WafEventAction::Block, "/"));
        let report = meter.waf_events(["a.example"]);
        assert_eq!(report.hosts.len(), 1);
        let events = &report.hosts["a.example"];
        assert_eq!(events.len(), MAX_WAF_EVENTS_PER_HOST);
        assert_eq!(events[0].path.len(), MAX_EVENT_PATH_BYTES);
        assert!(!events[0].path.contains('\u{7}'));
        assert_eq!(events[0].rule_ids, vec![-1, 7]);
        assert_eq!(events[1].path, "/old");
    }
}
