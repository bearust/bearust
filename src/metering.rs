//! Per-host usage metering for a managing control plane (Bearust Cloud).
//!
//! Counters are keyed by the host of the matched route, kept in memory with
//! atomics, and monotonic since process start. A random `boot_id` identifies
//! the process so a poller can tell a counter reset (restart) from traffic.
//! Recording never blocks on I/O and the number of hosts is capped, so
//! metering cannot grow without bound or slow the data plane.

use serde::Serialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
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
    }
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
}
