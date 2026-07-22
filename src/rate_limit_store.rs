//! Bounded, process-local runtime state for rate limiting.
use crate::rate_limit::{Decision, RateLimitKey, RateLimitPolicy, TokenBucket};
use http::{header, HeaderMap};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Mutex, RwLock},
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Network {
    address: IpAddr,
    prefix: u8,
}

impl Network {
    fn contains(self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(net), IpAddr::V4(value)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(net) & mask == u32::from(value) & mask
            }
            (IpAddr::V6(net), IpAddr::V6(value)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(net) & mask == u128::from(value) & mask
            }
            _ => false,
        }
    }
}

/// A finite set of trusted proxy networks. Invalid CIDRs are ignored.
#[derive(Clone, Debug, Default)]
pub struct IpNetSet(Vec<Network>);

impl IpNetSet {
    pub fn new<I, S>(cidrs: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        Self(
            cidrs
                .into_iter()
                .filter_map(|s| parse_network(s.as_ref()))
                .collect(),
        )
    }
    pub fn contains(&self, ip: IpAddr) -> bool {
        self.0.iter().any(|network| network.contains(ip))
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

fn parse_network(value: &str) -> Option<Network> {
    let (address, prefix) = value.trim().split_once('/')?;
    let address = address.parse().ok()?;
    let prefix = prefix.parse().ok()?;
    let valid = match address {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    };
    valid.then_some(Network { address, prefix })
}

struct Entry {
    bucket: TokenBucket,
    last_seen: Instant,
    sequence: u64,
}
struct State {
    entries: HashMap<RateLimitKey, Entry>,
    sequence: u64,
}

/// A lock-protected store with explicit capacity and idle eviction.
pub struct RateLimiterStore {
    max_entries: usize,
    idle_ttl: Duration,
    state: Mutex<State>,
    policy: RwLock<RateLimitPolicy>,
    host_policies: RwLock<HashMap<i64, RateLimitPolicy>>,
}

/// Hard upper bound for process-local entries, preventing accidental
/// unbounded memory growth when configuration is supplied by an operator.
pub const MAX_STORE_ENTRIES: usize = 100_000;

impl RateLimiterStore {
    pub fn new(max_entries: usize, idle_ttl: Duration) -> Self {
        Self {
            max_entries: max_entries.min(MAX_STORE_ENTRIES),
            idle_ttl,
            state: Mutex::new(State {
                entries: HashMap::new(),
                sequence: 0,
            }),
            policy: RwLock::new(RateLimitPolicy::default()),
            host_policies: RwLock::new(HashMap::new()),
        }
    }

    pub fn set_policy(&self, policy: RateLimitPolicy) {
        if let Ok(mut current) = self.policy.write() {
            *current = policy;
        }
        // Buckets encode capacity/refill parameters. Clear them atomically
        // on policy changes so existing clients cannot retain stale limits.
        if let Ok(mut state) = self.state.lock() {
            state.entries.clear();
            state.sequence = 0;
        }
    }

    pub fn set_host_policy(&self, host_id: i64, policy: RateLimitPolicy) {
        if let Ok(mut current) = self.host_policies.write() {
            current.insert(host_id, policy);
        }
        if let Ok(mut state) = self.state.lock() {
            state.entries.retain(|k, _| k.proxy_host_id != host_id);
        }
    }

    pub fn policy(&self) -> RateLimitPolicy {
        self.policy.read().map(|p| p.clone()).unwrap_or_default()
    }

    pub fn host_policy(&self, host_id: i64) -> RateLimitPolicy {
        self.host_policies
            .read()
            .ok()
            .and_then(|map| map.get(&host_id).cloned())
            .unwrap_or_else(|| self.policy())
    }

    pub fn evaluate(&self, key: RateLimitKey, policy: &RateLimitPolicy, now: Instant) -> Decision {
        if !policy.enabled || self.max_entries == 0 || policy.validate().is_err() {
            return Decision::Allowed {
                remaining_tokens: policy.capacity,
            };
        }
        // Validate and construct before mutating the store. This keeps the
        // fail-open contract even if a future policy variant cannot construct
        // a bucket after validation.
        let bucket = match TokenBucket::from_policy(policy) {
            Ok(bucket) => bucket,
            Err(_) => {
                return Decision::Allowed {
                    remaining_tokens: policy.capacity,
                }
            }
        };
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state
            .entries
            .retain(|_, entry| now.saturating_duration_since(entry.last_seen) <= self.idle_ttl);
        if !state.entries.contains_key(&key) && state.entries.len() >= self.max_entries {
            if let Some(oldest) = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.sequence)
                .map(|(key, _)| *key)
            {
                state.entries.remove(&oldest);
            }
        }
        state.sequence = state.sequence.wrapping_add(1);
        let sequence = state.sequence;
        let entry = state.entries.entry(key).or_insert_with(|| Entry {
            bucket,
            last_seen: now,
            sequence,
        });
        entry.last_seen = now;
        entry.sequence = sequence;
        entry.bucket.try_consume(now, 1)
    }

    /// Number of currently retained client buckets (primarily for telemetry
    /// and boundedness checks).
    pub fn len(&self) -> usize {
        match self.state.lock() {
            Ok(state) => state.entries.len(),
            Err(poisoned) => poisoned.into_inner().entries.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Select a client address only from trusted proxy forwarding headers.
pub fn client_ip(peer: IpAddr, headers: &HeaderMap, trusted: &IpNetSet) -> IpAddr {
    if !trusted.contains(peer) {
        return peer;
    }
    if let Some(value) = headers.get(header::FORWARDED).and_then(|v| v.to_str().ok()) {
        if let Some(ip) = value.split(',').next().and_then(parse_forwarded_for) {
            return ip;
        }
    }
    if let Some(value) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        if let Some(ip) = value
            .split(',')
            .next()
            .and_then(|part| part.trim().parse().ok())
        {
            return ip;
        }
    }
    peer
}

fn parse_forwarded_for(value: &str) -> Option<IpAddr> {
    let part = value
        .split(';')
        .find_map(|part| part.trim().strip_prefix("for="))?
        .trim_matches('"');
    if let Some(stripped) = part.strip_prefix('[') {
        return stripped.split(']').next()?.parse().ok();
    }
    part.parse().ok()
}

#[allow(dead_code)]
fn _keep_ip_types_linked(_: Ipv4Addr, _: Ipv6Addr) {}
