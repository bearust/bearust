//! Bounded, process-local runtime state for rate limiting.
use crate::rate_limit::{Decision, RateLimitKey, RateLimitPolicy, TokenBucket};
use http::{header, HeaderMap};
use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Mutex,
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
}

impl RateLimiterStore {
    pub fn new(max_entries: usize, idle_ttl: Duration) -> Self {
        Self {
            max_entries,
            idle_ttl,
            state: Mutex::new(State {
                entries: HashMap::new(),
                sequence: 0,
            }),
        }
    }

    pub fn evaluate(&self, key: RateLimitKey, policy: &RateLimitPolicy, now: Instant) -> Decision {
        if !policy.enabled || self.max_entries == 0 || policy.validate().is_err() {
            return Decision::Allowed {
                remaining_tokens: policy.capacity,
            };
        }
        let mut state = self.state.lock().expect("rate limiter store lock poisoned");
        state
            .entries
            .retain(|_, entry| now.saturating_duration_since(entry.last_seen) <= self.idle_ttl);
        if !state.entries.contains_key(&key) && state.entries.len() >= self.max_entries {
            if let Some(oldest) = state
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.sequence)
                .map(|(key, _)| key.clone())
            {
                state.entries.remove(&oldest);
            }
        }
        state.sequence = state.sequence.wrapping_add(1);
        let sequence = state.sequence;
        let entry = state.entries.entry(key).or_insert_with(|| Entry {
            bucket: TokenBucket::from_policy(policy).expect("validated rate-limit policy"),
            last_seen: now,
            sequence,
        });
        entry.last_seen = now;
        entry.sequence = sequence;
        entry.bucket.try_consume(now, 1)
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.state
            .lock()
            .expect("rate limiter store lock poisoned")
            .entries
            .len()
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
