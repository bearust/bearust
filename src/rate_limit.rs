//! Pure, bounded token-bucket rate-limit policy and decision math.
//!
//! The bucket deliberately uses `std::time::Instant`: wall-clock changes must
//! never manufacture tokens or make a client wait indefinitely.

use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    time::{Duration, Instant},
};
use thiserror::Error;

pub const MIN_CAPACITY: u32 = 1;
pub const MAX_CAPACITY: u32 = 1_000_000;
pub const MIN_REFILL_PER_SECOND: f64 = 0.001;
pub const MAX_REFILL_PER_SECOND: f64 = 100_000.0;
pub const MAX_RETRY_AFTER: Duration = Duration::from_secs(3_600);

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum RateLimitAction {
    #[default]
    Monitor,
    Block,
}

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RateLimitKeyScope {
    #[default]
    ProxyHostIp,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimitPolicy {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub action: RateLimitAction,
    #[serde(default = "default_capacity")]
    pub capacity: u32,
    #[serde(default = "default_refill")]
    pub refill_per_second: f64,
    #[serde(default)]
    pub key_scope: RateLimitKeyScope,
}

fn default_capacity() -> u32 {
    60
}
fn default_refill() -> f64 {
    1.0
}

impl Default for RateLimitPolicy {
    fn default() -> Self {
        Self {
            enabled: false,
            action: RateLimitAction::Monitor,
            capacity: default_capacity(),
            refill_per_second: default_refill(),
            key_scope: RateLimitKeyScope::ProxyHostIp,
        }
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum RateLimitConfigError {
    #[error("capacity is outside the permitted bounds")]
    CapacityOutOfBounds,
    #[error("refill_per_second is outside the permitted bounds")]
    RefillOutOfBounds,
}

impl RateLimitPolicy {
    pub fn validate(&self) -> Result<(), RateLimitConfigError> {
        if !(MIN_CAPACITY..=MAX_CAPACITY).contains(&self.capacity) {
            return Err(RateLimitConfigError::CapacityOutOfBounds);
        }
        if !self.refill_per_second.is_finite()
            || !(MIN_REFILL_PER_SECOND..=MAX_REFILL_PER_SECOND).contains(&self.refill_per_second)
        {
            return Err(RateLimitConfigError::RefillOutOfBounds);
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct RateLimitKey {
    pub proxy_host_id: i64,
    pub client_ip: IpAddr,
}

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Decision {
    Allowed {
        remaining_tokens: u32,
    },
    Limited {
        remaining_tokens: u32,
        retry_after: Duration,
    },
}

pub struct TokenBucket {
    capacity: f64,
    refill_per_second: f64,
    tokens: f64,
    last_seen: Option<Instant>,
}

impl TokenBucket {
    pub fn new(capacity: u32, refill_per_second: f64) -> Result<Self, RateLimitConfigError> {
        let policy = RateLimitPolicy {
            capacity,
            refill_per_second,
            ..RateLimitPolicy::default()
        };
        policy.validate()?;
        Ok(Self {
            capacity: capacity as f64,
            refill_per_second,
            tokens: capacity as f64,
            last_seen: None,
        })
    }

    pub fn from_policy(policy: &RateLimitPolicy) -> Result<Self, RateLimitConfigError> {
        policy.validate()?;
        Self::new(policy.capacity, policy.refill_per_second)
    }

    pub fn try_consume(&mut self, now: Instant, cost: u32) -> Decision {
        if let Some(previous) = self.last_seen {
            if let Some(delta) = now.checked_duration_since(previous) {
                self.tokens =
                    (self.tokens + delta.as_secs_f64() * self.refill_per_second).min(self.capacity);
                self.last_seen = Some(now);
            }
        } else {
            self.last_seen = Some(now);
        }

        let cost = cost as f64;
        if cost <= self.tokens {
            self.tokens -= cost;
            return Decision::Allowed {
                remaining_tokens: floor_tokens(self.tokens),
            };
        }

        let missing = cost - self.tokens;
        let seconds = (missing / self.refill_per_second).ceil().max(0.0);
        let retry_after = if seconds >= MAX_RETRY_AFTER.as_secs_f64() {
            MAX_RETRY_AFTER
        } else {
            Duration::from_secs_f64(seconds)
        };
        Decision::Limited {
            remaining_tokens: floor_tokens(self.tokens),
            retry_after,
        }
    }
}

fn floor_tokens(tokens: f64) -> u32 {
    tokens.floor().clamp(0.0, u32::MAX as f64) as u32
}
