//! Runtime security policy snapshots shared by the HTTP/1-2 and HTTP/3 data
//! planes. Policies are deliberately bounded and fail closed only for an
//! explicitly configured block rule; malformed records are ignored at reload
//! time and surfaced by the control-plane validation endpoint.

use crate::control_plane::repository::{self, DbPool};
use arc_swap::ArcSwap;
use base64::Engine as _;
use std::{collections::HashMap, net::IpAddr, sync::Arc};

pub const MAX_IP_RULES: usize = 2_048;
pub const MAX_HOST_AUTH_RULES: usize = 4_096;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum IpSecurityAction {
    Monitor,
    Block,
    Allow,
}

#[derive(Clone, Debug)]
pub struct IpSecurityRule {
    pub id: i64,
    pub cidr: String,
    pub action: IpSecurityAction,
    pub score: i32,
    pub country_code: Option<String>,
    pub enabled: bool,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct IpSecurityDecision {
    pub blocked: bool,
    pub score: i32,
    pub rule_id: Option<i64>,
    pub country_code: Option<String>,
}

#[derive(Clone, Debug)]
struct CompiledIpRule {
    id: i64,
    network: IpNetwork,
    action: IpSecurityAction,
    score: i32,
    country_code: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct IpSecuritySnapshot {
    rules: Vec<CompiledIpRule>,
}

pub struct IpSecurityStore {
    current: ArcSwap<IpSecuritySnapshot>,
}

impl IpSecurityStore {
    pub async fn load(db: &DbPool) -> Result<Self, String> {
        let store = Self {
            current: ArcSwap::from_pointee(IpSecuritySnapshot::default()),
        };
        store.reload(db).await?;
        Ok(store)
    }

    pub async fn reload(&self, db: &DbPool) -> Result<(), String> {
        let rules = repository::list_ip_security_rules(db)
            .await
            .map_err(|_| "unable to load IP security rules")?;
        let mut compiled = Vec::with_capacity(rules.len().min(MAX_IP_RULES));
        for rule in rules
            .into_iter()
            .filter(|rule| rule.enabled)
            .take(MAX_IP_RULES)
        {
            let Some(network) = IpNetwork::parse(&rule.cidr) else {
                continue;
            };
            compiled.push(CompiledIpRule {
                id: rule.id,
                network,
                action: match rule.action {
                    crate::control_plane::models::IpSecurityAction::Monitor => {
                        IpSecurityAction::Monitor
                    }
                    crate::control_plane::models::IpSecurityAction::Block => {
                        IpSecurityAction::Block
                    }
                    crate::control_plane::models::IpSecurityAction::Allow => {
                        IpSecurityAction::Allow
                    }
                },
                score: rule.score,
                country_code: rule.country_code,
            });
        }
        self.current
            .store(Arc::new(IpSecuritySnapshot { rules: compiled }));
        Ok(())
    }

    pub fn evaluate(&self, ip: IpAddr) -> IpSecurityDecision {
        let snapshot = self.current.load();
        let mut best: Option<&CompiledIpRule> = None;
        for rule in &snapshot.rules {
            if rule.network.contains(ip)
                && best.is_none_or(|current| rule.network.prefix > current.network.prefix)
            {
                best = Some(rule);
            }
        }
        let Some(rule) = best else {
            return IpSecurityDecision::default();
        };
        IpSecurityDecision {
            blocked: rule.action == IpSecurityAction::Block,
            score: rule.score,
            rule_id: Some(rule.id),
            country_code: rule.country_code.clone(),
        }
    }

    pub fn snapshot(&self) -> Arc<IpSecuritySnapshot> {
        self.current.load_full()
    }
}

pub fn valid_cidr(value: &str) -> bool {
    IpNetwork::parse(value).is_some()
}

#[derive(Clone, Debug)]
pub struct HostAuthConfig {
    pub host_id: i64,
    pub host: String,
    pub enabled: bool,
    pub realm: String,
    pub username: String,
    pub password_hash: String,
}

#[derive(Clone, Debug, Default)]
pub struct HostAuthSnapshot {
    hosts: HashMap<String, HostAuthConfig>,
}

pub struct HostAuthStore {
    current: ArcSwap<HostAuthSnapshot>,
}

impl HostAuthStore {
    pub async fn load(db: &DbPool) -> Result<Self, String> {
        let store = Self {
            current: ArcSwap::from_pointee(HostAuthSnapshot::default()),
        };
        store.reload(db).await?;
        Ok(store)
    }

    pub async fn reload(&self, db: &DbPool) -> Result<(), String> {
        let configs = repository::list_host_auth_configs(db)
            .await
            .map_err(|_| "unable to load host authentication policies")?;
        let hosts = configs
            .into_iter()
            .filter(|config| config.enabled && !config.username.is_empty())
            .take(MAX_HOST_AUTH_RULES)
            .map(|config| {
                let key = config.host.to_ascii_lowercase();
                let value = HostAuthConfig {
                    host_id: config.host_id,
                    host: config.host,
                    enabled: config.enabled,
                    realm: config.realm,
                    username: config.username,
                    password_hash: config.password_hash,
                };
                (key, value)
            })
            .collect();
        self.current.store(Arc::new(HostAuthSnapshot { hosts }));
        Ok(())
    }

    pub fn protected(&self, host: &str) -> bool {
        self.current
            .load()
            .hosts
            .contains_key(&host.to_ascii_lowercase())
    }

    pub fn authorized(&self, host: &str, authorization: Option<&str>) -> bool {
        let snapshot = self.current.load();
        let Some(config) = snapshot.hosts.get(&host.to_ascii_lowercase()) else {
            return true;
        };
        let Some(value) = authorization.and_then(parse_basic_authorization) else {
            return false;
        };
        value.0 == config.username
            && crate::control_plane::auth::verify_password(&value.1, &config.password_hash)
    }

    pub fn realm(&self, host: &str) -> Option<String> {
        self.current
            .load()
            .hosts
            .get(&host.to_ascii_lowercase())
            .map(|config| config.realm.clone())
    }
}

fn parse_basic_authorization(value: &str) -> Option<(String, String)> {
    let encoded = value
        .strip_prefix("Basic ")
        .or_else(|| value.strip_prefix("basic "))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .ok()?;
    let pair = String::from_utf8(decoded).ok()?;
    let (username, password) = pair.split_once(':')?;
    Some((username.to_owned(), password.to_owned()))
}

#[derive(Clone, Copy, Debug)]
struct IpNetwork {
    address: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = value.trim().split_once('/')?;
        let address = address.parse().ok()?;
        let prefix = prefix.parse().ok()?;
        let valid = match address {
            IpAddr::V4(_) => prefix <= 32,
            IpAddr::V6(_) => prefix <= 128,
        };
        valid.then_some(Self { address, prefix })
    }

    fn contains(self, ip: IpAddr) -> bool {
        match (self.address, ip) {
            (IpAddr::V4(network), IpAddr::V4(value)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - self.prefix)
                };
                u32::from(network) & mask == u32::from(value) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(value)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - self.prefix)
                };
                u128::from(network) & mask == u128::from(value) & mask
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn longest_ip_rule_is_selected() {
        let store = IpSecurityStore {
            current: ArcSwap::from_pointee(IpSecuritySnapshot {
                rules: vec![
                    CompiledIpRule {
                        id: 1,
                        network: IpNetwork::parse("198.51.100.0/24").unwrap(),
                        action: IpSecurityAction::Monitor,
                        score: 10,
                        country_code: None,
                    },
                    CompiledIpRule {
                        id: 2,
                        network: IpNetwork::parse("198.51.100.20/32").unwrap(),
                        action: IpSecurityAction::Block,
                        score: 90,
                        country_code: None,
                    },
                ],
            }),
        };
        let decision = store.evaluate("198.51.100.20".parse().unwrap());
        assert_eq!(decision.rule_id, Some(2));
        assert!(decision.blocked);
    }

    #[test]
    fn basic_authorization_is_bounded_and_case_insensitive() {
        let value = base64::engine::general_purpose::STANDARD.encode("user:secret");
        assert_eq!(
            parse_basic_authorization(&format!("basic {value}")),
            Some(("user".into(), "secret".into()))
        );
    }
}
