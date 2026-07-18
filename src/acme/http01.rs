use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use thiserror::Error;
#[derive(Debug, Error)]
pub enum Http01Error {
    #[error("invalid HTTP-01 token or key authorization")]
    InvalidValue,
}
type ChallengeKey = (String, String, String);
type ChallengeValue = (String, Instant);
#[derive(Clone)]
pub struct Http01Store {
    inner: Arc<Mutex<HashMap<ChallengeKey, ChallengeValue>>>,
    lifetime: Duration,
}
impl Default for Http01Store {
    fn default() -> Self {
        Self::new(Duration::from_secs(600))
    }
}
impl Http01Store {
    pub fn new(lifetime: Duration) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HashMap::new())),
            lifetime,
        }
    }
    pub fn put(&self, token: &str, value: &str) -> Result<(), Http01Error> {
        self.put_for_order("", "", token, value)
    }
    pub fn put_for_order(
        &self,
        order: &str,
        hostname: &str,
        token: &str,
        value: &str,
    ) -> Result<(), Http01Error> {
        if !valid_token(token)
            || !valid_key_authorization(token, value)
            || order.bytes().any(|b| b.is_ascii_control())
            || hostname.bytes().any(|b| b.is_ascii_control())
        {
            return Err(Http01Error::InvalidValue);
        }
        self.inner.lock().expect("challenge lock").insert(
            (
                order.to_owned(),
                hostname.to_ascii_lowercase(),
                token.to_owned(),
            ),
            (value.to_owned(), Instant::now() + self.lifetime),
        );
        Ok(())
    }
    pub fn get(&self, token: &str) -> Option<String> {
        self.get_for_order("", "", token)
    }
    pub fn get_for_order(&self, order: &str, hostname: &str, token: &str) -> Option<String> {
        if !valid_token(token) {
            return None;
        }
        let mut map = self.inner.lock().ok()?;
        let key = (
            order.to_owned(),
            hostname.to_ascii_lowercase(),
            token.to_owned(),
        );
        let (value, expiry) = map.get(&key)?.clone();
        if Instant::now() >= expiry {
            map.remove(&key);
            None
        } else {
            Some(value)
        }
    }
    pub fn remove(&self, token: &str) {
        self.remove_for_order("", "", token);
    }
    pub fn remove_for_order(&self, order: &str, hostname: &str, token: &str) {
        if let Ok(mut map) = self.inner.lock() {
            map.remove(&(
                order.to_owned(),
                hostname.to_ascii_lowercase(),
                token.to_owned(),
            ));
        }
    }
}
fn valid_token(v: &str) -> bool {
    !v.is_empty()
        && v.len() <= 256
        && v.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
fn valid_key_authorization(token: &str, value: &str) -> bool {
    let Some((prefix, digest)) = value.split_once('.') else {
        return false;
    };
    prefix == token
        && (32..=128).contains(&digest.len())
        && digest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}
/// Returns a challenge response only for the exact ACME HTTP-01 path.
pub fn lookup_http01(path: &str, store: &Http01Store) -> Option<String> {
    let token = path.strip_prefix("/.well-known/acme-challenge/")?;
    if token.is_empty() || token.contains('/') {
        return None;
    }
    store.get(token)
}
pub(crate) struct ChallengeGuard {
    store: Http01Store,
    order: String,
    hostname: String,
    token: String,
}
impl ChallengeGuard {
    pub fn new(store: Http01Store, order: &str, hostname: &str, token: &str) -> Self {
        Self {
            store,
            order: order.to_owned(),
            hostname: hostname.to_owned(),
            token: token.to_owned(),
        }
    }
}
impl Drop for ChallengeGuard {
    fn drop(&mut self) {
        self.store
            .remove_for_order(&self.order, &self.hostname, &self.token);
    }
}
