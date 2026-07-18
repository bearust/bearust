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

#[derive(Clone)]
pub struct Http01Store {
    inner: Arc<Mutex<HashMap<String, (String, Instant)>>>,
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
    pub fn put(&self, token: &str, key_authorization: &str) -> Result<(), Http01Error> {
        if token.is_empty()
            || token.len() > 256
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            || key_authorization.is_empty()
            || key_authorization.len() > 4096
            || key_authorization.bytes().any(|b| b.is_ascii_control())
        {
            return Err(Http01Error::InvalidValue);
        }
        self.inner.lock().expect("challenge lock").insert(
            token.to_owned(),
            (key_authorization.to_owned(), Instant::now() + self.lifetime),
        );
        Ok(())
    }
    pub fn get(&self, token: &str) -> Option<String> {
        if token.is_empty()
            || token.len() > 256
            || !token
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            return None;
        }
        let mut map = self.inner.lock().ok()?;
        let (value, expiry) = map.get(token)?.clone();
        if Instant::now() >= expiry {
            map.remove(token);
            None
        } else {
            Some(value)
        }
    }
    pub fn remove(&self, token: &str) {
        if let Ok(mut map) = self.inner.lock() {
            map.remove(token);
        }
    }
}
