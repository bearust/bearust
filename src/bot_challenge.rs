//! Bounded, replay-safe proof-of-work challenges.
use crate::secrets::SecretStore;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

type HmacSha256 = Hmac<Sha256>;
pub const CHALLENGE_TTL_SECONDS: u64 = 300;
pub const MAX_ATTEMPTS: u8 = 5;
pub const DIFFICULTY: u8 = 2;
pub const MAX_TOKEN_BYTES: usize = 512;
pub const MAX_NONCES: usize = 1024;
pub const MAX_FINGERPRINT_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct Challenge {
    pub token: String,
    pub difficulty: u8,
    pub expires_at: u64,
    pub fingerprint_prefix: String,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VerifyError {
    Invalid,
    Expired,
    Replay,
    AttemptsExceeded,
    FingerprintMismatch,
    Capacity,
}
#[derive(Clone, Debug)]
struct NonceState {
    expires_at: u64,
    attempts: u8,
}

#[derive(Clone)]
pub struct ChallengeService {
    key: Arc<Vec<u8>>,
    nonces: Arc<Mutex<HashMap<[u8; 32], NonceState>>>,
}
impl ChallengeService {
    pub fn new(secrets: &SecretStore) -> Result<Self, crate::secrets::SecretError> {
        Ok(Self {
            key: Arc::new(secrets.get_or_create("bot-challenge-signing-key", 32)?),
            nonces: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    pub fn from_key(key: Vec<u8>) -> Result<Self, VerifyError> {
        if key.is_empty() || key.len() > 256 {
            return Err(VerifyError::Invalid);
        }
        Ok(Self {
            key: Arc::new(key),
            nonces: Arc::new(Mutex::new(HashMap::new())),
        })
    }
    pub async fn issue_challenge(
        &self,
        fingerprint: &str,
        now: u64,
    ) -> Result<Challenge, VerifyError> {
        if fingerprint.is_empty() || fingerprint.len() > MAX_FINGERPRINT_BYTES {
            return Err(VerifyError::Invalid);
        }
        let nonce = uuid::Uuid::new_v4().as_bytes().to_vec();
        let expires_at = now.saturating_add(CHALLENGE_TTL_SECONDS);
        let digest: [u8; 32] = Sha256::digest(&nonce).into();
        let mut nonces = self.nonces.lock().await;
        nonces.retain(|_, state| state.expires_at > now);
        if nonces.len() >= MAX_NONCES {
            return Err(VerifyError::Capacity);
        }
        nonces.insert(
            digest,
            NonceState {
                expires_at,
                attempts: 0,
            },
        );
        let prefix = fingerprint.chars().take(16).collect::<String>();
        let payload = format!(
            "1.{}.{}.{}.{}",
            URL_SAFE_NO_PAD.encode(nonce),
            prefix,
            now,
            expires_at
        );
        let token = signed_token(&self.key, payload.as_bytes());
        Ok(Challenge {
            token,
            difficulty: DIFFICULTY,
            expires_at,
            fingerprint_prefix: prefix,
        })
    }
    pub async fn verify_solution(
        &self,
        token: &str,
        fingerprint: &str,
        solution: &str,
        now: u64,
    ) -> Result<(), VerifyError> {
        if token.len() > MAX_TOKEN_BYTES
            || solution.len() > 64
            || fingerprint.is_empty()
            || fingerprint.len() > MAX_FINGERPRINT_BYTES
        {
            return Err(VerifyError::Invalid);
        }
        let (payload, sig) = token.rsplit_once('.').ok_or(VerifyError::Invalid)?;
        let expected = signed_token(&self.key, payload.as_bytes());
        let expected_sig = expected.rsplit_once('.').ok_or(VerifyError::Invalid)?.1;
        if !constant_time_eq(sig.as_bytes(), expected_sig.as_bytes()) {
            return Err(VerifyError::Invalid);
        }
        let mut fields = payload.split('.');
        if fields.next() != Some("1") {
            return Err(VerifyError::Invalid);
        }
        let nonce_b64 = fields.next().ok_or(VerifyError::Invalid)?;
        let prefix = fields.next().ok_or(VerifyError::Invalid)?;
        let issued: u64 = fields
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(VerifyError::Invalid)?;
        let expiry: u64 = fields
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(VerifyError::Invalid)?;
        if fields.next().is_some()
            || issued > now
            || expiry.saturating_sub(issued) > CHALLENGE_TTL_SECONDS
        {
            return Err(VerifyError::Invalid);
        }
        if expiry <= now {
            return Err(VerifyError::Expired);
        }
        if !fingerprint.starts_with(prefix) {
            return Err(VerifyError::FingerprintMismatch);
        }
        let nonce = URL_SAFE_NO_PAD
            .decode(nonce_b64)
            .map_err(|_| VerifyError::Invalid)?;
        if nonce.len() != 16 {
            return Err(VerifyError::Invalid);
        }
        let digest: [u8; 32] = Sha256::digest(&nonce).into();
        let mut states = self.nonces.lock().await;
        let state = states.get_mut(&digest).ok_or(VerifyError::Replay)?;
        if state.expires_at <= now {
            states.remove(&digest);
            return Err(VerifyError::Expired);
        }
        if state.attempts >= MAX_ATTEMPTS {
            return Err(VerifyError::AttemptsExceeded);
        }
        state.attempts += 1;
        let mut pow = Sha256::new();
        pow.update(nonce_b64.as_bytes());
        pow.update(solution.as_bytes());
        if !hex::encode(pow.finalize()).starts_with(&"0".repeat(DIFFICULTY as usize)) {
            return Err(VerifyError::Invalid);
        }
        states.remove(&digest);
        Ok(())
    }

    pub fn issue_clearance(&self, fingerprint: &str, now: u64) -> Result<String, VerifyError> {
        if fingerprint.is_empty() || fingerprint.len() > MAX_FINGERPRINT_BYTES {
            return Err(VerifyError::Invalid);
        }
        let expiry = now.saturating_add(CHALLENGE_TTL_SECONDS);
        let prefix = fingerprint.chars().take(16).collect::<String>();
        Ok(signed_token(
            &self.key,
            format!("c.{}.{}.{}", prefix, now, expiry).as_bytes(),
        ))
    }

    pub fn verify_clearance(
        &self,
        token: &str,
        fingerprint: &str,
        now: u64,
    ) -> Result<(), VerifyError> {
        if token.len() > MAX_TOKEN_BYTES
            || fingerprint.is_empty()
            || fingerprint.len() > MAX_FINGERPRINT_BYTES
        {
            return Err(VerifyError::Invalid);
        }
        let (payload, sig) = token.rsplit_once('.').ok_or(VerifyError::Invalid)?;
        let expected_sig = signed_token(&self.key, payload.as_bytes())
            .rsplit_once('.')
            .ok_or(VerifyError::Invalid)?
            .1
            .to_owned();
        if !constant_time_eq(sig.as_bytes(), expected_sig.as_bytes()) {
            return Err(VerifyError::Invalid);
        }
        let mut fields = payload.split('.');
        if fields.next() != Some("c") {
            return Err(VerifyError::Invalid);
        }
        let prefix = fields.next().ok_or(VerifyError::Invalid)?;
        let issued: u64 = fields
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(VerifyError::Invalid)?;
        let expiry: u64 = fields
            .next()
            .and_then(|v| v.parse().ok())
            .ok_or(VerifyError::Invalid)?;
        if fields.next().is_some()
            || issued > now
            || expiry <= now
            || expiry.saturating_sub(issued) > CHALLENGE_TTL_SECONDS
        {
            return Err(VerifyError::Invalid);
        }
        if fingerprint.starts_with(prefix) {
            Ok(())
        } else {
            Err(VerifyError::FingerprintMismatch)
        }
    }
}

pub async fn issue_challenge(
    service: &ChallengeService,
    fingerprint: &str,
    now: u64,
) -> Result<Challenge, VerifyError> {
    service.issue_challenge(fingerprint, now).await
}
pub async fn verify_solution(
    service: &ChallengeService,
    token: &str,
    fingerprint: &str,
    solution: &str,
    now: u64,
) -> Result<(), VerifyError> {
    service
        .verify_solution(token, fingerprint, solution, now)
        .await
}

pub fn signed_token(key: &[u8], payload: &[u8]) -> String {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts bounded keys");
    mac.update(payload);
    format!(
        "{}.{}",
        String::from_utf8_lossy(payload),
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |v, (x, y)| v | (x ^ y)) == 0
}
pub fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
