use regex::{Captures, Regex};
use serde::Serialize;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    fmt,
    net::IpAddr,
    sync::{
        atomic::{AtomicU8, Ordering},
        Mutex, MutexGuard, OnceLock,
    },
    time::{Duration, Instant},
};

pub const MAX_REDACTION_INPUT_BYTES: usize = 256 * 1024;
pub const MAX_REDACTED_JSON_BYTES: usize = 16 * 1024;

const MAX_DEPTH: usize = 8;
const MAX_OBJECT_FIELDS: usize = 64;
const MAX_ARRAY_ITEMS: usize = 64;
const MAX_STRING_BYTES: usize = 2 * 1024;

const REDACTED: &str = "[REDACTED]";
const REDACTED_IP: &str = "[REDACTED_IP]";
const REDACTED_PRIVATE_KEY: &str = "[REDACTED_PRIVATE_KEY]";

const CIRCUIT_CLOSED: u8 = 0;
const CIRCUIT_OPEN: u8 = 1;
const CIRCUIT_HALF_OPEN: u8 = 2;

/// A sanitized, bounded value suitable for provider input.
///
/// Accepted input is hashed while redaction runs and is never retained.
/// Oversized input is rejected before full serialization and receives a
/// correlation hash of the rejection reason.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct RedactedValue {
    value: Value,
    correlation_hash: String,
}

impl RedactedValue {
    pub fn value(&self) -> &Value {
        &self.value
    }

    pub fn correlation_hash(&self) -> &str {
        &self.correlation_hash
    }

    #[cfg(test)]
    pub(crate) fn for_repository_test(value: Value) -> Self {
        let encoded = serde_json::to_vec(&value).unwrap_or_default();
        Self {
            value,
            correlation_hash: hex::encode(Sha256::digest(&encoded)),
        }
    }
}

impl fmt::Debug for RedactedValue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RedactedValue")
            .field("serialized_bytes", &serialized_len(&self.value))
            .field("correlation_hash", &self.correlation_hash)
            .finish()
    }
}

/// Deterministically reduces arbitrary JSON to the advisor's safe field set.
#[derive(Clone, Debug, Default)]
pub struct Redactor {
    secret_keys: HashSet<String>,
    secret_text_patterns: Vec<Regex>,
}

impl Redactor {
    pub fn with_secret_keys<I, S>(secret_keys: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut secret_keys = secret_keys
            .into_iter()
            .map(|key| normalize_key(key.as_ref()))
            .filter(|key| !key.is_empty())
            .collect::<Vec<_>>();
        secret_keys.sort();
        secret_keys.dedup();
        Self {
            secret_text_patterns: secret_keys
                .iter()
                .map(|key| configured_credential_regex(key))
                .collect(),
            secret_keys: secret_keys.into_iter().collect(),
        }
    }

    pub fn redact(&self, value: &Value) -> RedactedValue {
        if serialized_len_with_limit(value, MAX_REDACTION_INPUT_BYTES).is_none() {
            return RedactedValue {
                value: rejection_value("input_too_large"),
                correlation_hash: rejection_hash("input_too_large"),
            };
        }

        let encoded = serde_json::to_vec(value).unwrap_or_default();
        let correlation_hash = hex::encode(Sha256::digest(&encoded));

        let redacted = self.redact_value(value, 0);
        let value = if serialized_len(&redacted) > MAX_REDACTED_JSON_BYTES {
            rejection_value("output_truncated")
        } else {
            redacted
        };

        RedactedValue {
            value,
            correlation_hash,
        }
    }

    fn redact_value(&self, value: &Value, depth: usize) -> Value {
        if depth >= MAX_DEPTH {
            return Value::String("[TRUNCATED]".to_owned());
        }

        match value {
            Value::Null | Value::Bool(_) | Value::Number(_) => value.clone(),
            Value::String(value) => Value::String(self.redact_text(value)),
            Value::Array(values) => Value::Array(
                values
                    .iter()
                    .take(MAX_ARRAY_ITEMS)
                    .map(|value| self.redact_value(value, depth + 1))
                    .collect(),
            ),
            Value::Object(values) => {
                let mut redacted = Map::new();
                for (key, value) in values.iter().take(MAX_OBJECT_FIELDS) {
                    let normalized = normalize_key(key);
                    if is_request_body_key(&normalized) {
                        continue;
                    }
                    if self.secret_keys.contains(&normalized) || is_sensitive_key(&normalized) {
                        redacted.insert(key.clone(), Value::String(REDACTED.to_owned()));
                    } else if is_safe_key(&normalized) {
                        redacted.insert(key.clone(), self.redact_value(value, depth + 1));
                    }
                }
                Value::Object(redacted)
            }
        }
    }

    fn redact_text(&self, value: &str) -> String {
        let without_keys = private_key_regex()
            .replace_all(value, REDACTED_PRIVATE_KEY)
            .into_owned();
        let without_credentials = redact_credential_matches(credential_text_regex(), &without_keys);
        let without_configured_credentials = self
            .secret_text_patterns
            .iter()
            .fold(without_credentials, |value, pattern| {
                redact_credential_matches(pattern, &value)
            });
        let without_bearer_tokens = bearer_token_regex()
            .replace_all(&without_configured_credentials, "$1 [REDACTED]")
            .into_owned();
        let without_jwts = jwt_regex()
            .replace_all(&without_bearer_tokens, "[REDACTED_TOKEN]")
            .into_owned();
        let without_ipv6 = ipv6_candidate_regex()
            .replace_all(&without_jwts, |captures: &Captures<'_>| {
                let candidate = &captures[0];
                if candidate
                    .parse::<IpAddr>()
                    .is_ok_and(|address| address.is_ipv6())
                {
                    REDACTED_IP.to_owned()
                } else {
                    candidate.to_owned()
                }
            })
            .into_owned();
        let without_ips = ipv4_regex()
            .replace_all(&without_ipv6, REDACTED_IP)
            .into_owned();
        truncate_utf8(&without_ips, MAX_STRING_BYTES)
    }
}

/// Atomic circuit state with a monotonic cooldown timestamp.
pub struct ProviderGuard {
    state: AtomicU8,
    consecutive_failures: AtomicU8,
    failure_threshold: u8,
    cooldown: Duration,
    opened_at: Mutex<Option<Instant>>,
}

impl ProviderGuard {
    pub fn new(failure_threshold: u8, cooldown: Duration) -> Self {
        Self {
            state: AtomicU8::new(CIRCUIT_CLOSED),
            consecutive_failures: AtomicU8::new(0),
            failure_threshold: failure_threshold.max(1),
            cooldown,
            opened_at: Mutex::new(None),
        }
    }

    /// Returns immediately. Once the cooldown expires, exactly one caller is
    /// admitted as the half-open probe.
    pub fn allow_request(&self) -> bool {
        match self.state.load(Ordering::Acquire) {
            CIRCUIT_CLOSED => true,
            CIRCUIT_OPEN => {
                let opened_at = lock_recover(&self.opened_at);
                match self.state.load(Ordering::Acquire) {
                    CIRCUIT_CLOSED => true,
                    CIRCUIT_OPEN => {
                        let cooldown_elapsed = opened_at.as_ref().is_some_and(|opened_at| {
                            Instant::now()
                                .checked_duration_since(*opened_at)
                                .is_some_and(|elapsed| elapsed >= self.cooldown)
                        });
                        cooldown_elapsed
                            && self
                                .state
                                .compare_exchange(
                                    CIRCUIT_OPEN,
                                    CIRCUIT_HALF_OPEN,
                                    Ordering::AcqRel,
                                    Ordering::Acquire,
                                )
                                .is_ok()
                    }
                    CIRCUIT_HALF_OPEN => false,
                    _ => false,
                }
            }
            CIRCUIT_HALF_OPEN => false,
            _ => false,
        }
    }

    pub fn record_success(&self) {
        let mut opened_at = lock_recover(&self.opened_at);
        self.consecutive_failures.store(0, Ordering::Release);
        *opened_at = None;
        self.state.store(CIRCUIT_CLOSED, Ordering::Release);
    }

    pub fn record_failure(&self, now: Instant) {
        if self.state.load(Ordering::Acquire) == CIRCUIT_CLOSED {
            let previous = self
                .consecutive_failures
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |failures| {
                    Some(failures.saturating_add(1))
                })
                .unwrap_or(u8::MAX);
            if previous.saturating_add(1) < self.failure_threshold {
                return;
            }
        }

        let mut opened_at = lock_recover(&self.opened_at);
        self.consecutive_failures
            .store(self.failure_threshold, Ordering::Release);
        if opened_at
            .as_ref()
            .is_none_or(|previous_failure| now > *previous_failure)
        {
            *opened_at = Some(now);
        }
        self.state.store(CIRCUIT_OPEN, Ordering::Release);
    }
}

impl fmt::Debug for ProviderGuard {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderGuard")
            .field("state", &self.state.load(Ordering::Acquire))
            .field(
                "consecutive_failures",
                &self.consecutive_failures.load(Ordering::Acquire),
            )
            .field("failure_threshold", &self.failure_threshold)
            .field("cooldown", &self.cooldown)
            .finish()
    }
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn serialized_len(value: &Value) -> usize {
    serde_json::to_vec(value).map_or(0, |encoded| encoded.len())
}

fn serialized_len_with_limit(value: &Value, limit: usize) -> Option<usize> {
    fn add(total: usize, amount: usize, limit: usize) -> Option<usize> {
        total
            .checked_add(amount)
            .filter(|candidate| *candidate <= limit)
    }

    match value {
        Value::Null => (4 <= limit).then_some(4),
        Value::Bool(true) => (4 <= limit).then_some(4),
        Value::Bool(false) => (5 <= limit).then_some(5),
        Value::Number(number) => {
            let len = number.to_string().len();
            (len <= limit).then_some(len)
        }
        Value::String(value) => escaped_string_len_with_limit(value, limit),
        Value::Array(values) => {
            let mut total = 2;
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    total = add(total, 1, limit)?;
                }
                let remaining = limit.checked_sub(total)?;
                total = add(total, serialized_len_with_limit(value, remaining)?, limit)?;
            }
            Some(total)
        }
        Value::Object(values) => {
            let mut total = 2;
            for (index, (key, value)) in values.iter().enumerate() {
                if index > 0 {
                    total = add(total, 1, limit)?;
                }
                let remaining = limit.checked_sub(total)?;
                total = add(total, escaped_string_len_with_limit(key, remaining)?, limit)?;
                total = add(total, 1, limit)?;
                let remaining = limit.checked_sub(total)?;
                total = add(total, serialized_len_with_limit(value, remaining)?, limit)?;
            }
            Some(total)
        }
    }
}

fn escaped_string_len_with_limit(value: &str, limit: usize) -> Option<usize> {
    let mut total = 2;
    if total > limit {
        return None;
    }
    for character in value.chars() {
        let encoded_bytes = match character {
            '"' | '\\' | '\u{0008}' | '\u{000c}' | '\n' | '\r' | '\t' => 2,
            '\u{0000}'..='\u{001f}' => 6,
            _ => character.len_utf8(),
        };
        total = total
            .checked_add(encoded_bytes)
            .filter(|candidate| *candidate <= limit)?;
    }
    Some(total)
}

fn rejection_hash(status: &str) -> String {
    hex::encode(Sha256::digest(status.as_bytes()))
}

fn rejection_value(status: &str) -> Value {
    let mut value = Map::new();
    value.insert(
        "redaction_status".to_owned(),
        Value::String(status.to_owned()),
    );
    Value::Object(value)
}

fn normalize_key(key: &str) -> String {
    key.trim()
        .to_ascii_lowercase()
        .replace(['-', ' ', '.'], "_")
}

fn is_request_body_key(key: &str) -> bool {
    matches!(
        key,
        "body" | "request_body" | "raw_body" | "response_body" | "payload"
    )
}

fn is_sensitive_key(key: &str) -> bool {
    matches!(
        key,
        "authorization"
            | "proxy_authorization"
            | "cookie"
            | "set_cookie"
            | "password"
            | "passwd"
            | "api_key"
            | "apikey"
            | "access_token"
            | "refresh_token"
            | "token"
            | "secret"
            | "client_secret"
            | "private_key"
            | "llm_api_key"
    ) || key.ends_with("_password")
        || key.ends_with("_token")
        || key.ends_with("_secret")
        || key.ends_with("_api_key")
}

fn is_safe_key(key: &str) -> bool {
    matches!(
        key,
        "workflow"
            | "host_id"
            | "from"
            | "to"
            | "command"
            | "event"
            | "events"
            | "request"
            | "headers"
            | "details"
            | "metadata"
            | "summary"
            | "signals"
            | "method"
            | "path"
            | "route"
            | "status"
            | "category"
            | "score"
            | "severity"
            | "reason"
            | "reason_id"
            | "reason_ids"
            | "count"
            | "timestamp"
            | "duration_ms"
            | "model"
            | "label"
            | "message"
    )
}

fn redact_credential_matches(regex: &Regex, value: &str) -> String {
    regex
        .replace_all(value, |captures: &Captures<'_>| {
            format!("{}{}{}", &captures[1], &captures[2], REDACTED)
        })
        .into_owned()
}

fn configured_credential_regex(key: &str) -> Regex {
    let key = key
        .split('_')
        .map(regex::escape)
        .collect::<Vec<_>>()
        .join(r"[-_. ]*");
    Regex::new(&format!(
        r#"(?i)\b({key})\b(\s*[:=]\s*)(?:(?:bearer|basic)\s+)?(?:"[^"]*"|'[^']*'|[^\s&,;]+)"#
    ))
    .expect("escaped configured credential regex must compile")
}

fn credential_text_regex() -> &'static Regex {
    static CREDENTIAL: OnceLock<Regex> = OnceLock::new();
    CREDENTIAL.get_or_init(|| {
        Regex::new(
            r#"(?i)\b(authorization|proxy[-_. ]*authorization|cookie|set[-_. ]*cookie|password|passwd|api[-_. ]*key|apikey|access[-_. ]*token|refresh[-_. ]*token|token|secret|client[-_. ]*secret)\b(\s*[:=]\s*)(?:(?:bearer|basic)\s+)?(?:"[^"]*"|'[^']*'|[^\s&,;]+)"#,
        )
        .expect("credential regex must compile")
    })
}

fn bearer_token_regex() -> &'static Regex {
    static BEARER: OnceLock<Regex> = OnceLock::new();
    BEARER.get_or_init(|| {
        Regex::new(r"(?i)\b(bearer|basic)\s+[a-z0-9._~+/=-]+")
            .expect("authorization scheme regex must compile")
    })
}

fn jwt_regex() -> &'static Regex {
    static JWT: OnceLock<Regex> = OnceLock::new();
    JWT.get_or_init(|| {
        Regex::new(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")
            .expect("JWT regex must compile")
    })
}

fn private_key_regex() -> &'static Regex {
    static PRIVATE_KEY: OnceLock<Regex> = OnceLock::new();
    PRIVATE_KEY.get_or_init(|| {
        Regex::new(
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
        )
        .expect("private-key regex must compile")
    })
}

fn ipv4_regex() -> &'static Regex {
    static IPV4: OnceLock<Regex> = OnceLock::new();
    IPV4.get_or_init(|| {
        Regex::new(
            r"\b(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}\b",
        )
        .expect("IPv4 regex must compile")
    })
}

fn ipv6_candidate_regex() -> &'static Regex {
    static IPV6: OnceLock<Regex> = OnceLock::new();
    IPV6.get_or_init(|| {
        Regex::new(r"(?i)[0-9a-f:]*:[0-9a-f:]+").expect("IPv6 candidate regex must compile")
    })
}

fn truncate_utf8(value: &str, maximum_bytes: usize) -> String {
    if value.len() <= maximum_bytes {
        return value.to_owned();
    }

    const SUFFIX: &str = "[TRUNCATED]";
    let content_limit = maximum_bytes.saturating_sub(SUFFIX.len());
    let boundary = value
        .char_indices()
        .map(|(index, _)| index)
        .take_while(|index| *index <= content_limit)
        .last()
        .unwrap_or(0);
    format!("{}{SUFFIX}", &value[..boundary])
}
