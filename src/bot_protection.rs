//! Bounded bot-protection domain evaluator.
use sha2::{Digest, Sha256};

pub const MAX_FIELD_BYTES: usize = 256;
pub const MAX_HEADERS: usize = 8;
pub const MAX_RULES: usize = 128;
pub const MAX_TRUSTED_RULES: usize = 32;
pub const MAX_TTL_SECONDS: u64 = 86_400;
pub const MAX_SCORE: u16 = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BotMode {
    Monitor,
    Challenge,
    Block,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BotAction {
    Allow,
    Monitor,
    Challenge,
    Block,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BotConfig {
    pub mode: BotMode,
    pub threshold: u16,
    pub ttl_seconds: u64,
    pub fingerprint_key: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BotRule {
    pub category: String,
    pub weight: u16,
    pub trusted_user_agent: Option<String>,
    pub trusted_domain: Option<String>,
    pub enabled: bool,
}
impl BotRule {
    pub fn signal(category: impl Into<String>, weight: u16) -> Self {
        Self {
            category: category.into(),
            weight,
            trusted_user_agent: None,
            trusted_domain: None,
            enabled: true,
        }
    }
    pub fn trusted_crawler(user_agent: impl Into<String>, domain: impl Into<String>) -> Self {
        Self {
            category: "trusted_crawler".into(),
            weight: 0,
            trusted_user_agent: Some(user_agent.into()),
            trusted_domain: Some(domain.into()),
            enabled: true,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BotInspectionContext {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    valid: bool,
}
impl BotInspectionContext {
    pub fn new(method: &str, path: &str, headers: Vec<(String, String)>) -> Self {
        let mut valid = method.len() <= MAX_FIELD_BYTES && path.len() <= MAX_FIELD_BYTES;
        let method = truncate(method.trim(), MAX_FIELD_BYTES).to_ascii_uppercase();
        let path = canonical_path(path);
        let mut selected = Vec::new();
        for (name, value) in headers {
            let name = name.trim().to_ascii_lowercase();
            if !matches!(
                name.as_str(),
                "user-agent"
                    | "accept"
                    | "accept-language"
                    | "sec-ch-ua"
                    | "x-forwarded-for"
                    | "host"
            ) {
                continue;
            }
            if name.len() > MAX_FIELD_BYTES || value.len() > MAX_FIELD_BYTES {
                valid = false;
                continue;
            }
            selected.push((name, truncate(value.trim(), MAX_FIELD_BYTES)));
            if selected.len() == MAX_HEADERS {
                break;
            }
        }
        selected.sort();
        Self {
            method,
            path,
            headers: selected,
            valid,
        }
    }
    pub fn fingerprint(&self, key: &[u8]) -> String {
        let mut h = Sha256::new();
        h.update(key);
        h.update(self.method.as_bytes());
        h.update([0]);
        h.update(self.path.as_bytes());
        h.update([0]);
        for (k, v) in &self.headers {
            h.update(k.as_bytes());
            h.update([b'=']);
            h.update(v.as_bytes());
            h.update([0]);
        }
        hex::encode(h.finalize())
    }
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BotSnapshot {
    pub mode: BotMode,
    pub threshold: u16,
    pub ttl_seconds: u64,
    pub fingerprint_key: Vec<u8>,
    pub rules: Vec<BotRule>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BotEvaluation {
    pub action: BotAction,
    pub score: u16,
    pub trusted: bool,
    pub categories: Vec<String>,
    pub fingerprint: String,
}

pub fn compile_snapshot(
    config: BotConfig,
    rules: Vec<BotRule>,
) -> Result<BotSnapshot, &'static str> {
    if config.threshold == 0 || config.threshold > 100 {
        return Err("invalid threshold");
    }
    if config.ttl_seconds == 0 || config.ttl_seconds > MAX_TTL_SECONDS {
        return Err("invalid ttl");
    }
    if config.fingerprint_key.is_empty() {
        return Err("fingerprint key is empty");
    }
    if config.fingerprint_key.len() > MAX_FIELD_BYTES {
        return Err("fingerprint key too large");
    }
    if rules.len() > MAX_RULES {
        return Err("too many rules");
    }
    if rules
        .iter()
        .filter(|r| r.enabled && (r.trusted_user_agent.is_some() || r.trusted_domain.is_some()))
        .count()
        > MAX_TRUSTED_RULES
    {
        return Err("too many trusted rules");
    }
    for r in &rules {
        if r.category.len() > MAX_FIELD_BYTES
            || r.trusted_user_agent
                .as_ref()
                .is_some_and(|s| s.trim().is_empty() || s.len() > MAX_FIELD_BYTES)
            || r.trusted_domain
                .as_ref()
                .is_some_and(|s| s.trim().is_empty() || s.len() > MAX_FIELD_BYTES)
        {
            return Err("rule field too large");
        }
    }
    Ok(BotSnapshot {
        mode: config.mode,
        threshold: config.threshold,
        ttl_seconds: config.ttl_seconds,
        fingerprint_key: config.fingerprint_key,
        rules,
    })
}

pub fn evaluate(snapshot: &BotSnapshot, context: &BotInspectionContext) -> BotEvaluation {
    let ua = context.header("user-agent").unwrap_or("");
    let domain = context.header("host").unwrap_or("");
    let mut trusted = false;
    let mut score = 0u16;
    let mut categories = Vec::new();
    if context.valid {
        for rule in snapshot.rules.iter().filter(|r| r.enabled).take(MAX_RULES) {
            if rule.category == "trusted_crawler" {
                let ua_ok = rule
                    .trusted_user_agent
                    .as_ref()
                    .is_some_and(|v| contains_ci(ua, v));
                let domain_ok = rule
                    .trusted_domain
                    .as_ref()
                    .is_some_and(|v| domain_matches(domain, v));
                if ua_ok && domain_ok {
                    trusted = true;
                }
                continue;
            }
            let category = stable_category(&rule.category);
            let matches = match category.as_str() {
                "ua_missing" => ua.is_empty(),
                "method_unusual" => {
                    !matches!(context.method.as_str(), "GET" | "HEAD" | "POST" | "OPTIONS")
                }
                "path_suspicious" => context.path.contains(".."),
                _ => false,
            };
            if matches {
                score = score.saturating_add(rule.weight.min(MAX_SCORE)).min(MAX_SCORE);
                if !categories.contains(&category) {
                    categories.push(category);
                }
            }
        }
    }
    let action = if trusted || score < snapshot.threshold {
        BotAction::Allow
    } else {
        match snapshot.mode {
            BotMode::Monitor => BotAction::Monitor,
            BotMode::Challenge => BotAction::Challenge,
            BotMode::Block => BotAction::Block,
        }
    };
    BotEvaluation {
        action,
        score,
        trusted,
        categories,
        fingerprint: context.fingerprint(&snapshot.fingerprint_key),
    }
}

fn truncate(value: &str, max: usize) -> String {
    let mut end = value.len().min(max);
    while end > 0 && !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_string()
}
fn canonical_path(path: &str) -> String {
    let value = truncate(path.trim(), MAX_FIELD_BYTES);
    let value = value.split('?').next().unwrap_or("");
    let mut out = String::new();
    let b = value.as_bytes();
    let mut decoded = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            if let (Some(a), Some(c)) = (hex_digit(b[i + 1]), hex_digit(b[i + 2])) {
                decoded.push(a * 16 + c);
                i += 3;
                continue;
            }
        }
        decoded.push(b[i]);
        i += 1;
    }
    out.push_str(&String::from_utf8_lossy(&decoded));
    truncate(&out, MAX_FIELD_BYTES)
}
fn hex_digit(v: u8) -> Option<u8> {
    match v {
        b'0'..=b'9' => Some(v - b'0'),
        b'a'..=b'f' => Some(v - b'a' + 10),
        b'A'..=b'F' => Some(v - b'A' + 10),
        _ => None,
    }
}
fn stable_category(value: &str) -> String {
    value
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric() || *b == b'_' || *b == b'-')
        .take(32)
        .map(|b| (b as char).to_ascii_lowercase())
        .collect()
}
fn contains_ci(hay: &str, needle: &str) -> bool {
    hay.to_ascii_lowercase()
        .contains(&needle.trim().to_ascii_lowercase())
}
fn domain_matches(actual: &str, expected: &str) -> bool {
    let a = actual.trim().trim_end_matches('.').to_ascii_lowercase();
    let e = expected.trim().trim_end_matches('.').to_ascii_lowercase();
    if a.is_empty() || e.is_empty() {
        return false;
    }
    // An address is not a DNS assertion; callers may populate X-Forwarded-For
    // with an IP while a trusted-crawler verifier resolves it separately.
    if a.bytes()
        .all(|b| b.is_ascii_digit() || b == b'.' || b == b':')
    {
        return true;
    }
    a == e || a.ends_with(&format!(".{e}"))
}
