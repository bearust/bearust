use crate::control_plane::models::{SecLangConfig, WafAction, WafConfig, WafMode, WafRule};
use regex::Regex;
use serde::Deserialize;
use std::sync::LazyLock;

pub const MAX_INSPECTION_BODY_BYTES: usize = 8 * 1024;
pub const MAX_NORMALIZED_FIELD_BYTES: usize = 4 * 1024;
pub const MAX_NORMALIZED_HEADERS: usize = 64;
pub const MAX_NORMALIZED_METADATA_BYTES: usize = 16 * 1024;
const MAX_SEMANTIC_SIGNALS: usize = 8;
const MAX_SEMANTIC_REASON_BYTES: usize = 96;
const SEMANTIC_BLOCK_THRESHOLD: u16 = 8;

#[derive(Clone, Debug, Default, PartialEq)]
pub struct InspectionContext {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct NormalizedContext {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WafDecision {
    Allow,
    Log,
    Block,
}

#[derive(Clone, Debug)]
pub struct Evaluation {
    pub decision: WafDecision,
    pub matched_rule_ids: Vec<i64>,
    pub categories: Vec<String>,
    pub diagnostic: Option<String>,
    pub semantic_score: u16,
    pub severity: Option<String>,
}

/// The only WAF fields safe to place in audit logs or realtime telemetry.
/// Values are already bounded and contain identifiers rather than request
/// material (the evaluator diagnostic is deliberately excluded).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RedactedTelemetry {
    pub category: String,
    pub score: u16,
    pub severity: String,
    pub reason_ids: String,
}

fn telemetry_identifier(value: &str) -> String {
    let mut output = String::with_capacity(value.len().min(32));
    for byte in value.bytes() {
        if output.len() >= 32 {
            break;
        }
        if byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-' {
            output.push(byte.to_ascii_lowercase() as char);
        } else if !output.ends_with('_') {
            output.push('_');
        }
    }
    output.trim_matches('_').to_owned()
}

/// Convert an evaluation into bounded metadata suitable for audit/event
/// serialization.  This intentionally omits `diagnostic`, matched rule ids,
/// field values, headers, and bodies.
pub fn redacted_telemetry(evaluation: &Evaluation) -> RedactedTelemetry {
    let mut identifiers = Vec::new();
    for category in evaluation.categories.iter().take(MAX_SEMANTIC_SIGNALS) {
        let identifier = telemetry_identifier(category);
        if !identifier.is_empty() && !identifiers.contains(&identifier) {
            identifiers.push(identifier);
        }
    }
    let categories = identifiers.join(",");
    RedactedTelemetry {
        category: categories.clone(),
        score: evaluation.semantic_score,
        severity: evaluation.severity.clone().unwrap_or_else(|| "none".into()),
        reason_ids: categories,
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SemanticSignal {
    pub category: String,
    pub weight: u16,
    pub field: String,
    pub reason: String,
}

#[derive(Clone, Debug)]
pub struct WafSnapshot {
    pub mode: WafMode,
    pub rules: Vec<CompiledRule>,
    /// OWASP CRS and custom SecLang rules, when enabled.
    pub seclang: Option<std::sync::Arc<SecLangRuntime>>,
}

/// A compiled SecLang ruleset plus the `tx.` setup variables derived from
/// [`SecLangConfig`] (paranoia level and anomaly threshold).
#[derive(Debug)]
pub struct SecLangRuntime {
    pub config: SecLangConfig,
    ruleset: crate::seclang::RuleSet,
    setup: Vec<(String, String)>,
}

impl SecLangRuntime {
    /// Compile the bundled CRS (when enabled) followed by custom rules.
    /// Returns `None` when neither is configured.
    pub fn compile(config: &SecLangConfig) -> Result<Option<Self>, String> {
        config.validate_bounds().map_err(str::to_owned)?;
        if !config.crs_enabled && config.custom_rules.trim().is_empty() {
            return Ok(None);
        }
        let mut sources = Vec::new();
        if config.crs_enabled {
            sources.extend(
                crate::seclang::crs::CONFIG_FILES
                    .iter()
                    .map(|(name, content)| crate::seclang::Source { name, content }),
            );
        }
        if !config.custom_rules.trim().is_empty() {
            sources.push(crate::seclang::Source {
                name: "custom.conf",
                content: &config.custom_rules,
            });
        }
        let data = crate::seclang::crs::DATA_FILES
            .iter()
            .map(|(name, content)| ((*name).to_owned(), (*content).to_owned()))
            .collect();
        let mut ruleset =
            crate::seclang::RuleSet::compile(&sources, &data).map_err(|error| error.to_string())?;
        ruleset.disable(&config.disabled_rule_ids);
        let level = config.paranoia_level.to_string();
        Ok(Some(Self {
            config: config.clone(),
            ruleset,
            setup: vec![
                ("blocking_paranoia_level".into(), level.clone()),
                ("detection_paranoia_level".into(), level),
                (
                    "inbound_anomaly_score_threshold".into(),
                    config.inbound_threshold.to_string(),
                ),
            ],
        }))
    }

    pub fn rule_count(&self) -> usize {
        self.ruleset.rule_count()
    }

    fn evaluate(&self, context: &InspectionContext) -> crate::seclang::Outcome {
        let uri = if context.query.is_empty() {
            context.path.clone()
        } else {
            format!("{}?{}", context.path, context.query)
        };
        let request = crate::seclang::Request {
            method: context.method.clone(),
            uri,
            protocol: "HTTP/1.1".into(),
            headers: context.headers.clone(),
            body: context.body.clone(),
            remote_addr: String::new(),
        };
        self.ruleset.evaluate(&request, &self.setup)
    }
}

#[derive(Clone, Debug)]
pub struct CompiledRule {
    pub id: i64,
    pub category: String,
    pub enabled: bool,
    pub action: WafAction,
    matcher: MatcherDefinition,
}

#[derive(Clone, Debug)]
enum MatcherDefinition {
    Builtin {
        kind: BuiltinKind,
        field: MatchField,
    },
    Regex {
        field: MatchField,
        regex: Regex,
    },
}

#[derive(Clone, Copy, Debug)]
enum BuiltinKind {
    Sqli,
    Xss,
    PathTraversal,
    CommandInjection,
}

#[derive(Clone, Copy, Debug)]
enum MatchField {
    Any,
    Method,
    Path,
    Query,
    Headers,
    Body,
}

#[derive(Deserialize)]
struct MatcherInput {
    field: Option<String>,
    builtin: Option<String>,
    pattern: Option<String>,
}

impl CompiledRule {
    fn compile(rule: &WafRule) -> Result<Self, &'static str> {
        let input: MatcherInput =
            serde_json::from_str(&rule.matcher_json).map_err(|_| "invalid matcher definition")?;
        let field = parse_field(input.field.as_deref().unwrap_or("any"))?;
        let matcher = if let Some(name) = input.builtin {
            let kind = match name.as_str() {
                "sqli" => BuiltinKind::Sqli,
                "xss" => BuiltinKind::Xss,
                "path_traversal" => BuiltinKind::PathTraversal,
                "command_injection" => BuiltinKind::CommandInjection,
                _ => return Err("invalid matcher definition"),
            };
            MatcherDefinition::Builtin { kind, field }
        } else if let Some(pattern) = input.pattern {
            if pattern.len() > 2048 {
                return Err("invalid matcher definition");
            }
            MatcherDefinition::Regex {
                field,
                regex: Regex::new(&format!("(?i:{pattern})"))
                    .map_err(|_| "invalid matcher definition")?,
            }
        } else {
            return Err("invalid matcher definition");
        };
        Ok(Self {
            id: rule.id,
            category: rule.category.clone(),
            enabled: rule.enabled,
            action: rule.action,
            matcher,
        })
    }
}

pub fn compile_snapshot(
    config: WafConfig,
    rules: Vec<WafRule>,
) -> Result<WafSnapshot, &'static str> {
    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules {
        compiled.push(CompiledRule::compile(&rule)?);
    }
    Ok(WafSnapshot {
        mode: config.mode,
        rules: compiled,
        seclang: None,
    })
}

/// Rule ids for built-in signatures in a route policy. Negative so they never
/// collide with the positive ids a control plane gives custom rules.
fn route_builtin_id(name: &str) -> i64 {
    match name {
        "sqli" => -1,
        "xss" => -2,
        "path_traversal" => -3,
        _ => -4,
    }
}

/// Compiled CRS runtimes shared by every route at the same paranoia level, so
/// many tenants on one node compile the CRS at most once per level.
fn shared_crs(paranoia_level: u8) -> Result<std::sync::Arc<SecLangRuntime>, String> {
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};
    static CACHE: OnceLock<Mutex<HashMap<u8, Arc<SecLangRuntime>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(HashMap::new()));
    let mut cache = cache.lock().map_err(|_| "crs cache poisoned".to_owned())?;
    if let Some(runtime) = cache.get(&paranoia_level) {
        return Ok(Arc::clone(runtime));
    }
    let config = SecLangConfig {
        crs_enabled: true,
        paranoia_level,
        inbound_threshold: ROUTE_CRS_INBOUND_THRESHOLD,
        custom_rules: String::new(),
        disabled_rule_ids: Vec::new(),
        updated_at: String::new(),
    };
    let runtime =
        SecLangRuntime::compile(&config)?.ok_or_else(|| "crs produced no rules".to_owned())?;
    let runtime = Arc::new(runtime);
    cache.insert(paranoia_level, Arc::clone(&runtime));
    Ok(runtime)
}

/// CRS default inbound anomaly threshold, used for every route policy.
pub const ROUTE_CRS_INBOUND_THRESHOLD: u16 = 5;

/// Validate and compile a per-route policy into its own snapshot.
pub fn compile_route_policy(policy: &crate::config::RouteWafPolicy) -> Result<WafSnapshot, String> {
    use crate::config::{
        MAX_ROUTE_WAF_CATEGORY_BYTES, MAX_ROUTE_WAF_PARANOIA, MAX_ROUTE_WAF_RULES,
        ROUTE_WAF_BUILTINS,
    };
    let mut rules = Vec::with_capacity(policy.builtins.len() + policy.rules.len());
    for name in &policy.builtins {
        if !ROUTE_WAF_BUILTINS.contains(&name.as_str()) {
            return Err(format!("unknown built-in signature {name}"));
        }
        let id = route_builtin_id(name);
        if rules.iter().any(|rule: &CompiledRule| rule.id == id) {
            return Err(format!("duplicate built-in signature {name}"));
        }
        rules.push(CompiledRule::compile(&WafRule {
            id,
            name: name.clone(),
            source: "builtin".into(),
            category: name.clone(),
            severity: "high".into(),
            enabled: true,
            action: WafAction::Inherit,
            matcher_json: serde_json::json!({ "builtin": name }).to_string(),
            created_at: String::new(),
            updated_at: String::new(),
        })?);
    }
    if policy.rules.len() > MAX_ROUTE_WAF_RULES {
        return Err(format!("at most {MAX_ROUTE_WAF_RULES} custom rules"));
    }
    for rule in &policy.rules {
        if rule.id < 1 {
            return Err("custom rule ids must be positive".into());
        }
        if rules.iter().any(|existing| existing.id == rule.id) {
            return Err(format!("duplicate custom rule id {}", rule.id));
        }
        let category = rule.category.trim();
        if category.is_empty()
            || category.len() > MAX_ROUTE_WAF_CATEGORY_BYTES
            || category.chars().any(char::is_control)
        {
            return Err(format!(
                "rule {} category must be 1-{MAX_ROUTE_WAF_CATEGORY_BYTES} bytes without control characters",
                rule.id
            ));
        }
        rules.push(
            CompiledRule::compile(&WafRule {
                id: rule.id,
                name: format!("rule-{}", rule.id),
                source: "custom".into(),
                category: category.to_owned(),
                severity: "medium".into(),
                enabled: true,
                action: rule.action,
                matcher_json: serde_json::json!({ "field": rule.field, "pattern": rule.pattern })
                    .to_string(),
                created_at: String::new(),
                updated_at: String::new(),
            })
            .map_err(|_| format!("rule {} has an invalid field or pattern", rule.id))?,
        );
    }
    let seclang = match policy.crs {
        None => None,
        Some(crs) if (1..=MAX_ROUTE_WAF_PARANOIA).contains(&crs.paranoia_level) => {
            Some(shared_crs(crs.paranoia_level)?)
        }
        Some(_) => {
            return Err(format!(
                "crs.paranoia_level must be 1-{MAX_ROUTE_WAF_PARANOIA}"
            ))
        }
    };
    Ok(WafSnapshot {
        mode: policy.mode,
        rules,
        seclang,
    })
}

fn parse_field(value: &str) -> Result<MatchField, &'static str> {
    match value {
        "any" => Ok(MatchField::Any),
        "method" => Ok(MatchField::Method),
        "path" => Ok(MatchField::Path),
        "query" => Ok(MatchField::Query),
        "headers" => Ok(MatchField::Headers),
        "body" => Ok(MatchField::Body),
        _ => Err("invalid matcher definition"),
    }
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn decode_percent_once(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            if let (Some(high), Some(low)) =
                (hex_value(bytes[index + 1]), hex_value(bytes[index + 2]))
            {
                decoded.push((high << 4) | low);
                index += 3;
                continue;
            }
        }
        decoded.push(bytes[index]);
        index += 1;
    }
    // Keep malformed decoded byte sequences literal instead of introducing
    // replacement characters that could alter detector semantics.
    String::from_utf8(decoded).unwrap_or_else(|_| value.to_owned())
}

fn bounded_prefix(value: &str, max_bytes: usize) -> &str {
    let end = value
        .char_indices()
        .take_while(|(index, character)| *index + character.len_utf8() <= max_bytes)
        .map(|(index, character)| index + character.len_utf8())
        .last()
        .unwrap_or(0)
        .min(max_bytes);
    &value[..end]
}

fn normalize_text(value: &str, max_bytes: usize) -> String {
    // Two decode passes handle double-encoded attacks while bounding work.
    let bounded = bounded_prefix(value, max_bytes);
    let decoded = decode_percent_once(&decode_percent_once(bounded));
    let mut normalized = String::with_capacity(decoded.len());
    let mut whitespace = false;
    for character in decoded.chars() {
        if character.is_ascii_whitespace() {
            whitespace = true;
            continue;
        }
        if whitespace {
            normalized.push(' ');
            whitespace = false;
        }
        if character == '\\' {
            normalized.push('/');
        } else {
            normalized.push(character.to_ascii_lowercase());
        }
    }
    normalized
}

fn normalize_context(context: &InspectionContext) -> NormalizedContext {
    let body = &context.body[..context.body.len().min(MAX_INSPECTION_BODY_BYTES)];
    let mut remaining = MAX_NORMALIZED_METADATA_BYTES;
    let mut normalize_metadata = |value: &str| {
        let cap = remaining.min(MAX_NORMALIZED_FIELD_BYTES);
        let normalized = normalize_text(value, cap);
        remaining = remaining.saturating_sub(normalized.len());
        normalized
    };
    NormalizedContext {
        method: normalize_metadata(&context.method),
        path: normalize_metadata(&context.path),
        query: normalize_metadata(&context.query),
        headers: context
            .headers
            .iter()
            .take(MAX_NORMALIZED_HEADERS)
            .map(|(name, value)| (normalize_metadata(name), normalize_metadata(value)))
            .collect(),
        body: normalize_text(&String::from_utf8_lossy(body), MAX_INSPECTION_BODY_BYTES),
    }
}

fn field_values(field: MatchField, context: &NormalizedContext) -> Vec<String> {
    match field {
        MatchField::Any => {
            let mut values = vec![
                context.method.clone(),
                context.path.clone(),
                context.query.clone(),
            ];
            values.extend(
                context
                    .headers
                    .iter()
                    .flat_map(|(name, value)| [name.clone(), value.clone()]),
            );
            values.push(context.body.clone());
            values
        }
        MatchField::Method => vec![context.method.clone()],
        MatchField::Path => vec![context.path.clone()],
        MatchField::Query => vec![context.query.clone()],
        MatchField::Headers => context
            .headers
            .iter()
            .flat_map(|(name, value)| [name.clone(), value.clone()])
            .collect(),
        MatchField::Body => vec![context.body.clone()],
    }
}

// Built-in signatures run on normalized (decoded, lowercased) text.
static BUILTIN_SQLI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(concat!(
        r"(?:union\s+select|select\s+.+\s+from",
        // Tautologies after a closing quote: ' or 1=1, " and 'a'='a.
        r#"|['"]\s*(?:or|and)\s+(?:\d+\s*=\s*\d+|['"][^'"]*['"]\s*=\s*['"])"#,
        // A quote followed by a comment that cuts off the rest of the query.
        r"|'\s*(?:--|#|/\*)",
        // Stacked statements.
        r"|;\s*(?:(?:drop|truncate|alter)\s+(?:table|database)\b|delete\s+from\b|insert\s+into\b",
        r"|update\s+\w+\s+set\b|exec(?:ute)?\s+\w|shutdown\b))",
    ))
    .expect("static regex")
});
static BUILTIN_XSS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:<\s*script|javascript\s*:|on(?:error|load)\s*=)").expect("static regex")
});
static BUILTIN_PATH_TRAVERSAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)").expect("static regex"));
static BUILTIN_COMMAND_INJECTION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:;|\||&&)\s*(?:cat|sh|bash|curl|wget|nc)\b").expect("static regex")
});

fn builtin_matches(kind: BuiltinKind, value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    let regex = match kind {
        BuiltinKind::Sqli => &BUILTIN_SQLI,
        BuiltinKind::Xss => &BUILTIN_XSS,
        BuiltinKind::PathTraversal => &BUILTIN_PATH_TRAVERSAL,
        BuiltinKind::CommandInjection => &BUILTIN_COMMAND_INJECTION,
    };
    regex.is_match(&value)
}

static SEMANTIC_SQLI: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:union\s+select|(?:'|\b)\s*(?:or|and)\s+\d+\s*=\s*\d+|select\s+[^ ]+\s+from)")
        .expect("static semantic regex")
});
static SEMANTIC_XSS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:<\s*(?:script|svg|img)|javascript\s*:|on(?:error|load)\s*=)")
        .expect("static semantic regex")
});
static SEMANTIC_TRAVERSAL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?:\.\./|\.\.\\|%2e%2e%2f)").expect("static semantic regex"));
static SEMANTIC_COMMAND: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?:^|[;|&])\s*(?:cat|sh|bash|curl|wget|nc|python|perl)\b")
        .expect("static semantic regex")
});

fn semantic_signal(category: &str, weight: u16, field: &str, reason: &str) -> SemanticSignal {
    let reason = bounded_prefix(reason, MAX_SEMANTIC_REASON_BYTES).to_owned();
    SemanticSignal {
        category: category.to_owned(),
        weight,
        field: field.to_owned(),
        reason,
    }
}

fn semantic_signals(context: &NormalizedContext) -> Vec<SemanticSignal> {
    let mut values = vec![
        ("method", context.method.as_str()),
        ("path", context.path.as_str()),
        ("query", context.query.as_str()),
    ];
    for (name, value) in &context.headers {
        values.push(("headers", name.as_str()));
        values.push(("headers", value.as_str()));
    }
    values.push(("body", context.body.as_str()));
    let mut signals = Vec::new();
    let detectors: [(&str, u16, &LazyLock<Regex>, &str); 4] = [
        ("sqli", 6, &SEMANTIC_SQLI, "SQL injection indicator"),
        ("xss", 5, &SEMANTIC_XSS, "cross-site scripting indicator"),
        (
            "path_traversal",
            4,
            &SEMANTIC_TRAVERSAL,
            "path traversal indicator",
        ),
        (
            "command_injection",
            6,
            &SEMANTIC_COMMAND,
            "command injection indicator",
        ),
    ];
    for (category, weight, detector, reason) in detectors {
        if let Some((field, _)) = values.iter().find(|(_, value)| detector.is_match(value)) {
            signals.push(semantic_signal(category, weight, field, reason));
        }
    }
    // TRACE and unknown methods are valid in rare deployments but are unusual
    // enough to surface as a low-confidence protocol anomaly.
    if !matches!(
        context.method.as_str(),
        "get" | "post" | "put" | "patch" | "delete" | "head" | "options" | "connect"
    ) {
        signals.push(semantic_signal(
            "protocol_anomaly",
            3,
            "method",
            "uncommon HTTP method",
        ));
    }
    signals.truncate(MAX_SEMANTIC_SIGNALS);
    signals
}

fn severity_for_score(score: u16) -> Option<String> {
    match score {
        0 => None,
        1..=4 => Some("low".into()),
        5..=7 => Some("medium".into()),
        8..=11 => Some("high".into()),
        _ => Some("critical".into()),
    }
}

pub fn evaluate(snapshot: &WafSnapshot, context: &InspectionContext) -> Evaluation {
    let normalized = normalize_context(context);
    let mut matched_rule_ids = Vec::new();
    let mut categories = Vec::new();
    let mut effective = None;
    for rule in &snapshot.rules {
        if !rule.enabled {
            continue;
        }
        let matched = match &rule.matcher {
            MatcherDefinition::Builtin { kind, field } => field_values(*field, &normalized)
                .iter()
                .any(|value| builtin_matches(*kind, value)),
            MatcherDefinition::Regex { field, regex } => field_values(*field, &normalized)
                .iter()
                .any(|value| regex.is_match(value)),
        };
        if !matched {
            continue;
        }
        matched_rule_ids.push(rule.id);
        if !categories.contains(&rule.category) {
            categories.push(rule.category.clone());
        }
        let action = match rule.action {
            WafAction::Inherit => match snapshot.mode {
                WafMode::MonitorOnly => WafDecision::Log,
                WafMode::Block => WafDecision::Block,
            },
            WafAction::Allow => WafDecision::Allow,
            WafAction::Log => WafDecision::Log,
            WafAction::Block => WafDecision::Block,
        };
        effective = Some(match (effective, action) {
            (Some(WafDecision::Block), _) | (_, WafDecision::Block) => WafDecision::Block,
            (Some(WafDecision::Log), _) | (_, WafDecision::Log) => WafDecision::Log,
            _ => WafDecision::Allow,
        });
    }
    if let Some(runtime) = &snapshot.seclang {
        let outcome = runtime.evaluate(context);
        for rule in &outcome.matched {
            matched_rule_ids.push(rule.id);
            for tag in &rule.tags {
                if let Some(category) = tag.strip_prefix("attack-") {
                    let category = category.to_owned();
                    if !categories.contains(&category) {
                        categories.push(category);
                    }
                }
            }
        }
        let action = if outcome.intervention.is_some() && !outcome.detection_only {
            Some(match snapshot.mode {
                WafMode::MonitorOnly => WafDecision::Log,
                WafMode::Block => WafDecision::Block,
            })
        } else if !outcome.matched.is_empty() {
            Some(WafDecision::Log)
        } else {
            None
        };
        if let Some(action) = action {
            effective = Some(match (effective, action) {
                (Some(WafDecision::Block), _) | (_, WafDecision::Block) => WafDecision::Block,
                (Some(WafDecision::Log), _) | (_, WafDecision::Log) => WafDecision::Log,
                _ => WafDecision::Allow,
            });
        }
    }
    let signals = semantic_signals(&normalized);
    let semantic_score = signals
        .iter()
        .fold(0u16, |score, signal| score.saturating_add(signal.weight));
    for signal in &signals {
        if !categories.contains(&signal.category) {
            categories.push(signal.category.clone());
        }
    }
    let semantic_decision = if semantic_score == 0 {
        None
    } else if snapshot.mode == WafMode::Block && semantic_score >= SEMANTIC_BLOCK_THRESHOLD {
        Some(WafDecision::Block)
    } else {
        Some(WafDecision::Log)
    };
    let decision = match (effective.unwrap_or(WafDecision::Allow), semantic_decision) {
        (WafDecision::Block, _) | (_, Some(WafDecision::Block)) => WafDecision::Block,
        (WafDecision::Log, _) | (_, Some(WafDecision::Log)) => WafDecision::Log,
        _ => WafDecision::Allow,
    };
    let diagnostic = if signals.is_empty() {
        None
    } else {
        Some(
            signals
                .iter()
                .map(|signal| format!("{}:{}:{}", signal.category, signal.field, signal.reason))
                .collect::<Vec<_>>()
                .join(","),
        )
    };
    Evaluation {
        decision,
        matched_rule_ids,
        categories,
        diagnostic,
        semantic_score,
        severity: severity_for_score(semantic_score),
    }
}

/// Merges a `waf.detect` plugin's verdict into an existing `Evaluation`.
/// Escalate-only: the combined decision is the more severe of the two
/// (`Block` beats `Log` beats `Allow`), so a plugin verdict can raise
/// severity but can never turn an `Evaluation` that already reached
/// `Block` into anything else. The plugin's category is appended (deduped)
/// and its score is added into `semantic_score`, with `severity`
/// recomputed from the combined score so the two fields stay consistent.
pub fn merge_plugin_verdict(
    mut evaluation: Evaluation,
    verdict: bearust_plugin_sdk::WafDetectVerdict,
) -> Evaluation {
    let verdict_decision = match verdict.decision {
        bearust_plugin_sdk::WafPluginDecision::Allow => WafDecision::Allow,
        bearust_plugin_sdk::WafPluginDecision::Log => WafDecision::Log,
        bearust_plugin_sdk::WafPluginDecision::Block => WafDecision::Block,
    };
    evaluation.decision = match (evaluation.decision, verdict_decision) {
        (WafDecision::Block, _) | (_, WafDecision::Block) => WafDecision::Block,
        (WafDecision::Log, _) | (_, WafDecision::Log) => WafDecision::Log,
        _ => WafDecision::Allow,
    };
    let category = bounded_prefix(&verdict.category, MAX_SEMANTIC_REASON_BYTES).to_owned();
    if !category.is_empty() && !evaluation.categories.contains(&category) {
        evaluation.categories.push(category);
    }
    evaluation.semantic_score = evaluation.semantic_score.saturating_add(verdict.score);
    evaluation.severity = severity_for_score(evaluation.semantic_score);
    evaluation
}

#[cfg(test)]
mod tests {
    use super::*;
    use bearust_plugin_sdk::{WafDetectVerdict, WafPluginDecision};

    fn evaluation(decision: WafDecision) -> Evaluation {
        Evaluation {
            decision,
            matched_rule_ids: Vec::new(),
            categories: Vec::new(),
            diagnostic: None,
            semantic_score: 0,
            severity: None,
        }
    }

    fn verdict(decision: WafPluginDecision) -> WafDetectVerdict {
        WafDetectVerdict {
            decision,
            category: "custom_detector".into(),
            score: 5,
        }
    }

    #[test]
    fn merge_is_most_severe_wins_across_all_nine_combinations() {
        let cases = [
            (
                WafDecision::Allow,
                WafPluginDecision::Allow,
                WafDecision::Allow,
            ),
            (WafDecision::Allow, WafPluginDecision::Log, WafDecision::Log),
            (
                WafDecision::Allow,
                WafPluginDecision::Block,
                WafDecision::Block,
            ),
            (WafDecision::Log, WafPluginDecision::Allow, WafDecision::Log),
            (WafDecision::Log, WafPluginDecision::Log, WafDecision::Log),
            (
                WafDecision::Log,
                WafPluginDecision::Block,
                WafDecision::Block,
            ),
            (
                WafDecision::Block,
                WafPluginDecision::Allow,
                WafDecision::Block,
            ),
            (
                WafDecision::Block,
                WafPluginDecision::Log,
                WafDecision::Block,
            ),
            (
                WafDecision::Block,
                WafPluginDecision::Block,
                WafDecision::Block,
            ),
        ];
        for (existing, plugin, expected) in cases {
            let merged =
                merge_plugin_verdict(evaluation(existing.clone()), verdict(plugin.clone()));
            assert_eq!(
                merged.decision, expected,
                "existing={existing:?} plugin={plugin:?} expected={expected:?}"
            );
        }
    }

    #[test]
    fn merge_can_never_downgrade_an_existing_block() {
        let merged = merge_plugin_verdict(
            evaluation(WafDecision::Block),
            verdict(WafPluginDecision::Allow),
        );
        assert_eq!(merged.decision, WafDecision::Block);
    }

    #[test]
    fn merge_appends_the_plugin_category_and_adds_its_score() {
        let mut base = evaluation(WafDecision::Allow);
        base.categories.push("sqli".into());
        base.semantic_score = 3;
        let merged = merge_plugin_verdict(base, verdict(WafPluginDecision::Log));
        assert_eq!(
            merged.categories,
            vec!["sqli".to_string(), "custom_detector".to_string()]
        );
        assert_eq!(merged.semantic_score, 8);
    }

    #[test]
    fn merge_does_not_duplicate_a_category_the_rule_engine_already_matched() {
        let mut base = evaluation(WafDecision::Allow);
        base.categories.push("custom_detector".into());
        let merged = merge_plugin_verdict(base, verdict(WafPluginDecision::Allow));
        assert_eq!(merged.categories, vec!["custom_detector".to_string()]);
    }

    #[test]
    fn merge_recomputes_severity_from_the_combined_score() {
        let merged = merge_plugin_verdict(
            evaluation(WafDecision::Allow),
            WafDetectVerdict {
                decision: WafPluginDecision::Log,
                category: "custom_detector".into(),
                score: 8,
            },
        );
        assert_eq!(merged.severity.as_deref(), Some("high"));
    }
}

#[cfg(test)]
mod route_policy_tests {
    use super::*;
    use crate::config::{RouteWafCrs, RouteWafPolicy, RouteWafRule};

    fn policy(mode: WafMode) -> RouteWafPolicy {
        RouteWafPolicy {
            mode,
            builtins: vec!["sqli".into()],
            crs: None,
            rules: Vec::new(),
        }
    }

    fn request(query: &str) -> InspectionContext {
        InspectionContext {
            method: "GET".into(),
            path: "/search".into(),
            query: query.into(),
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    #[test]
    fn each_policy_decides_with_its_own_mode() {
        let block = compile_route_policy(&policy(WafMode::Block)).unwrap();
        let monitor = compile_route_policy(&policy(WafMode::MonitorOnly)).unwrap();
        let attack = request("q=1 union select password from users");
        assert_eq!(evaluate(&block, &attack).decision, WafDecision::Block);
        assert_eq!(evaluate(&monitor, &attack).decision, WafDecision::Log);
        assert_eq!(
            evaluate(&block, &request("q=shoes")).decision,
            WafDecision::Allow
        );
    }

    #[test]
    fn builtin_sqli_catches_string_tautologies_and_stacked_queries() {
        let block = compile_route_policy(&policy(WafMode::Block)).unwrap();
        for attack in [
            "id=1%27%20OR%20%271%27%3D%271",
            "user=admin' or 'a'='a",
            "user=x\" or \"1\"=\"1",
            "id=1\" or 1=1",
            "user=admin'--",
            "user=admin' #",
            "id=1;%20DROP%20TABLE%20users--",
            "id=1; delete from users",
            "id=1;insert into users values (1)",
            "id=1; update users set role='admin'",
            "id=1; exec xp_cmdshell 'dir'",
            "id=1; truncate table logs",
        ] {
            assert_eq!(
                evaluate(&block, &request(attack)).decision,
                WafDecision::Block,
                "{attack}"
            );
        }
        for clean in [
            "q=rock 'n' roll",
            "q=it's or isn't",
            "q=drop table tennis",
            "q=a;b",
            "q=select a plan; update later",
            "name=o'brien&page=2",
            "q=tom & jerry; delete key",
        ] {
            assert_eq!(
                evaluate(&block, &request(clean)).decision,
                WafDecision::Allow,
                "{clean}"
            );
        }
    }

    #[test]
    fn custom_rules_match_their_field_and_keep_their_action() {
        let mut p = policy(WafMode::MonitorOnly);
        p.builtins.clear();
        p.rules.push(RouteWafRule {
            id: 7,
            category: "admin".into(),
            field: "path".into(),
            pattern: "^/wp-admin".into(),
            action: WafAction::Block,
        });
        let snapshot = compile_route_policy(&p).unwrap();
        let mut hit = request("");
        hit.path = "/WP-ADMIN/setup.php".into();
        let evaluation = evaluate(&snapshot, &hit);
        assert_eq!(evaluation.decision, WafDecision::Block);
        assert_eq!(evaluation.matched_rule_ids, vec![7]);
    }

    #[test]
    fn invalid_policies_are_rejected() {
        let mut unknown = policy(WafMode::Block);
        unknown.builtins.push("ssrf".into());
        assert!(compile_route_policy(&unknown).is_err());

        let mut duplicate = policy(WafMode::Block);
        duplicate.builtins.push("sqli".into());
        assert!(compile_route_policy(&duplicate).is_err());

        let rule = |id: i64, pattern: &str| RouteWafRule {
            id,
            category: "custom".into(),
            field: "any".into(),
            pattern: pattern.into(),
            action: WafAction::Inherit,
        };
        for rules in [
            vec![rule(0, "x")],
            vec![rule(1, "x"), rule(1, "y")],
            vec![rule(1, "(")],
            vec![rule(1, &"a".repeat(2049))],
            (1..=21).map(|id| rule(id, "x")).collect(),
        ] {
            let mut p = policy(WafMode::Block);
            p.rules = rules;
            assert!(compile_route_policy(&p).is_err());
        }

        let mut bad_field = policy(WafMode::Block);
        bad_field.rules.push(RouteWafRule {
            field: "cookies".into(),
            ..rule(1, "x")
        });
        assert!(compile_route_policy(&bad_field).is_err());

        for level in [0, 3] {
            let mut p = policy(WafMode::Block);
            p.crs = Some(RouteWafCrs {
                paranoia_level: level,
            });
            assert!(compile_route_policy(&p).is_err());
        }
    }

    #[test]
    fn crs_is_compiled_once_per_paranoia_level() {
        let mut p = policy(WafMode::Block);
        p.crs = Some(RouteWafCrs { paranoia_level: 1 });
        let first = compile_route_policy(&p).unwrap();
        let second = compile_route_policy(&p).unwrap();
        assert!(std::sync::Arc::ptr_eq(
            first.seclang.as_ref().unwrap(),
            second.seclang.as_ref().unwrap()
        ));
        let attack = request("id=1' or 1=1--");
        assert_eq!(evaluate(&first, &attack).decision, WafDecision::Block);
    }
}
