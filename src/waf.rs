use crate::control_plane::models::{WafAction, WafConfig, WafMode, WafRule};
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

#[derive(Clone, Debug, Default)]
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

fn builtin_matches(kind: BuiltinKind, value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    match kind {
        BuiltinKind::Sqli => Regex::new(
            r"(?:union\s+select|(?:'|%27)\s*(?:or|and)\s+\d+\s*=\s*\d+|select\s+.+\s+from)",
        )
        .expect("static regex")
        .is_match(&value),
        BuiltinKind::Xss => Regex::new(r"(?:<\s*script|javascript\s*:|on(?:error|load)\s*=)")
            .expect("static regex")
            .is_match(&value),
        BuiltinKind::PathTraversal => Regex::new(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)")
            .expect("static regex")
            .is_match(&value),
        BuiltinKind::CommandInjection => {
            Regex::new(r"(?:;|\||&&)\s*(?:cat|sh|bash|curl|wget|nc)\b")
                .expect("static regex")
                .is_match(&value)
        }
    }
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
