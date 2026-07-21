use crate::control_plane::models::{WafAction, WafConfig, WafMode, WafRule};
use regex::Regex;
use serde::Deserialize;

pub const MAX_INSPECTION_BODY_BYTES: usize = 8 * 1024;

#[derive(Clone, Debug, Default)]
pub struct InspectionContext {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WafDecision { Allow, Log, Block }

#[derive(Clone, Debug)]
pub struct Evaluation {
    pub decision: WafDecision,
    pub matched_rule_ids: Vec<i64>,
    pub categories: Vec<String>,
    pub diagnostic: Option<String>,
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
    Builtin { kind: BuiltinKind, field: MatchField },
    Regex { field: MatchField, regex: Regex },
}

#[derive(Clone, Copy, Debug)]
enum BuiltinKind { Sqli, Xss, PathTraversal, CommandInjection }

#[derive(Clone, Copy, Debug)]
enum MatchField { Any, Method, Path, Query, Headers, Body }

#[derive(Deserialize)]
struct MatcherInput {
    field: Option<String>,
    builtin: Option<String>,
    pattern: Option<String>,
}

impl CompiledRule {
    fn compile(rule: &WafRule) -> Result<Self, &'static str> {
        let input: MatcherInput = serde_json::from_str(&rule.matcher_json).map_err(|_| "invalid matcher definition")?;
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
            if pattern.len() > 2048 { return Err("invalid matcher definition"); }
            MatcherDefinition::Regex { field, regex: Regex::new(&format!("(?i:{pattern})")).map_err(|_| "invalid matcher definition")? }
        } else {
            return Err("invalid matcher definition");
        };
        Ok(Self { id: rule.id, category: rule.category.clone(), enabled: rule.enabled, action: rule.action, matcher })
    }
}

pub fn compile_snapshot(config: WafConfig, rules: Vec<WafRule>) -> Result<WafSnapshot, &'static str> {
    let mut compiled = Vec::with_capacity(rules.len());
    for rule in rules { compiled.push(CompiledRule::compile(&rule)?); }
    Ok(WafSnapshot { mode: config.mode, rules: compiled })
}

fn parse_field(value: &str) -> Result<MatchField, &'static str> {
    match value { "any" => Ok(MatchField::Any), "method" => Ok(MatchField::Method), "path" => Ok(MatchField::Path), "query" => Ok(MatchField::Query), "headers" => Ok(MatchField::Headers), "body" => Ok(MatchField::Body), _ => Err("invalid matcher definition") }
}

fn field_values(field: MatchField, context: &InspectionContext) -> Vec<String> {
    match field {
        MatchField::Any => {
            let mut values = vec![context.method.clone(), context.path.clone(), context.query.clone()];
            values.extend(context.headers.iter().flat_map(|(name, value)| [name.clone(), value.clone()]));
            values.push(String::from_utf8_lossy(&context.body[..context.body.len().min(MAX_INSPECTION_BODY_BYTES)]).into_owned());
            values
        }
        MatchField::Method => vec![context.method.clone()],
        MatchField::Path => vec![context.path.clone()],
        MatchField::Query => vec![context.query.clone()],
        MatchField::Headers => context.headers.iter().flat_map(|(name, value)| [name.clone(), value.clone()]).collect(),
        MatchField::Body => vec![String::from_utf8_lossy(&context.body[..context.body.len().min(MAX_INSPECTION_BODY_BYTES)]).into_owned()],
    }
}

fn builtin_matches(kind: BuiltinKind, value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    match kind {
        BuiltinKind::Sqli => Regex::new(r"(?:union\s+select|(?:'|%27)\s*(?:or|and)\s+\d+\s*=\s*\d+|select\s+.+\s+from)").expect("static regex").is_match(&value),
        BuiltinKind::Xss => Regex::new(r"(?:<\s*script|javascript\s*:|on(?:error|load)\s*=)").expect("static regex").is_match(&value),
        BuiltinKind::PathTraversal => Regex::new(r"(?:\.\./|\.\.\\|%2e%2e%2f|%2e%2e/)").expect("static regex").is_match(&value),
        BuiltinKind::CommandInjection => Regex::new(r"(?:;|\||&&)\s*(?:cat|sh|bash|curl|wget|nc)\b").expect("static regex").is_match(&value),
    }
}

pub fn evaluate(snapshot: &WafSnapshot, context: &InspectionContext) -> Evaluation {
    let mut matched_rule_ids = Vec::new();
    let mut categories = Vec::new();
    let mut effective = None;
    for rule in &snapshot.rules {
        if !rule.enabled { continue; }
        let matched = match &rule.matcher {
            MatcherDefinition::Builtin { kind, field } => field_values(*field, context).iter().any(|value| builtin_matches(*kind, value)),
            MatcherDefinition::Regex { field, regex } => field_values(*field, context).iter().any(|value| regex.is_match(value)),
        };
        if !matched { continue; }
        matched_rule_ids.push(rule.id);
        if !categories.contains(&rule.category) { categories.push(rule.category.clone()); }
        let action = match rule.action { WafAction::Inherit => match snapshot.mode { WafMode::MonitorOnly => WafDecision::Log, WafMode::Block => WafDecision::Block }, WafAction::Allow => WafDecision::Allow, WafAction::Log => WafDecision::Log, WafAction::Block => WafDecision::Block };
        effective = Some(match (effective, action) { (Some(WafDecision::Block), _) | (_, WafDecision::Block) => WafDecision::Block, (Some(WafDecision::Log), _) | (_, WafDecision::Log) => WafDecision::Log, _ => WafDecision::Allow });
    }
    Evaluation { decision: effective.unwrap_or(WafDecision::Allow), matched_rule_ids, categories, diagnostic: None }
}
