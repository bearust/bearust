//! A SecLang (ModSecurity/Coraza rule language) engine for request-phase
//! inspection, sufficient to run the OWASP Core Rule Set.
//!
//! Supported: `SecRule`, `SecAction`, `SecMarker`, `SecDefaultAction`;
//! chains; `setvar` with macro expansion; `skip`/`skipAfter`; `capture`;
//! `multiMatch`; `ctl:` rule/target removal, `ruleEngine`, and
//! `requestBodyProcessor`; the CRS operator and transformation sets (see
//! [`operator`] and [`transform`]); URL-encoded, multipart, JSON, and XML
//! request bodies. Phases 1 and 2 run; response phases are ignored because
//! Bearust inspects requests only. Persistent collections (`IP`, `GLOBAL`,
//! `SESSION`) are empty. Engine limits are explicit rather than silent: an
//! unsupported operator, transformation, or action fails rule loading.

pub mod crs;
pub mod operator;
pub mod parser;
pub mod transform;

use operator::Operator;
use parser::{Directive, Selector, VariableSpec};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use transform::Transform;

/// Values longer than this are truncated before matching, bounding regex
/// work per value.
const MAX_VALUE_BYTES: usize = 64 * 1024;
/// Hard ceiling on rules in one ruleset.
const MAX_RULES: usize = 10_000;

#[derive(Debug, Error)]
pub enum SecLangError {
    #[error("line {line}: {message}")]
    Parse { line: usize, message: String },
    #[error("rule {rule_id}: {message}")]
    Rule { rule_id: i64, message: String },
    #[error("@{operator}: {message}")]
    Operator { operator: String, message: String },
    #[error("ruleset exceeds {MAX_RULES} rules")]
    TooManyRules,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disruptive {
    Pass,
    Block,
    Deny,
    Drop,
    Allow(AllowScope),
    Redirect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowScope {
    Phase,
    Request,
    All,
}

#[derive(Debug, Clone)]
enum SetVar {
    Set(String, String),
    Add(String, String),
    Sub(String, String),
    Delete(String),
}

#[derive(Debug, Clone)]
enum Ctl {
    RuleRemoveById(Vec<(i64, i64)>),
    RuleRemoveByTag(String),
    RuleRemoveTargetById(Vec<(i64, i64)>, VariableSpec),
    RuleRemoveTargetByTag(String, VariableSpec),
    RuleEngine(String),
    RequestBodyProcessor(String),
    Ignored,
}

#[derive(Debug, Default)]
struct Actions {
    id: Option<i64>,
    phase: Option<u8>,
    disruptive: Option<Disruptive>,
    status: Option<u16>,
    log: Option<bool>,
    transforms: Vec<Transform>,
    reset_transforms: bool,
    multi_match: bool,
    capture: bool,
    chain: bool,
    setvars: Vec<SetVar>,
    ctls: Vec<Ctl>,
    skip: usize,
    skip_after: Option<String>,
    msg: Option<String>,
    tags: Vec<String>,
    severity: Option<String>,
}

fn parse_actions(text: Option<&str>) -> Result<Actions, String> {
    let mut actions = Actions::default();
    let Some(text) = text else { return Ok(actions) };
    for (name, value) in parser::actions(text)? {
        let value_str = value.clone().unwrap_or_default();
        match name.as_str() {
            "id" => actions.id = Some(value_str.parse().map_err(|_| "invalid id")?),
            "phase" => {
                actions.phase = Some(match value_str.as_str() {
                    "request" => 2,
                    "response" => 4,
                    "logging" => 5,
                    number => number.parse().map_err(|_| "invalid phase")?,
                })
            }
            "pass" => actions.disruptive = Some(Disruptive::Pass),
            "block" => actions.disruptive = Some(Disruptive::Block),
            "deny" => actions.disruptive = Some(Disruptive::Deny),
            "drop" => actions.disruptive = Some(Disruptive::Drop),
            "redirect" => actions.disruptive = Some(Disruptive::Redirect),
            "allow" => {
                actions.disruptive = Some(Disruptive::Allow(match value_str.as_str() {
                    "phase" => AllowScope::Phase,
                    "request" => AllowScope::Request,
                    _ => AllowScope::All,
                }))
            }
            "status" => actions.status = value_str.parse().ok(),
            "log" => actions.log = Some(true),
            "nolog" => actions.log = Some(false),
            "t" => match Transform::parse(&value_str)? {
                Some(transform) => actions.transforms.push(transform),
                None => {
                    actions.transforms.clear();
                    actions.reset_transforms = true;
                }
            },
            "multimatch" => actions.multi_match = true,
            "capture" => actions.capture = true,
            "chain" => actions.chain = true,
            "setvar" => actions.setvars.push(parse_setvar(&value_str)?),
            "ctl" => actions.ctls.push(parse_ctl(&value_str)?),
            "skip" => actions.skip = value_str.parse().map_err(|_| "invalid skip")?,
            "skipafter" => actions.skip_after = Some(value_str),
            "msg" => actions.msg = value,
            "tag" => actions.tags.push(value_str),
            "severity" => actions.severity = value,
            // Metadata and logging/persistence actions with no effect on a
            // request decision.
            "auditlog" | "noauditlog" | "ver" | "rev" | "maturity" | "accuracy" | "logdata"
            | "expirevar" | "initcol" | "setenv" | "setuid" | "setsid" | "sanitisematched"
            | "sanitizematched" | "sanitisearg" | "sanitizearg" | "append" | "prepend"
            | "deprecatevar" | "exec" | "xmlns" => {}
            other => return Err(format!("unsupported action {other}")),
        }
    }
    Ok(actions)
}

fn parse_setvar(value: &str) -> Result<SetVar, String> {
    let value = value.trim();
    if let Some(name) = value.strip_prefix('!') {
        return Ok(SetVar::Delete(tx_key(name)?));
    }
    let Some((name, rhs)) = value.split_once('=') else {
        return Ok(SetVar::Set(tx_key(value)?, "1".into()));
    };
    let key = tx_key(name)?;
    Ok(if let Some(n) = rhs.strip_prefix('+') {
        SetVar::Add(key, n.to_owned())
    } else if let Some(n) = rhs.strip_prefix('-') {
        SetVar::Sub(key, n.to_owned())
    } else {
        SetVar::Set(key, rhs.to_owned())
    })
}

/// Only the transaction collection is supported; persistent collections
/// are accepted and discarded by keying them outside `tx.`.
fn tx_key(name: &str) -> Result<String, String> {
    let (collection, key) = name
        .trim()
        .split_once('.')
        .ok_or_else(|| format!("invalid setvar target {name}"))?;
    Ok(format!("{}.{}", collection.to_ascii_lowercase(), key))
}

fn id_ranges(text: &str) -> Result<Vec<(i64, i64)>, String> {
    text.split([' ', ','])
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (lo, hi) = part.split_once('-').unwrap_or((part, part));
            Ok((
                lo.trim().parse().map_err(|_| format!("bad id {part}"))?,
                hi.trim().parse().map_err(|_| format!("bad id {part}"))?,
            ))
        })
        .collect()
}

fn parse_ctl(value: &str) -> Result<Ctl, String> {
    let (name, arg) = value.split_once('=').unwrap_or((value, ""));
    let target = |arg: &str| -> Result<(String, VariableSpec), String> {
        let (selector, var) = arg.split_once(';').ok_or("ctl target needs ';'")?;
        let mut vars = parser::variables(var)?;
        Ok((
            selector.to_owned(),
            vars.pop().ok_or("ctl target needs a variable")?,
        ))
    };
    Ok(match name.trim().to_ascii_lowercase().as_str() {
        "ruleremovebyid" => Ctl::RuleRemoveById(id_ranges(arg)?),
        "ruleremovebytag" => Ctl::RuleRemoveByTag(arg.to_owned()),
        "ruleremovetargetbyid" => {
            let (ids, var) = target(arg)?;
            Ctl::RuleRemoveTargetById(id_ranges(&ids)?, var)
        }
        "ruleremovetargetbytag" => {
            let (tag, var) = target(arg)?;
            Ctl::RuleRemoveTargetByTag(tag, var)
        }
        "ruleengine" => Ctl::RuleEngine(arg.to_ascii_lowercase()),
        "requestbodyprocessor" => Ctl::RequestBodyProcessor(arg.to_ascii_uppercase()),
        "auditengine"
        | "auditlogparts"
        | "forcerequestbodyvariable"
        | "requestbodyaccess"
        | "requestbodylimit"
        | "responsebodyaccess"
        | "debugloglevel"
        | "hashengine" => Ctl::Ignored,
        other => return Err(format!("unsupported ctl:{other}")),
    })
}

#[derive(Debug)]
struct Target {
    spec: VariableSpec,
    regex: Option<regex::Regex>,
    /// Collection-cache keys for phases 1 and 2, built once at compile time.
    cache_keys: [String; 2],
}

fn compile_target(spec: VariableSpec) -> Result<Target, String> {
    let regex = match &spec.selector {
        Selector::Regex(pattern) => Some(
            regex::RegexBuilder::new(pattern)
                .case_insensitive(true)
                .build()
                .map_err(|error| format!("bad selector regex: {error}"))?,
        ),
        _ => None,
    };
    let base = format!("{}|{:?}", spec.name, spec.selector);
    Ok(Target {
        cache_keys: [format!("{base}|1"), format!("{base}|2")],
        spec,
        regex,
    })
}

#[derive(Debug)]
struct Rule {
    id: i64,
    phase: u8,
    targets: Vec<Target>,
    exclusions: Vec<Target>,
    operator: Option<Operator>,
    actions: Actions,
    chained: Option<Box<Rule>>,
}

#[derive(Debug)]
enum Entry {
    Rule(Box<Rule>),
    Marker(String),
}

/// A compiled ruleset ready to evaluate requests.
#[derive(Debug)]
pub struct RuleSet {
    entries: Vec<Entry>,
    defaults: HashMap<u8, Actions>,
    rule_count: usize,
}

/// One named configuration file in load order.
pub struct Source<'a> {
    pub name: &'a str,
    pub content: &'a str,
}

impl RuleSet {
    /// Compile configuration files (in order) plus `@pmFromFile` data files
    /// keyed by file name.
    pub fn compile(
        sources: &[Source<'_>],
        data_files: &HashMap<String, String>,
    ) -> Result<Self, SecLangError> {
        let mut entries = Vec::new();
        let mut defaults: HashMap<u8, Actions> = HashMap::new();
        let mut pending_chain: Option<Box<Rule>> = None;
        let mut rule_count = 0;
        for source in sources {
            for directive in parser::directives(source.content)? {
                match directive {
                    Directive::Rule {
                        variables,
                        operator,
                        actions,
                        line,
                    } => {
                        let rule = compile_rule(
                            Some(&variables),
                            Some(&operator),
                            actions.as_deref(),
                            line,
                            data_files,
                        )
                        .map_err(|message| SecLangError::Parse {
                            line,
                            message: format!("{}: {message}", source.name),
                        })?;
                        rule_count += 1;
                        if rule_count > MAX_RULES {
                            return Err(SecLangError::TooManyRules);
                        }
                        attach(&mut entries, &mut pending_chain, rule, &defaults)?;
                    }
                    Directive::Action { actions, line } => {
                        let rule = compile_rule(None, None, Some(&actions), line, data_files)
                            .map_err(|message| SecLangError::Parse {
                                line,
                                message: format!("{}: {message}", source.name),
                            })?;
                        rule_count += 1;
                        attach(&mut entries, &mut pending_chain, rule, &defaults)?;
                    }
                    Directive::Marker(name) => entries.push(Entry::Marker(name)),
                    Directive::DefaultAction(text) => {
                        let actions =
                            parse_actions(Some(&text)).map_err(|message| SecLangError::Parse {
                                line: 0,
                                message: format!("{}: {message}", source.name),
                            })?;
                        defaults.insert(actions.phase.unwrap_or(2), actions);
                    }
                    Directive::Ignored(_) => {}
                }
            }
        }
        if let Some(rule) = pending_chain {
            return Err(SecLangError::Rule {
                rule_id: rule.id,
                message: "chain is not terminated".into(),
            });
        }
        Ok(Self {
            entries,
            defaults,
            rule_count,
        })
    }

    pub fn rule_count(&self) -> usize {
        self.rule_count
    }

    /// Remove rules by id, as a permanent `ctl:ruleRemoveById`.
    pub fn disable(&mut self, ids: &[i64]) {
        if ids.is_empty() {
            return;
        }
        let before = self.entries.len();
        self.entries
            .retain(|entry| !matches!(entry, Entry::Rule(rule) if ids.contains(&rule.id)));
        self.rule_count = self.rule_count.saturating_sub(before - self.entries.len());
    }
}

fn compile_rule(
    variables: Option<&str>,
    operator: Option<&str>,
    actions: Option<&str>,
    line: usize,
    data_files: &HashMap<String, String>,
) -> Result<Rule, String> {
    let actions = parse_actions(actions)?;
    let mut targets = Vec::new();
    let mut exclusions = Vec::new();
    if let Some(variables) = variables {
        for spec in parser::variables(variables)? {
            if spec.exclude {
                exclusions.push(compile_target(spec)?);
            } else {
                targets.push(compile_target(spec)?);
            }
        }
    }
    let operator = operator
        .map(|raw| Operator::parse(raw, data_files))
        .transpose()
        .map_err(|error| error.to_string())?;
    Ok(Rule {
        id: actions.id.unwrap_or(-(line as i64)),
        phase: actions.phase.unwrap_or(2),
        targets,
        exclusions,
        operator,
        actions,
        chained: None,
    })
}

/// Append a rule, threading chain links onto their starter. Chain links
/// inherit the starter's phase.
fn attach(
    entries: &mut Vec<Entry>,
    pending: &mut Option<Box<Rule>>,
    mut rule: Rule,
    defaults: &HashMap<u8, Actions>,
) -> Result<(), SecLangError> {
    match pending.take() {
        None => {
            if rule.actions.id.is_none() {
                return Err(SecLangError::Rule {
                    rule_id: rule.id,
                    message: "rule has no id".into(),
                });
            }
            if !rule.actions.reset_transforms {
                if let Some(default) = defaults.get(&rule.phase) {
                    let mut transforms = default.transforms.clone();
                    transforms.append(&mut rule.actions.transforms);
                    rule.actions.transforms = transforms;
                }
            }
            if rule.actions.chain {
                *pending = Some(Box::new(rule));
            } else {
                entries.push(Entry::Rule(Box::new(rule)));
            }
        }
        Some(mut starter) => {
            rule.phase = starter.phase;
            rule.id = starter.id;
            let continues = rule.actions.chain;
            let mut link = &mut starter.chained;
            while let Some(next) = link {
                link = &mut next.chained;
            }
            *link = Some(Box::new(rule));
            if continues {
                *pending = Some(starter);
            } else {
                entries.push(Entry::Rule(starter));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Transactions
// ---------------------------------------------------------------------------

/// The request as seen by the engine. Header names keep their case.
#[derive(Clone, Debug, Default)]
pub struct Request {
    pub method: String,
    /// Path and query exactly as received, e.g. `/a/b.php?x=1`.
    pub uri: String,
    pub protocol: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub remote_addr: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchedRule {
    pub id: i64,
    pub msg: Option<String>,
    pub tags: Vec<String>,
    pub severity: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Intervention {
    pub rule_id: i64,
    pub status: u16,
    pub disruptive: Disruptive,
}

#[derive(Debug, Default)]
pub struct Outcome {
    /// Rules that matched and log (as in the audit log's rule list).
    pub matched: Vec<MatchedRule>,
    pub intervention: Option<Intervention>,
    /// `tx.blocking_inbound_anomaly_score` / `tx.anomaly_score`, when set.
    pub anomaly_score: i64,
    /// `ctl:ruleEngine=DetectionOnly` or `Off` was applied.
    pub detection_only: bool,
}

type Values = Vec<(String, Vec<u8>)>;

struct Transaction<'r> {
    request: &'r Request,
    path: String,
    query: String,
    args_get: Values,
    args_post: Values,
    files: Values,
    part_headers: Values,
    headers: Values,
    cookies: Values,
    body_processor: Option<String>,
    body_parsed: bool,
    xml_text: Option<Vec<u8>>,
    xml_attributes: Vec<Vec<u8>>,
    tx: HashMap<String, Vec<u8>>,
    matched_var: (String, Vec<u8>),
    matched_vars: Values,
    removed_ids: Vec<(i64, i64)>,
    removed_tags: HashSet<String>,
    removed_targets: Vec<(RemovedBy, VariableSpec)>,
    engine_off: bool,
    detection_only: bool,
    outcome: Outcome,
    unique_id: String,
    /// Request-derived collections are fixed within a phase, so each is
    /// built once per (variable, selector, phase).
    collection_cache: std::cell::RefCell<HashMap<String, std::rc::Rc<Values>>>,
    /// Transformation pipelines repeat across CRS rules (`t:urlDecodeUni`,
    /// `t:htmlEntityDecode`, ...); results are cached by (pipeline, input).
    transform_cache: HashMap<u64, Vec<TransformEntry>>,
}

fn tx_lookup_key(key: &str) -> String {
    let mut out = String::with_capacity(key.len() + 3);
    out.push_str("tx.");
    out.extend(key.chars().map(|c| c.to_ascii_lowercase()));
    out
}

/// `(pipeline, input, output)` in the transform cache.
type TransformEntry = (Vec<Transform>, Vec<u8>, std::rc::Rc<Vec<u8>>);

/// FNV-1a: the transform cache hashes every inspected value, and SipHash's
/// DoS resistance is unnecessary because buckets compare full keys.
struct Fnv1a(u64);

impl Default for Fnv1a {
    fn default() -> Self {
        Self(0xcbf2_9ce4_8422_2325)
    }
}

impl std::hash::Hasher for Fnv1a {
    fn write(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.0 = (self.0 ^ u64::from(*byte)).wrapping_mul(0x0100_0000_01b3);
        }
    }
    fn finish(&self) -> u64 {
        self.0
    }
}

/// Collections whose content can change during a phase (setvar, matches,
/// ctl) and must not be cached.
fn volatile(name: &str) -> bool {
    matches!(
        name,
        "TX" | "MATCHED_VAR"
            | "MATCHED_VAR_NAME"
            | "MATCHED_VARS"
            | "MATCHED_VARS_NAMES"
            | "REQBODY_PROCESSOR"
            | "REQBODY_ERROR"
            | "REQBODY_PROCESSOR_ERROR"
    )
}

enum RemovedBy {
    Ids(Vec<(i64, i64)>),
    Tag(String),
}

fn decode_component(raw: &str) -> Vec<u8> {
    transform::Transform::UrlDecodeUni.apply(raw.as_bytes())
}

fn parse_urlencoded(text: &str) -> Values {
    text.split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
            (
                String::from_utf8_lossy(&decode_component(name)).into_owned(),
                decode_component(value),
            )
        })
        .collect()
}

fn flatten_json(prefix: &str, value: &serde_json::Value, out: &mut Values) {
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                flatten_json(&format!("{prefix}.{key}"), value, out);
            }
        }
        serde_json::Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                flatten_json(&format!("{prefix}.{index}"), value, out);
            }
        }
        serde_json::Value::String(text) => out.push((prefix.to_owned(), text.as_bytes().to_vec())),
        serde_json::Value::Null => out.push((prefix.to_owned(), Vec::new())),
        other => out.push((prefix.to_owned(), other.to_string().into_bytes())),
    }
}

/// `key=value` parameters of a Content-Disposition line; quoted values may
/// contain `;` and backslash-escaped quotes.
fn disposition_params(line: &str) -> Vec<(String, String)> {
    let mut params = Vec::new();
    let mut chars = line.chars().skip_while(|c| *c != ';').peekable();
    while chars.next().is_some() {
        let key: String = chars
            .by_ref()
            .take_while(|c| *c != '=')
            .collect::<String>()
            .trim()
            .to_ascii_lowercase();
        while chars.peek().is_some_and(|c| *c == ' ') {
            chars.next();
        }
        let mut value = String::new();
        if chars.peek() == Some(&'"') {
            chars.next();
            while let Some(c) = chars.next() {
                match c {
                    '\\' if matches!(chars.peek(), Some('"' | '\\')) => {
                        value.push(chars.next().unwrap_or('\\'));
                    }
                    '"' => break,
                    other => value.push(other),
                }
            }
            while chars.peek().is_some_and(|c| *c != ';') {
                chars.next();
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c == ';' {
                    break;
                }
                value.push(c);
                chars.next();
            }
            value = value.trim().to_owned();
        }
        if !key.is_empty() {
            params.push((key, value));
        }
    }
    params
}

/// Minimal multipart parser: fields become `ARGS_POST`, file parts become
/// `FILES` (name -> filename), and every part header line is kept as
/// `MULTIPART_PART_HEADERS` (name -> line).
fn parse_multipart(body: &[u8], boundary: &str) -> (Values, Values, Values) {
    let mut args = Vec::new();
    let mut files = Vec::new();
    let mut part_headers = Vec::new();
    let delimiter = format!("--{boundary}");
    let text = String::from_utf8_lossy(body);
    for part in text.split(delimiter.as_str()).skip(1) {
        if part.starts_with("--") {
            break;
        }
        let part = part.trim_start_matches("\r\n").trim_start_matches('\n');
        let (head, content) = part
            .split_once("\r\n\r\n")
            .or_else(|| part.split_once("\n\n"))
            .unwrap_or((part, ""));
        let content = content
            .strip_suffix("\r\n")
            .or_else(|| content.strip_suffix('\n'))
            .unwrap_or(content);
        let mut name = None;
        let mut filename = None;
        for line in head.lines() {
            if !line.to_ascii_lowercase().starts_with("content-disposition") {
                continue;
            }
            for (key, value) in disposition_params(line) {
                match key.as_str() {
                    "name" => name = Some(value),
                    "filename" => filename = Some(value),
                    _ => {}
                }
            }
        }
        let name = name.unwrap_or_default();
        for line in head.lines().filter(|line| !line.trim().is_empty()) {
            part_headers.push((name.clone(), line.as_bytes().to_vec()));
        }
        match filename {
            Some(filename) => files.push((name, filename.into_bytes())),
            None => args.push((name, content.as_bytes().to_vec())),
        }
    }
    (args, files, part_headers)
}

/// Split an XML body into its text content (`XML:/*`) and attribute values
/// (`XML://@*`). A small scanner, not a validating parser.
fn scan_xml(body: &[u8]) -> (Vec<u8>, Vec<Vec<u8>>) {
    let mut text = Vec::with_capacity(body.len());
    let mut attributes = Vec::new();
    let mut i = 0;
    while i < body.len() {
        if body[i] != b'<' {
            text.push(body[i]);
            i += 1;
            continue;
        }
        let end = body[i..]
            .iter()
            .position(|b| *b == b'>')
            .map_or(body.len(), |p| i + p);
        let tag = &body[i + 1..end];
        if !matches!(tag.first(), Some(b'?' | b'!' | b'/')) {
            let mut j = 0;
            while j < tag.len() {
                if tag[j] == b'=' {
                    let mut k = j + 1;
                    while k < tag.len() && tag[k].is_ascii_whitespace() {
                        k += 1;
                    }
                    if let Some(&quote) = tag.get(k).filter(|q| **q == b'"' || **q == b'\'') {
                        let start = k + 1;
                        let len = tag[start..]
                            .iter()
                            .position(|b| *b == quote)
                            .unwrap_or(tag.len() - start);
                        attributes.push(tag[start..start + len].to_vec());
                        j = start + len + 1;
                        continue;
                    }
                }
                j += 1;
            }
        }
        i = end + 1;
    }
    (text, attributes)
}

impl<'r> Transaction<'r> {
    fn new(request: &'r Request) -> Self {
        let (path, query) = request
            .uri
            .split_once('?')
            .map_or((request.uri.clone(), String::new()), |(p, q)| {
                (p.to_owned(), q.to_owned())
            });
        let cookies = request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("cookie"))
            .flat_map(|(_, value)| value.split(';'))
            .filter_map(|pair| {
                let pair = pair.trim();
                (!pair.is_empty()).then(|| {
                    let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
                    (name.to_owned(), value.as_bytes().to_vec())
                })
            })
            .collect();
        Self {
            request,
            args_get: parse_urlencoded(&query),
            path,
            query,
            args_post: Vec::new(),
            files: Vec::new(),
            part_headers: Vec::new(),
            headers: request
                .headers
                .iter()
                .map(|(k, v)| (k.clone(), v.as_bytes().to_vec()))
                .collect(),
            cookies,
            body_processor: None,
            body_parsed: false,
            xml_text: None,
            xml_attributes: Vec::new(),
            tx: HashMap::new(),
            matched_var: (String::new(), Vec::new()),
            matched_vars: Vec::new(),
            removed_ids: Vec::new(),
            removed_tags: HashSet::new(),
            removed_targets: Vec::new(),
            engine_off: false,
            detection_only: false,
            outcome: Outcome::default(),
            unique_id: format!("{:016x}", rand::random::<u64>()),
            collection_cache: std::cell::RefCell::new(HashMap::new()),
            transform_cache: HashMap::new(),
        }
    }

    fn header(&self, name: &str) -> Option<&str> {
        self.request
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Process the body before phase 2, honoring `ctl:requestBodyProcessor`.
    fn parse_body(&mut self) {
        if self.body_parsed {
            return;
        }
        self.body_parsed = true;
        let content_type = self
            .header("content-type")
            .unwrap_or("")
            .to_ascii_lowercase();
        let processor = self.body_processor.clone().unwrap_or_else(|| {
            if content_type.starts_with("application/x-www-form-urlencoded") {
                "URLENCODED".into()
            } else if content_type.starts_with("multipart/form-data") {
                "MULTIPART".into()
            } else if content_type.contains("json") {
                "JSON".into()
            } else if content_type.contains("xml") {
                "XML".into()
            } else {
                String::new()
            }
        });
        let body = &self.request.body;
        match processor.as_str() {
            "URLENCODED" => {
                self.args_post = parse_urlencoded(&String::from_utf8_lossy(body));
            }
            "MULTIPART" => {
                if let Some(boundary) = content_type
                    .split(';')
                    .find_map(|part| part.trim().strip_prefix("boundary="))
                {
                    // The boundary keeps its original case.
                    let original = self.header("content-type").unwrap_or("");
                    let start = original.to_ascii_lowercase().find("boundary=").unwrap_or(0) + 9;
                    let boundary = original
                        .get(start..start + boundary.len())
                        .unwrap_or(boundary)
                        .trim_matches('"')
                        .to_owned();
                    let (args, files, part_headers) = parse_multipart(body, &boundary);
                    self.args_post = args;
                    self.files = files;
                    self.part_headers = part_headers;
                }
            }
            "JSON" => {
                if let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) {
                    let mut out = Vec::new();
                    flatten_json("json", &value, &mut out);
                    self.args_post = out;
                } else {
                    self.tx.insert("reqbody_error".into(), b"1".to_vec());
                }
            }
            "XML" => {
                let (text, attributes) = scan_xml(body);
                self.xml_text = Some(text);
                self.xml_attributes = attributes;
            }
            _ => {}
        }
        self.body_processor = Some(processor);
    }

    fn removed(&self, rule: &Rule) -> bool {
        self.removed_ids
            .iter()
            .any(|(lo, hi)| (*lo..=*hi).contains(&rule.id))
            || rule
                .actions
                .tags
                .iter()
                .any(|tag| self.removed_tags.contains(tag))
    }

    fn excluded_by_ctl(&self, rule: &Rule, name: &str, key: &str) -> bool {
        self.removed_targets.iter().any(|(by, spec)| {
            let applies = match by {
                RemovedBy::Ids(ranges) => {
                    ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(&rule.id))
                }
                RemovedBy::Tag(tag) => rule.actions.tags.iter().any(|t| t == tag),
            };
            applies
                && spec.name == name
                && match &spec.selector {
                    Selector::None => true,
                    Selector::Key(k) => k.eq_ignore_ascii_case(key),
                    Selector::Regex(pattern) => regex::RegexBuilder::new(pattern)
                        .case_insensitive(true)
                        .build()
                        .is_ok_and(|re| re.is_match(key)),
                }
        })
    }

    fn single(&self, name: &str) -> Option<Vec<u8>> {
        let r = self.request;
        Some(match name {
            "REQUEST_URI" | "REQUEST_URI_RAW" => r.uri.as_bytes().to_vec(),
            // ModSecurity exposes the URL-decoded path.
            "REQUEST_FILENAME" => transform::Transform::UrlDecode.apply(self.path.as_bytes()),
            "REQUEST_BASENAME" => transform::Transform::UrlDecode
                .apply(self.path.rsplit('/').next().unwrap_or("").as_bytes()),
            "REQUEST_LINE" => format!("{} {} {}", r.method, r.uri, r.protocol).into_bytes(),
            "REQUEST_METHOD" => r.method.as_bytes().to_vec(),
            "REQUEST_PROTOCOL" => r.protocol.as_bytes().to_vec(),
            "QUERY_STRING" => self.query.as_bytes().to_vec(),
            "REQUEST_BODY" => {
                if self.body_processor.as_deref() == Some("URLENCODED")
                    || self.body_processor.as_deref() == Some("")
                {
                    r.body.clone()
                } else {
                    return None;
                }
            }
            "REQUEST_BODY_LENGTH" => r.body.len().to_string().into_bytes(),
            "FULL_REQUEST" => {
                let mut full = format!("{} {} {}\r\n", r.method, r.uri, r.protocol);
                for (k, v) in &r.headers {
                    full.push_str(&format!("{k}: {v}\r\n"));
                }
                full.push_str("\r\n");
                let mut bytes = full.into_bytes();
                bytes.extend_from_slice(&r.body);
                bytes
            }
            "FULL_REQUEST_LENGTH" => (r.uri.len()
                + r.body.len()
                + r.headers
                    .iter()
                    .map(|(k, v)| k.len() + v.len() + 4)
                    .sum::<usize>())
            .to_string()
            .into_bytes(),
            "REMOTE_ADDR" | "REMOTE_HOST" => r.remote_addr.as_bytes().to_vec(),
            "SERVER_NAME" => self
                .header("host")
                .unwrap_or("")
                .split(':')
                .next()
                .unwrap_or("")
                .as_bytes()
                .to_vec(),
            "UNIQUE_ID" => self.unique_id.as_bytes().to_vec(),
            "REQBODY_PROCESSOR" => self.body_processor.clone().unwrap_or_default().into_bytes(),
            "REQBODY_ERROR" | "REQBODY_PROCESSOR_ERROR" => self
                .tx
                .get("reqbody_error")
                .cloned()
                .unwrap_or_else(|| b"0".to_vec()),
            "ARGS_COMBINED_SIZE" => self
                .args_get
                .iter()
                .chain(&self.args_post)
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
                .to_string()
                .into_bytes(),
            "FILES_COMBINED_SIZE" => b"0".to_vec(),
            "MATCHED_VAR" => self.matched_var.1.clone(),
            "MATCHED_VAR_NAME" => self.matched_var.0.as_bytes().to_vec(),
            "MULTIPART_STRICT_ERROR"
            | "MULTIPART_UNMATCHED_BOUNDARY"
            | "MULTIPART_BOUNDARY_QUOTED"
            | "MULTIPART_BOUNDARY_WHITESPACE"
            | "MULTIPART_DATA_BEFORE"
            | "MULTIPART_DATA_AFTER"
            | "MULTIPART_HEADER_FOLDING"
            | "MULTIPART_LF_LINE"
            | "MULTIPART_MISSING_SEMICOLON"
            | "MULTIPART_INVALID_QUOTING"
            | "MULTIPART_INVALID_PART"
            | "MULTIPART_INVALID_HEADER_FOLDING"
            | "MULTIPART_FILE_LIMIT_EXCEEDED"
            | "INBOUND_DATA_ERROR"
            | "OUTBOUND_DATA_ERROR"
            | "URLENCODED_ERROR"
            | "DURATION"
            | "HIGHEST_SEVERITY" => b"0".to_vec(),
            _ => return None,
        })
    }

    /// Collect `(name, value)` pairs for one variable reference.
    fn collect(&self, target: &Target, phase: u8) -> std::rc::Rc<Values> {
        let key = &target.cache_keys[usize::from(phase >= 2)];
        if key.is_empty() || volatile(&target.spec.name) {
            return std::rc::Rc::new(self.collect_uncached(target, phase));
        }
        if let Some(values) = self.collection_cache.borrow().get(key.as_str()) {
            return values.clone();
        }
        let values = std::rc::Rc::new(self.collect_uncached(target, phase));
        self.collection_cache
            .borrow_mut()
            .insert(key.clone(), values.clone());
        values
    }

    fn collect_uncached(&self, target: &Target, phase: u8) -> Values {
        let spec = &target.spec;
        let body_ready = phase >= 2;
        let keyed = |pairs: &Values, label: &str| -> Values {
            pairs
                .iter()
                .filter(|(key, _)| match &spec.selector {
                    Selector::None => true,
                    Selector::Key(k) => k.eq_ignore_ascii_case(key),
                    Selector::Regex(_) => target.regex.as_ref().is_some_and(|re| re.is_match(key)),
                })
                .map(|(key, value)| (format!("{label}:{key}"), value.clone()))
                .collect()
        };
        let names = |pairs: &Values, label: &str| -> Values {
            keyed(pairs, label)
                .into_iter()
                .map(|(name, _)| {
                    let key = name
                        .split_once(':')
                        .map(|(_, k)| k)
                        .unwrap_or("")
                        .to_owned();
                    (name, key.into_bytes())
                })
                .collect()
        };
        let empty = Vec::new();
        let post = if body_ready { &self.args_post } else { &empty };
        let files = if body_ready { &self.files } else { &empty };
        match spec.name.as_str() {
            "ARGS" => {
                let mut all = keyed(&self.args_get, "ARGS");
                all.extend(keyed(post, "ARGS"));
                all
            }
            "ARGS_GET" => keyed(&self.args_get, "ARGS_GET"),
            "ARGS_POST" => keyed(post, "ARGS_POST"),
            "ARGS_NAMES" => {
                let mut all = names(&self.args_get, "ARGS_NAMES");
                all.extend(names(post, "ARGS_NAMES"));
                all
            }
            "ARGS_GET_NAMES" => names(&self.args_get, "ARGS_GET_NAMES"),
            "ARGS_POST_NAMES" => names(post, "ARGS_POST_NAMES"),
            "REQUEST_HEADERS" => keyed(&self.headers, "REQUEST_HEADERS"),
            "REQUEST_HEADERS_NAMES" => names(&self.headers, "REQUEST_HEADERS_NAMES"),
            "REQUEST_COOKIES" => keyed(&self.cookies, "REQUEST_COOKIES"),
            "REQUEST_COOKIES_NAMES" => names(&self.cookies, "REQUEST_COOKIES_NAMES"),
            "FILES" | "MULTIPART_FILENAME" => keyed(files, &spec.name),
            "FILES_NAMES" | "MULTIPART_NAME" => names(files, &spec.name),
            "MULTIPART_PART_HEADERS" if body_ready => {
                keyed(&self.part_headers, "MULTIPART_PART_HEADERS")
            }
            "XML" => match (&self.xml_text, body_ready) {
                (Some(text), true) => {
                    let attributes_only =
                        matches!(&spec.selector, Selector::Key(path) if path.contains('@'));
                    if attributes_only {
                        self.xml_attributes
                            .iter()
                            .map(|value| ("XML".to_owned(), value.clone()))
                            .collect()
                    } else {
                        vec![("XML".into(), text.clone())]
                    }
                }
                _ => Vec::new(),
            },
            // Direct lookups: the TX map is large and referenced constantly.
            "TX" => match &spec.selector {
                Selector::Key(key) => self
                    .tx
                    .get(&tx_lookup_key(key))
                    .map(|value| vec![(format!("TX:{key}"), value.clone())])
                    .unwrap_or_default(),
                _ => self
                    .tx
                    .iter()
                    .filter_map(|(k, v)| {
                        let key = k.strip_prefix("tx.")?;
                        let selected = match &spec.selector {
                            Selector::Regex(_) => {
                                target.regex.as_ref().is_some_and(|re| re.is_match(key))
                            }
                            _ => true,
                        };
                        selected.then(|| (format!("TX:{key}"), v.clone()))
                    })
                    .collect(),
            },
            "MATCHED_VARS" => self.matched_vars.clone(),
            "MATCHED_VARS_NAMES" => self
                .matched_vars
                .iter()
                .map(|(name, _)| (name.clone(), name.as_bytes().to_vec()))
                .collect(),
            "IP"
            | "GLOBAL"
            | "SESSION"
            | "USER"
            | "RESOURCE"
            | "ENV"
            | "GEO"
            | "RULE"
            | "RESPONSE_HEADERS"
            | "RESPONSE_HEADERS_NAMES"
            | "RESPONSE_BODY"
            | "RESPONSE_STATUS"
            | "RESPONSE_PROTOCOL"
            | "RESPONSE_CONTENT_TYPE"
            | "RESPONSE_CONTENT_LENGTH"
            | "MULTIPART_PART_HEADERS"
            | "FILES_SIZES"
            | "FILES_TMPNAMES"
            | "FILES_TMP_CONTENT"
            | "STATUS_LINE"
            | "WEBSERVER_ERROR_LOG"
            | "AUTH_TYPE"
            | "REMOTE_USER" => Vec::new(),
            "REQUEST_BODY" if !body_ready => Vec::new(),
            name => self
                .single(name)
                .map(|value| vec![(name.to_owned(), value)])
                .unwrap_or_default(),
        }
    }

    /// References to the values a rule inspects, after exclusions. Values
    /// stay in the shared (cached) collections; only counts are allocated.
    fn values_for(&self, rule: &Rule, phase: u8) -> Vec<(std::rc::Rc<Values>, usize)> {
        let mut out = Vec::new();
        for target in &rule.targets {
            let values = self.collect(target, phase);
            let kept = (0..values.len()).filter(|&index| {
                let name = &values[index].0;
                let key = name.split_once(':').map_or("", |(_, k)| k);
                let excluded = rule.exclusions.iter().any(|ex| {
                    ex.spec.name == target.spec.name
                        && match &ex.spec.selector {
                            Selector::None => true,
                            Selector::Key(k) => k.eq_ignore_ascii_case(key),
                            Selector::Regex(_) => {
                                ex.regex.as_ref().is_some_and(|re| re.is_match(key))
                            }
                        }
                });
                !excluded
                    && (self.removed_targets.is_empty()
                        || !self.excluded_by_ctl(rule, &target.spec.name, key))
            });
            if target.spec.count {
                let count = kept.count();
                out.push((
                    std::rc::Rc::new(vec![(
                        target.spec.name.clone(),
                        count.to_string().into_bytes(),
                    )]),
                    0,
                ));
            } else {
                let kept: Vec<usize> = kept.collect();
                out.extend(kept.into_iter().map(|index| (values.clone(), index)));
            }
        }
        out
    }

    /// Expand `%{collection.key}` macros.
    fn expand(&self, text: &str, rule: &Rule) -> String {
        if !text.contains("%{") {
            return text.to_owned();
        }
        let mut out = String::with_capacity(text.len());
        let mut rest = text;
        while let Some(start) = rest.find("%{") {
            out.push_str(&rest[..start]);
            let after = &rest[start + 2..];
            let Some(end) = after.find('}') else {
                out.push_str(&rest[start..]);
                return out;
            };
            out.push_str(&self.lookup(&after[..end], rule));
            rest = &after[end + 1..];
        }
        out.push_str(rest);
        out
    }

    fn lookup(&self, reference: &str, rule: &Rule) -> String {
        let (collection, key) = reference.split_once('.').unwrap_or((reference, ""));
        let collection = collection.to_ascii_uppercase();
        let value = match collection.as_str() {
            "TX" => self
                .tx
                .get(&format!("tx.{}", key.to_ascii_lowercase()))
                .cloned(),
            "RULE" => match key.to_ascii_lowercase().as_str() {
                "id" => Some(rule.id.to_string().into_bytes()),
                "msg" => rule.actions.msg.clone().map(String::into_bytes),
                "severity" => rule.actions.severity.clone().map(String::into_bytes),
                _ => None,
            },
            _ => {
                let selector = if key.is_empty() {
                    Selector::None
                } else {
                    Selector::Key(key.to_owned())
                };
                let target = Target {
                    spec: VariableSpec {
                        name: collection,
                        selector,
                        exclude: false,
                        count: false,
                    },
                    regex: None,
                    cache_keys: [String::new(), String::new()],
                };
                self.collect(&target, 2).first().map(|(_, v)| v.clone())
            }
        };
        value
            .map(|v| String::from_utf8_lossy(&v).into_owned())
            .unwrap_or_default()
    }

    fn tx_number(&self, key: &str) -> i64 {
        self.tx
            .get(key)
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|v| v.trim().parse().ok())
            .unwrap_or(0)
    }

    fn apply_setvar(&mut self, setvar: &SetVar, rule: &Rule) {
        let resolve = |tx: &Self, key: &str| tx.expand(key, rule).to_ascii_lowercase();
        match setvar {
            SetVar::Set(key, value) => {
                let key = resolve(self, key);
                let value = self.expand(value, rule);
                self.tx.insert(key, value.into_bytes());
            }
            SetVar::Add(key, value) | SetVar::Sub(key, value) => {
                let key = resolve(self, key);
                let delta: i64 = self.expand(value, rule).trim().parse().unwrap_or(0);
                let current = self.tx_number(&key);
                let next = if matches!(setvar, SetVar::Add(..)) {
                    current.saturating_add(delta)
                } else {
                    current.saturating_sub(delta)
                };
                self.tx.insert(key, next.to_string().into_bytes());
            }
            SetVar::Delete(key) => {
                let key = resolve(self, key);
                self.tx.remove(&key);
            }
        }
    }

    fn apply_ctl(&mut self, ctl: &Ctl) {
        match ctl {
            Ctl::RuleRemoveById(ranges) => self.removed_ids.extend(ranges),
            Ctl::RuleRemoveByTag(tag) => {
                self.removed_tags.insert(tag.clone());
            }
            Ctl::RuleRemoveTargetById(ranges, spec) => self
                .removed_targets
                .push((RemovedBy::Ids(ranges.clone()), spec.clone())),
            Ctl::RuleRemoveTargetByTag(tag, spec) => self
                .removed_targets
                .push((RemovedBy::Tag(tag.clone()), spec.clone())),
            Ctl::RuleEngine(mode) => match mode.as_str() {
                "off" => self.engine_off = true,
                "detectiononly" => self.detection_only = true,
                _ => {}
            },
            Ctl::RequestBodyProcessor(processor) => {
                if !self.body_parsed {
                    self.body_processor = Some(processor.clone());
                }
            }
            Ctl::Ignored => {}
        }
    }

    fn transformed(&mut self, transforms: &[Transform], value: &[u8]) -> std::rc::Rc<Vec<u8>> {
        use std::hash::{Hash, Hasher};
        let mut hasher = Fnv1a::default();
        transforms.hash(&mut hasher);
        value.hash(&mut hasher);
        let bucket = self.transform_cache.entry(hasher.finish()).or_default();
        if let Some((_, _, output)) = bucket
            .iter()
            .find(|(chain, input, _)| chain == transforms && input.as_slice() == value)
        {
            return output.clone();
        }
        let mut current = value.to_vec();
        for transform in transforms {
            current = transform.apply(&current);
        }
        let output = std::rc::Rc::new(current);
        bucket.push((transforms.to_vec(), value.to_vec(), output.clone()));
        output
    }

    /// Evaluate one rule link; returns the matched `(name, value)` pairs.
    fn match_link(&mut self, rule: &Rule, starter: &Rule, phase: u8) -> Values {
        let Some(operator) = &rule.operator else {
            // SecAction: unconditional.
            for setvar in &rule.actions.setvars {
                self.apply_setvar(setvar, starter);
            }
            for ctl in &rule.actions.ctls {
                self.apply_ctl(ctl);
            }
            return vec![(String::new(), Vec::new())];
        };
        let param = if operator.has_macros {
            self.expand(&operator.param, rule)
        } else {
            operator.param.clone()
        };
        let mut matched = Vec::new();
        for (values, index) in self.values_for(rule, phase) {
            let (name, raw) = &values[index];
            let raw = &raw[..raw.len().min(MAX_VALUE_BYTES)];
            let mut candidates: Vec<std::rc::Rc<Vec<u8>>> = Vec::new();
            if rule.actions.multi_match {
                let mut current = raw.to_vec();
                candidates.push(std::rc::Rc::new(current.clone()));
                for transform in &rule.actions.transforms {
                    current = transform.apply(&current);
                    candidates.push(std::rc::Rc::new(current.clone()));
                }
            } else {
                candidates.push(self.transformed(&rule.actions.transforms, raw));
            }
            for candidate in candidates {
                let result = operator.evaluate(&candidate, &param, rule.actions.capture);
                if result.matched {
                    if rule.actions.capture {
                        if let Some(captures) = result.captures {
                            for (index, group) in captures.into_iter().enumerate() {
                                self.tx.insert(format!("tx.{index}"), group);
                            }
                        }
                    }
                    self.matched_var = (name.clone(), candidate.to_vec());
                    matched.push((name.clone(), candidate.to_vec()));
                    // Non-disruptive actions run once per matched value,
                    // seeing that value's captures and MATCHED_VAR.
                    for setvar in &rule.actions.setvars {
                        self.apply_setvar(setvar, starter);
                    }
                    for ctl in &rule.actions.ctls {
                        self.apply_ctl(ctl);
                    }
                    break;
                }
            }
        }
        matched
    }

    fn run_rule(&mut self, rule: &Rule, phase: u8, defaults: Option<&Actions>) -> RuleResult {
        // As in ModSecurity, each link's non-disruptive actions run as its
        // values match (see `match_link`), so later links read what it set.
        let mut link = Some(rule);
        while let Some(current) = link {
            let matched = self.match_link(current, rule, phase);
            if matched.is_empty() {
                return RuleResult::NoMatch;
            }
            self.matched_vars = matched;
            link = current.chained.as_deref();
        }
        let log = rule
            .actions
            .log
            .or_else(|| defaults.and_then(|d| d.log))
            .unwrap_or(true);
        if log && rule.operator.is_some() {
            self.outcome.matched.push(MatchedRule {
                id: rule.id,
                msg: rule.actions.msg.as_ref().map(|m| self.expand(m, rule)),
                tags: rule.actions.tags.clone(),
                severity: rule.actions.severity.clone(),
            });
        }
        let mut disruptive = rule.actions.disruptive.unwrap_or(Disruptive::Pass);
        if disruptive == Disruptive::Block {
            disruptive = defaults
                .and_then(|d| d.disruptive)
                .filter(|d| *d != Disruptive::Block)
                .unwrap_or(Disruptive::Pass);
        }
        RuleResult::Matched {
            disruptive,
            status: rule
                .actions
                .status
                .or_else(|| defaults.and_then(|d| d.status))
                .unwrap_or(403),
        }
    }
}

enum RuleResult {
    NoMatch,
    Matched { disruptive: Disruptive, status: u16 },
}

impl RuleSet {
    /// Evaluate the request phases (1 and 2) against a request. `setup`
    /// variables are applied first, as `crs-setup.conf` would.
    pub fn evaluate(&self, request: &Request, setup: &[(String, String)]) -> Outcome {
        let mut tx = Transaction::new(request);
        for (key, value) in setup {
            tx.tx.insert(
                format!("tx.{}", key.to_ascii_lowercase()),
                value.as_bytes().to_vec(),
            );
        }
        'phases: for phase in [1u8, 2] {
            if phase == 2 {
                tx.parse_body();
            }
            let defaults = self.defaults.get(&phase);
            let mut skip_after: Option<&str> = None;
            let mut skip = 0usize;
            for entry in &self.entries {
                let rule = match entry {
                    Entry::Marker(name) => {
                        if skip_after == Some(name.as_str()) {
                            skip_after = None;
                        }
                        continue;
                    }
                    Entry::Rule(rule) => rule,
                };
                if rule.phase != phase || skip_after.is_some() {
                    continue;
                }
                if skip > 0 {
                    skip -= 1;
                    continue;
                }
                if tx.engine_off {
                    break 'phases;
                }
                if tx.removed(rule) {
                    continue;
                }
                let RuleResult::Matched { disruptive, status } = tx.run_rule(rule, phase, defaults)
                else {
                    continue;
                };
                if let Some(marker) = &rule.actions.skip_after {
                    skip_after = Some(marker.as_str());
                }
                skip = rule.actions.skip;
                match disruptive {
                    Disruptive::Pass | Disruptive::Block => {}
                    Disruptive::Allow(AllowScope::Phase) => continue 'phases,
                    Disruptive::Allow(_) => break 'phases,
                    Disruptive::Deny | Disruptive::Drop | Disruptive::Redirect => {
                        if tx.detection_only {
                            continue;
                        }
                        tx.outcome.intervention = Some(Intervention {
                            rule_id: rule.id,
                            status,
                            disruptive,
                        });
                        break 'phases;
                    }
                }
            }
        }
        tx.outcome.anomaly_score = ["tx.blocking_inbound_anomaly_score", "tx.anomaly_score"]
            .iter()
            .map(|key| tx.tx_number(key))
            .max()
            .unwrap_or(0);
        tx.outcome.detection_only = tx.detection_only || tx.engine_off;
        tx.outcome
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(uri: &str, body: &str, content_type: &str) -> Request {
        Request {
            method: if body.is_empty() { "GET" } else { "POST" }.into(),
            uri: uri.into(),
            protocol: "HTTP/1.1".into(),
            headers: vec![
                ("Host".into(), "example.com".into()),
                ("Content-Type".into(), content_type.into()),
            ],
            body: body.as_bytes().to_vec(),
            remote_addr: "203.0.113.9".into(),
        }
    }

    const RULES: &str = r#"
SecDefaultAction "phase:2,log,pass"
SecAction "id:1,phase:1,pass,nolog,setvar:tx.threshold=5"
SecRule ARGS "@rx (?i)union\s+select" "id:100,phase:2,block,t:none,t:urlDecodeUni,setvar:'tx.score=+%{tx.critical}',msg:'SQLi in %{MATCHED_VAR_NAME}'"
SecRule REQUEST_HEADERS:User-Agent "@pm sqlmap nikto" "id:101,phase:1,block,setvar:tx.score=+5"
SecRule ARGS:skip "@streq yes" "id:102,phase:2,pass,nolog,skipAfter:END"
SecRule ARGS "@contains evil" "id:103,phase:2,block,setvar:tx.score=+5"
SecMarker END
SecRule &ARGS "@gt 3" "id:104,phase:2,block,chain"
    SecRule ARGS_NAMES "@rx ^x" "setvar:tx.score=+1"
SecRule TX:SCORE "@ge %{tx.threshold}" "id:900,phase:2,deny,status:406,msg:'score %{tx.score}'"
"#;

    fn ruleset() -> RuleSet {
        RuleSet::compile(
            &[Source {
                name: "test.conf",
                content: RULES,
            }],
            &HashMap::new(),
        )
        .unwrap()
    }

    fn setup() -> Vec<(String, String)> {
        vec![("critical".into(), "5".into())]
    }

    #[test]
    fn scores_and_blocks_like_crs_anomaly_mode() {
        let set = ruleset();
        let outcome = set.evaluate(&request("/?q=1%20UNION%20SELECT%20x", "", ""), &setup());
        let ids: Vec<_> = outcome.matched.iter().map(|m| m.id).collect();
        assert_eq!(ids, vec![100, 900]);
        assert_eq!(outcome.matched[0].msg.as_deref(), Some("SQLi in ARGS:q"));
        assert_eq!(outcome.intervention.unwrap().status, 406);
        assert_eq!(outcome.anomaly_score, 0);

        let clean = set.evaluate(&request("/?q=hello", "", ""), &setup());
        assert!(clean.matched.is_empty() && clean.intervention.is_none());
    }

    #[test]
    fn skip_after_chains_counts_and_bodies() {
        let set = ruleset();
        // skipAfter jumps over rule 103.
        let skipped = set.evaluate(&request("/?skip=yes&a=evil", "", ""), &setup());
        assert!(skipped.intervention.is_none());
        let hit = set.evaluate(&request("/?a=evil", "", ""), &setup());
        assert_eq!(hit.intervention.unwrap().rule_id, 900);
        // Chain: more than three args and one named x*.
        let chained = set.evaluate(&request("/?a=1&b=2&c=3&xx=4", "", ""), &setup());
        assert!(chained.matched.iter().any(|m| m.id == 104));
        // Body processors.
        let json = set.evaluate(
            &request("/", r#"{"a":{"b":"evil"}}"#, "application/json"),
            &setup(),
        );
        assert!(json.matched.iter().any(|m| m.id == 103));
        let form = set.evaluate(
            &request(
                "/",
                "a=1+union+select+2",
                "application/x-www-form-urlencoded",
            ),
            &setup(),
        );
        assert!(form.matched.iter().any(|m| m.id == 100));
    }

    #[test]
    fn rejects_unsupported_constructs_instead_of_ignoring_them() {
        for bad in [
            r#"SecRule ARGS "@nope x" "id:1,phase:2,pass""#,
            r#"SecRule ARGS "@rx x" "id:1,phase:2,t:frobnicate""#,
            r#"SecRule ARGS "@rx x" "id:1,phase:2,frobnicate""#,
            r#"SecRule ARGS "@rx x" "phase:2,pass""#,
            r#"SecRule ARGS "@rx x" "id:1,phase:2,chain""#,
        ] {
            assert!(
                RuleSet::compile(
                    &[Source {
                        name: "bad.conf",
                        content: bad
                    }],
                    &HashMap::new()
                )
                .is_err(),
                "{bad}"
            );
        }
    }
}
