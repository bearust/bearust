//! SecLang operators (`@rx`, `@pm`, comparisons, validators, libinjection).

use super::SecLangError;
use aho_corasick::{AhoCorasick, AhoCorasickBuilder, MatchKind};
use std::collections::HashMap;
use std::net::IpAddr;

/// Bound for compiled regex programs. Assembled CRS patterns are large.
const REGEX_SIZE_LIMIT: usize = 64 * 1024 * 1024;

#[derive(Debug)]
pub enum Regex {
    /// Byte-oriented, PCRE-like: `(?s)` and ASCII classes, no Unicode mode.
    Bytes(regex::bytes::Regex),
    /// Fallback for lookaround/backreferences; matches on lossy UTF-8.
    Fancy(Box<fancy_regex::Regex>),
}

impl Regex {
    pub fn compile(pattern: &str) -> Result<Self, String> {
        let attempt = |unicode: bool| {
            regex::bytes::RegexBuilder::new(pattern)
                .dot_matches_new_line(true)
                .unicode(unicode)
                .size_limit(REGEX_SIZE_LIMIT)
                .dfa_size_limit(REGEX_SIZE_LIMIT)
                .build()
        };
        if let Ok(regex) = attempt(false).or_else(|_| attempt(true)) {
            return Ok(Self::Bytes(regex));
        }
        fancy_regex::RegexBuilder::new(&format!("(?s){pattern}"))
            .delegate_size_limit(REGEX_SIZE_LIMIT)
            .build()
            .map(|regex| Self::Fancy(Box::new(regex)))
            .map_err(|error| format!("invalid regex: {error}"))
    }

    /// Match and return up to ten capture groups (group 0 is the match).
    pub fn captures(&self, input: &[u8]) -> Option<Vec<Vec<u8>>> {
        match self {
            Self::Bytes(regex) => regex.captures(input).map(|caps| {
                caps.iter()
                    .take(10)
                    .map(|group| group.map_or_else(Vec::new, |m| m.as_bytes().to_vec()))
                    .collect()
            }),
            Self::Fancy(regex) => {
                let text = String::from_utf8_lossy(input);
                regex.captures(&text).ok().flatten().map(|caps| {
                    caps.iter()
                        .take(10)
                        .map(|group| {
                            group.map_or_else(Vec::new, |m| m.as_str().as_bytes().to_vec())
                        })
                        .collect()
                })
            }
        }
    }

    pub fn is_match(&self, input: &[u8]) -> bool {
        match self {
            Self::Bytes(regex) => regex.is_match(input),
            Self::Fancy(regex) => regex
                .is_match(&String::from_utf8_lossy(input))
                .unwrap_or(false),
        }
    }
}

#[derive(Debug)]
pub enum Kind {
    Rx(Regex),
    Pm(AhoCorasick),
    Streq,
    Contains,
    BeginsWith,
    EndsWith,
    Within,
    Eq,
    Ge,
    Gt,
    Le,
    Lt,
    ValidateByteRange(Vec<(u8, u8)>),
    ValidateUrlEncoding,
    ValidateUtf8Encoding,
    DetectSqli,
    DetectXss,
    IpMatch(Vec<(IpAddr, u8)>),
    Unconditional,
    NoMatch,
}

#[derive(Debug)]
pub struct Operator {
    pub kind: Kind,
    pub negated: bool,
    /// Raw parameter; expanded per transaction when it contains macros.
    pub param: String,
    pub has_macros: bool,
}

pub struct MatchResult {
    pub matched: bool,
    pub captures: Option<Vec<Vec<u8>>>,
}

fn phrases(text: &str) -> Vec<String> {
    text.split_whitespace().map(str::to_owned).collect()
}

fn phrase_matcher(words: &[String]) -> Result<AhoCorasick, String> {
    AhoCorasickBuilder::new()
        .ascii_case_insensitive(true)
        .match_kind(MatchKind::Standard)
        .build(words)
        .map_err(|error| error.to_string())
}

fn byte_ranges(param: &str) -> Result<Vec<(u8, u8)>, String> {
    param
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (lo, hi) = part.split_once('-').unwrap_or((part, part));
            let lo = lo
                .trim()
                .parse::<u8>()
                .map_err(|_| format!("bad byte range {part}"))?;
            let hi = hi
                .trim()
                .parse::<u8>()
                .map_err(|_| format!("bad byte range {part}"))?;
            Ok((lo, hi))
        })
        .collect()
}

fn networks(param: &str) -> Result<Vec<(IpAddr, u8)>, String> {
    param
        .split(',')
        .map(str::trim)
        .filter(|part| !part.is_empty())
        .map(|part| {
            let (addr, bits) = match part.split_once('/') {
                Some((addr, bits)) => (addr, Some(bits)),
                None => (part, None),
            };
            let addr: IpAddr = addr.parse().map_err(|_| format!("bad address {part}"))?;
            let max = if addr.is_ipv4() { 32 } else { 128 };
            let bits = match bits {
                Some(bits) => bits
                    .parse::<u8>()
                    .map_err(|_| format!("bad prefix {part}"))?,
                None => max,
            };
            if bits > max {
                return Err(format!("bad prefix {part}"));
            }
            Ok((addr, bits))
        })
        .collect()
}

fn in_network(addr: IpAddr, (net, bits): (IpAddr, u8)) -> bool {
    match (addr, net) {
        (IpAddr::V4(a), IpAddr::V4(n)) => {
            let mask = if bits == 0 {
                0
            } else {
                u32::MAX << (32 - u32::from(bits))
            };
            u32::from(a) & mask == u32::from(n) & mask
        }
        (IpAddr::V6(a), IpAddr::V6(n)) => {
            let mask = if bits == 0 {
                0
            } else {
                u128::MAX << (128 - u32::from(bits))
            };
            u128::from(a) & mask == u128::from(n) & mask
        }
        _ => false,
    }
}

impl Operator {
    /// Parse `"!@rx foo"`; a bare string is an implicit `@rx`.
    pub fn parse(raw: &str, data_files: &HashMap<String, String>) -> Result<Self, SecLangError> {
        let mut text = raw.trim_start();
        let negated = text.starts_with('!');
        if negated {
            text = text[1..].trim_start();
        }
        let (name, param) = if let Some(rest) = text.strip_prefix('@') {
            match rest.split_once(|c: char| c.is_whitespace()) {
                Some((name, param)) => (name.to_ascii_lowercase(), param.trim_start().to_owned()),
                None => (rest.to_ascii_lowercase(), String::new()),
            }
        } else {
            ("rx".to_owned(), text.to_owned())
        };
        let has_macros = param.contains("%{");
        let error = |message: String| SecLangError::Operator {
            operator: name.clone(),
            message,
        };
        let kind = match name.as_str() {
            "rx" => {
                if has_macros {
                    return Err(error("macros in @rx are not supported".into()));
                }
                Kind::Rx(Regex::compile(&param).map_err(error)?)
            }
            "pm" => Kind::Pm(phrase_matcher(&phrases(&param)).map_err(error)?),
            "pmfromfile" | "pmf" => {
                let mut words = Vec::new();
                for file in param.split_whitespace() {
                    let name = file.rsplit('/').next().unwrap_or(file);
                    let content = data_files
                        .get(name)
                        .ok_or_else(|| error(format!("missing data file {name}")))?;
                    words.extend(
                        content
                            .lines()
                            .map(str::trim)
                            .filter(|line| !line.is_empty() && !line.starts_with('#'))
                            .map(str::to_owned),
                    );
                }
                Kind::Pm(phrase_matcher(&words).map_err(error)?)
            }
            "streq" => Kind::Streq,
            "contains" => Kind::Contains,
            "beginswith" => Kind::BeginsWith,
            "endswith" => Kind::EndsWith,
            "within" => Kind::Within,
            "eq" => Kind::Eq,
            "ge" => Kind::Ge,
            "gt" => Kind::Gt,
            "le" => Kind::Le,
            "lt" => Kind::Lt,
            "validatebyterange" => Kind::ValidateByteRange(byte_ranges(&param).map_err(error)?),
            "validateurlencoding" => Kind::ValidateUrlEncoding,
            "validateutf8encoding" => Kind::ValidateUtf8Encoding,
            "detectsqli" => Kind::DetectSqli,
            "detectxss" => Kind::DetectXss,
            "ipmatch" => Kind::IpMatch(networks(&param).map_err(error)?),
            "unconditionalmatch" => Kind::Unconditional,
            "nomatch" => Kind::NoMatch,
            other => return Err(error(format!("unsupported operator @{other}"))),
        };
        Ok(Self {
            kind,
            negated,
            param,
            has_macros,
        })
    }

    /// Evaluate against one value; `param` is the macro-expanded parameter.
    /// Capture groups are only extracted when `want_captures` is set, since
    /// a plain match is much cheaper.
    pub fn evaluate(&self, input: &[u8], param: &str, want_captures: bool) -> MatchResult {
        let mut captures = None;
        let matched = match &self.kind {
            // Most values do not match; test first so the capture
            // allocation only happens on a hit.
            Kind::Rx(regex) if want_captures => {
                if regex.is_match(input) {
                    captures = regex.captures(input);
                }
                captures.is_some()
            }
            Kind::Rx(regex) => regex.is_match(input),
            Kind::Pm(matcher) => matcher.find(input).is_some(),
            Kind::Streq => input == param.as_bytes(),
            Kind::Contains => contains(input, param.as_bytes()),
            Kind::BeginsWith => input.starts_with(param.as_bytes()),
            Kind::EndsWith => input.ends_with(param.as_bytes()),
            Kind::Within => !input.is_empty() && contains(param.as_bytes(), input),
            Kind::Eq => number(input) == number(param.as_bytes()),
            Kind::Ge => number(input) >= number(param.as_bytes()),
            Kind::Gt => number(input) > number(param.as_bytes()),
            Kind::Le => number(input) <= number(param.as_bytes()),
            Kind::Lt => number(input) < number(param.as_bytes()),
            Kind::ValidateByteRange(ranges) => input
                .iter()
                .any(|b| !ranges.iter().any(|(lo, hi)| (*lo..=*hi).contains(b))),
            Kind::ValidateUrlEncoding => invalid_url_encoding(input),
            Kind::ValidateUtf8Encoding => std::str::from_utf8(input).is_err(),
            Kind::DetectSqli => guarded(|| libinjectionrs::detect_sqli(input).is_injection()),
            Kind::DetectXss => guarded(|| libinjectionrs::detect_xss(input).is_injection()),
            Kind::IpMatch(nets) => std::str::from_utf8(input)
                .ok()
                .and_then(|text| text.trim().parse::<IpAddr>().ok())
                .is_some_and(|addr| nets.iter().any(|net| in_network(addr, *net))),
            Kind::Unconditional => true,
            Kind::NoMatch => false,
        };
        if self.negated {
            MatchResult {
                matched: !matched,
                captures: None,
            }
        } else {
            MatchResult { matched, captures }
        }
    }
}

/// libinjection ports index aggressively; a panic must never take down the
/// proxy worker, so treat one as "no detection".
fn guarded(detect: impl FnOnce() -> bool + std::panic::UnwindSafe) -> bool {
    std::panic::catch_unwind(detect).unwrap_or(false)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

/// Leading integer, as ModSecurity's `atoi` (non-numeric is 0).
fn number(input: &[u8]) -> i64 {
    let text = String::from_utf8_lossy(input);
    let text = text.trim();
    let sign_len = usize::from(text.starts_with(['-', '+']));
    let digits = text[sign_len..]
        .bytes()
        .take_while(u8::is_ascii_digit)
        .count();
    text[..sign_len + digits].parse().unwrap_or(0)
}

fn invalid_url_encoding(input: &[u8]) -> bool {
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'%' {
            let valid = input.len() > i + 2
                && input[i + 1].is_ascii_hexdigit()
                && input[i + 2].is_ascii_hexdigit();
            if !valid {
                return true;
            }
            i += 3;
        } else {
            i += 1;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    fn op(raw: &str) -> Operator {
        Operator::parse(raw, &HashMap::new()).unwrap()
    }

    #[test]
    fn operators_follow_modsecurity_semantics() {
        assert!(
            op("@rx (?i)union\\s+select")
                .evaluate(b"1 UNION select", "", false)
                .matched
        );
        assert!(op("@pm foo bar").evaluate(b"xxBARxx", "", false).matched);
        assert!(
            op("@within GET POST")
                .evaluate(b"GET", "GET POST", false)
                .matched
        );
        assert!(
            !op("@within GET POST")
                .evaluate(b"", "GET POST", false)
                .matched
        );
        assert!(op("@ge 5").evaluate(b"7", "5", false).matched);
        assert!(op("!@eq 0").evaluate(b"3", "0", false).matched);
        assert!(
            op("@validateByteRange 32-126")
                .evaluate(b"a\x01", "", false)
                .matched
        );
        assert!(
            op("@validateUrlEncoding")
                .evaluate(b"%zz", "", false)
                .matched
        );
        assert!(
            op("@ipMatch 10.0.0.0/8,::1")
                .evaluate(b"10.2.3.4", "", false)
                .matched
        );
        assert!(
            op("@detectSQLi")
                .evaluate(b"1' OR '1'='1", "", false)
                .matched
        );
        assert!(
            op("@detectXSS")
                .evaluate(b"<script>alert(1)</script>", "", false)
                .matched
        );
        // Lookahead needs the fancy-regex fallback.
        assert!(op("@rx a(?=b)").evaluate(b"ab", "", false).matched);
        let caps = op("@rx (\\d+)-(\\d+)")
            .evaluate(b"x 12-34", "", true)
            .captures
            .unwrap();
        assert_eq!(caps[2], b"34");
    }
}
