//! SecLang directive parser (the ModSecurity/Coraza rule language).
//!
//! Handles line continuations, comments, Apache-style quoting (only `\"`
//! is unescaped inside double quotes, so regex backslashes survive), the
//! variable list grammar with exclusions, counts, and `/regex/` selectors,
//! and comma-separated actions with single-quoted values.

use super::SecLangError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Directive {
    Rule {
        variables: String,
        operator: String,
        actions: Option<String>,
        line: usize,
    },
    Action {
        actions: String,
        line: usize,
    },
    Marker(String),
    DefaultAction(String),
    /// Directives that configure the host engine and have no effect here.
    Ignored(String),
}

/// Split a configuration file into logical directives.
pub fn directives(source: &str) -> Result<Vec<Directive>, SecLangError> {
    let mut out = Vec::new();
    let mut logical = String::new();
    let mut start_line = 0;
    for (index, raw) in source.lines().enumerate() {
        let line = raw.trim_end_matches('\r');
        if logical.is_empty() {
            let trimmed = line.trim_start();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            start_line = index + 1;
        }
        if let Some(stripped) = line.strip_suffix('\\') {
            logical.push_str(stripped);
            continue;
        }
        logical.push_str(line);
        out.push(parse_directive(logical.trim(), start_line)?);
        logical.clear();
    }
    if !logical.trim().is_empty() {
        out.push(parse_directive(logical.trim(), start_line)?);
    }
    Ok(out)
}

fn parse_directive(text: &str, line: usize) -> Result<Directive, SecLangError> {
    let args = split_args(text).map_err(|message| SecLangError::Parse { line, message })?;
    let Some((name, rest)) = args.split_first() else {
        return Ok(Directive::Ignored(String::new()));
    };
    let error = |message: &str| SecLangError::Parse {
        line,
        message: message.to_owned(),
    };
    match name.to_ascii_lowercase().as_str() {
        "secrule" => {
            if !(2..=3).contains(&rest.len()) {
                return Err(error(
                    "SecRule takes variables, operator, and optional actions",
                ));
            }
            Ok(Directive::Rule {
                variables: rest[0].clone(),
                operator: rest[1].clone(),
                actions: rest.get(2).cloned(),
                line,
            })
        }
        "secaction" => match rest {
            [actions] => Ok(Directive::Action {
                actions: actions.clone(),
                line,
            }),
            _ => Err(error("SecAction takes one action list")),
        },
        "secmarker" => match rest {
            [marker] => Ok(Directive::Marker(marker.clone())),
            _ => Err(error("SecMarker takes one name")),
        },
        "secdefaultaction" => match rest {
            [actions] => Ok(Directive::DefaultAction(actions.clone())),
            _ => Err(error("SecDefaultAction takes one action list")),
        },
        _ => Ok(Directive::Ignored(name.clone())),
    }
}

/// Apache `ap_getword_conf` semantics: whitespace-separated words, double or
/// single quotes group, and a backslash only escapes the active quote.
fn split_args(text: &str) -> Result<Vec<String>, String> {
    let mut args = Vec::new();
    let mut chars = text.chars().peekable();
    loop {
        while chars.peek().is_some_and(|c| c.is_whitespace()) {
            chars.next();
        }
        let Some(&first) = chars.peek() else { break };
        let mut word = String::new();
        if first == '"' || first == '\'' {
            chars.next();
            let mut closed = false;
            while let Some(c) = chars.next() {
                if c == '\\' && chars.peek() == Some(&first) {
                    word.push(first);
                    chars.next();
                } else if c == first {
                    closed = true;
                    break;
                } else {
                    word.push(c);
                }
            }
            if !closed {
                return Err("unterminated quoted argument".into());
            }
        } else {
            while let Some(&c) = chars.peek() {
                if c.is_whitespace() {
                    break;
                }
                word.push(c);
                chars.next();
            }
        }
        args.push(word);
    }
    Ok(args)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector {
    None,
    Key(String),
    Regex(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VariableSpec {
    pub name: String,
    pub selector: Selector,
    pub exclude: bool,
    pub count: bool,
}

/// Parse `ARGS|!ARGS:foo|&REQUEST_HEADERS:/^x-/|TX:0`.
pub fn variables(text: &str) -> Result<Vec<VariableSpec>, String> {
    let bytes: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < bytes.len() {
        let mut exclude = false;
        let mut count = false;
        while i < bytes.len() && (bytes[i] == '!' || bytes[i] == '&') {
            if bytes[i] == '!' {
                exclude = true;
            } else {
                count = true;
            }
            i += 1;
        }
        let start = i;
        while i < bytes.len() && bytes[i] != ':' && bytes[i] != '|' {
            i += 1;
        }
        let name: String = bytes[start..i]
            .iter()
            .collect::<String>()
            .trim()
            .to_ascii_uppercase();
        if name.is_empty() {
            return Err("empty variable name".into());
        }
        let mut selector = Selector::None;
        if i < bytes.len() && bytes[i] == ':' {
            i += 1;
            if name == "XML" {
                // XPath expressions are not regexes.
                let start = i;
                while i < bytes.len() && bytes[i] != '|' {
                    i += 1;
                }
                selector = Selector::Key(bytes[start..i].iter().collect());
            } else if i < bytes.len() && bytes[i] == '/' {
                i += 1;
                let mut pattern = String::new();
                while i < bytes.len() {
                    if bytes[i] == '\\' && i + 1 < bytes.len() && bytes[i + 1] == '/' {
                        pattern.push('/');
                        i += 2;
                        continue;
                    }
                    if bytes[i] == '/' {
                        break;
                    }
                    pattern.push(bytes[i]);
                    i += 1;
                }
                if i >= bytes.len() {
                    return Err("unterminated selector regex".into());
                }
                i += 1;
                selector = Selector::Regex(pattern);
            } else if i < bytes.len() && bytes[i] == '\'' {
                i += 1;
                let start = i;
                while i < bytes.len() && bytes[i] != '\'' {
                    i += 1;
                }
                selector = Selector::Key(bytes[start..i].iter().collect());
                i = (i + 1).min(bytes.len());
            } else {
                let start = i;
                while i < bytes.len() && bytes[i] != '|' {
                    i += 1;
                }
                selector =
                    Selector::Key(bytes[start..i].iter().collect::<String>().trim().to_owned());
            }
        }
        out.push(VariableSpec {
            name,
            selector,
            exclude,
            count,
        });
        while i < bytes.len() && bytes[i] != '|' {
            i += 1;
        }
        i += 1;
    }
    Ok(out)
}

/// Parse `id:1,phase:2,msg:'a, b',t:none` into `(name, value)` pairs.
pub fn actions(text: &str) -> Result<Vec<(String, Option<String>)>, String> {
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0;
    let mut out = Vec::new();
    while i < chars.len() {
        while i < chars.len() && (chars[i].is_whitespace() || chars[i] == ',') {
            i += 1;
        }
        if i >= chars.len() {
            break;
        }
        let start = i;
        while i < chars.len() && chars[i] != ':' && chars[i] != ',' {
            i += 1;
        }
        let name = chars[start..i]
            .iter()
            .collect::<String>()
            .trim()
            .to_ascii_lowercase();
        let mut value = None;
        if i < chars.len() && chars[i] == ':' {
            i += 1;
            while i < chars.len() && chars[i] == ' ' {
                i += 1;
            }
            let mut v = String::new();
            if i < chars.len() && chars[i] == '\'' {
                i += 1;
                let mut closed = false;
                while i < chars.len() {
                    if chars[i] == '\\' && i + 1 < chars.len() && chars[i + 1] == '\'' {
                        v.push('\'');
                        i += 2;
                        continue;
                    }
                    if chars[i] == '\'' {
                        closed = true;
                        i += 1;
                        break;
                    }
                    v.push(chars[i]);
                    i += 1;
                }
                if !closed {
                    return Err(format!("unterminated value for action {name}"));
                }
            } else {
                while i < chars.len() && chars[i] != ',' {
                    v.push(chars[i]);
                    i += 1;
                }
                v = v.trim().to_owned();
            }
            value = Some(v);
        }
        if !name.is_empty() {
            out.push((name, value));
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_continuations_and_keeps_regex_backslashes() {
        let source = "# comment\nSecRule ARGS \"@rx a\\\\b\\\"c\" \\\n    \"id:1,\\\n    phase:2,msg:'x, y'\"\nSecMarker END\n";
        let parsed = directives(source).unwrap();
        assert_eq!(
            parsed[0],
            Directive::Rule {
                variables: "ARGS".into(),
                operator: "@rx a\\\\b\"c".into(),
                actions: Some("id:1,    phase:2,msg:'x, y'".into()),
                line: 2,
            }
        );
        assert_eq!(parsed[1], Directive::Marker("END".into()));
        assert_eq!(
            actions("id:1,    phase:2,msg:'x, y'").unwrap(),
            vec![
                ("id".into(), Some("1".into())),
                ("phase".into(), Some("2".into())),
                ("msg".into(), Some("x, y".into())),
            ]
        );
    }

    #[test]
    fn parses_variable_lists_with_selectors() {
        let vars =
            variables("REQUEST_COOKIES|!REQUEST_COOKIES:/__utm|_ga/|&ARGS:x|XML:/*|TX:'a b'")
                .unwrap();
        assert_eq!(vars.len(), 5);
        assert_eq!(vars[1].selector, Selector::Regex("__utm|_ga".into()));
        assert!(vars[1].exclude && vars[2].count);
        assert_eq!(vars[3].selector, Selector::Key("/*".into()));
        assert_eq!(vars[4].selector, Selector::Key("a b".into()));
    }
}
