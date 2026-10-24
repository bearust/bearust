//! OWASP CRS regression suite (go-ftw format) against Bearust's SecLang
//! engine. Needs a CRS checkout, so it is ignored by default:
//!
//! ```sh
//! CRS_DIR=/path/to/coreruleset-4.x cargo test --release --test crs_regression -- --ignored --nocapture
//! ```
//!
//! Only request-phase tests with log expectations are run. The test fails
//! when the pass rate drops below `CRS_MIN_PASS_RATE` (default 0.99).

use bearust::seclang::{Request, RuleSet, Source};
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap};
use std::path::Path;

#[derive(Deserialize)]
struct TestFile {
    rule_id: Option<i64>,
    tests: Vec<TestCase>,
}

#[derive(Deserialize)]
struct TestCase {
    test_id: i64,
    stages: Vec<Stage>,
}

#[derive(Deserialize)]
struct Stage {
    input: Input,
    output: Output,
}

#[derive(Deserialize, Default)]
struct Input {
    method: Option<String>,
    uri: Option<String>,
    version: Option<String>,
    #[serde(default)]
    headers: BTreeMap<String, serde_yaml::Value>,
    data: Option<serde_yaml::Value>,
    encoded_request: Option<String>,
    autocomplete_headers: Option<bool>,
}

#[derive(Deserialize, Default)]
struct Output {
    log: Option<Log>,
}

#[derive(Deserialize, Default)]
struct Log {
    #[serde(default)]
    expect_ids: Vec<i64>,
    #[serde(default)]
    no_expect_ids: Vec<i64>,
}

const TEST_SETUP: &str = r#"
SecAction "id:900005,phase:1,nolog,pass,ctl:ruleRemoveById=910000,\
  setvar:tx.blocking_paranoia_level=4,setvar:tx.crs_validate_utf8_encoding=1,\
  setvar:tx.arg_name_length=100,setvar:tx.arg_length=400,\
  setvar:tx.max_file_size=64100,setvar:tx.combined_file_sizes=65535"
"#;

fn scalar(value: &serde_yaml::Value) -> String {
    match value {
        serde_yaml::Value::String(s) => s.clone(),
        serde_yaml::Value::Number(n) => n.to_string(),
        serde_yaml::Value::Bool(b) => b.to_string(),
        serde_yaml::Value::Sequence(items) => {
            items.iter().map(scalar).collect::<Vec<_>>().join("\r\n")
        }
        _ => String::new(),
    }
}

fn build(input: &Input) -> Option<Request> {
    if input.encoded_request.is_some() {
        return None;
    }
    let body = input
        .data
        .as_ref()
        .map(scalar)
        .unwrap_or_default()
        .into_bytes();
    let mut headers: Vec<(String, String)> = input
        .headers
        .iter()
        .map(|(k, v)| (k.clone(), scalar(v)))
        .collect();
    if input.autocomplete_headers.unwrap_or(true) {
        if !body.is_empty()
            && !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        {
            headers.push(("Content-Length".into(), body.len().to_string()));
        }
        // go-ftw defaults bodies to form encoding.
        if !body.is_empty()
            && !headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("content-type"))
        {
            headers.push((
                "Content-Type".into(),
                "application/x-www-form-urlencoded".into(),
            ));
        }
        if !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("connection"))
        {
            headers.push(("Connection".into(), "close".into()));
        }
    }
    Some(Request {
        method: input.method.clone().unwrap_or_else(|| "GET".into()),
        uri: input.uri.clone().unwrap_or_else(|| "/".into()),
        protocol: input.version.clone().unwrap_or_else(|| "HTTP/1.1".into()),
        headers,
        body,
        remote_addr: "127.0.0.1".into(),
    })
}

#[test]
#[ignore = "needs CRS_DIR"]
fn crs_regression_suite() {
    let Ok(dir) = std::env::var("CRS_DIR") else {
        eprintln!("CRS_DIR not set; skipping");
        return;
    };
    let dir = Path::new(&dir);
    let mut sources = vec![(
        "crs-setup.conf".to_owned(),
        std::fs::read_to_string(dir.join("crs-setup.conf.example")).unwrap(),
    )];
    sources.push(("test-setup.conf".into(), TEST_SETUP.into()));
    let mut data = HashMap::new();
    let mut files: Vec<_> = std::fs::read_dir(dir.join("rules"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    files.sort();
    for path in files {
        let name = path.file_name().unwrap().to_string_lossy().into_owned();
        if name.ends_with(".data") {
            data.insert(name, std::fs::read_to_string(&path).unwrap());
        } else if name.starts_with("REQUEST-") && name.ends_with(".conf") {
            sources.push((name, std::fs::read_to_string(&path).unwrap()));
        }
    }
    let sources: Vec<Source> = sources
        .iter()
        .map(|(name, content)| Source { name, content })
        .collect();
    let started = std::time::Instant::now();
    let ruleset = RuleSet::compile(&sources, &data).expect("CRS compiles");
    eprintln!(
        "compiled {} rules in {:?}",
        ruleset.rule_count(),
        started.elapsed()
    );

    let mut test_dirs: Vec<_> = std::fs::read_dir(dir.join("tests/regression/tests"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| {
            p.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("REQUEST-")
        })
        .collect();
    test_dirs.sort();
    let (mut passed, mut failed, mut skipped) = (0usize, 0usize, 0usize);
    let mut failures = Vec::new();
    let started = std::time::Instant::now();
    for test_dir in test_dirs {
        let mut yamls: Vec<_> = std::fs::read_dir(&test_dir)
            .unwrap()
            .map(|e| e.unwrap().path())
            .collect();
        yamls.sort();
        for yaml in yamls {
            let file: TestFile =
                match serde_yaml::from_str(&std::fs::read_to_string(&yaml).unwrap()) {
                    Ok(file) => file,
                    Err(error) => {
                        eprintln!("unparsable {}: {error}", yaml.display());
                        continue;
                    }
                };
            for case in file.tests {
                let [stage] = case.stages.as_slice() else {
                    skipped += 1;
                    continue;
                };
                let (Some(log), Some(request)) = (stage.output.log.as_ref(), build(&stage.input))
                else {
                    skipped += 1;
                    continue;
                };
                if log.expect_ids.is_empty() && log.no_expect_ids.is_empty() {
                    skipped += 1;
                    continue;
                }
                let outcome = ruleset.evaluate(&request, &[]);
                let ids: Vec<i64> = outcome.matched.iter().map(|m| m.id).collect();
                let ok = log.expect_ids.iter().all(|id| ids.contains(id))
                    && !log.no_expect_ids.iter().any(|id| ids.contains(id));
                if ok {
                    passed += 1;
                } else {
                    failed += 1;
                    failures.push(format!(
                        "{}-{} expect {:?} not {:?} got {:?}",
                        file.rule_id.unwrap_or(0),
                        case.test_id,
                        log.expect_ids,
                        log.no_expect_ids,
                        ids
                    ));
                }
            }
        }
    }
    let total = passed + failed;
    let rate = passed as f64 / total.max(1) as f64;
    for failure in &failures {
        eprintln!("FAIL {failure}");
    }
    eprintln!(
        "CRS regression: {passed}/{total} passed ({:.1}%), {skipped} skipped, in {:?}",
        rate * 100.0,
        started.elapsed()
    );
    let min: f64 = std::env::var("CRS_MIN_PASS_RATE")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.99);
    assert!(rate >= min, "pass rate {rate:.3} below {min}");
}

/// Per-request cost of the bundled CRS at paranoia level 1.
#[test]
#[ignore = "benchmark"]
fn crs_evaluation_latency() {
    let sources: Vec<Source> = bearust::seclang::crs::CONFIG_FILES
        .iter()
        .map(|(name, content)| Source { name, content })
        .collect();
    let data = bearust::seclang::crs::DATA_FILES
        .iter()
        .map(|(n, c)| ((*n).to_owned(), (*c).to_owned()))
        .collect();
    let ruleset = RuleSet::compile(&sources, &data).unwrap();
    let request = Request {
        method: "GET".into(),
        uri: "/products/42?page=2&sort=price&q=red+shoes".into(),
        protocol: "HTTP/1.1".into(),
        headers: vec![
            ("Host".into(), "shop.example.com".into()),
            (
                "User-Agent".into(),
                "Mozilla/5.0 (X11; Linux x86_64) Firefox/131.0".into(),
            ),
            ("Accept".into(), "text/html,application/xhtml+xml".into()),
            ("Accept-Language".into(), "en-US,en;q=0.5".into()),
            ("Cookie".into(), "session=abc123; theme=dark".into()),
        ],
        body: Vec::new(),
        remote_addr: "203.0.113.9".into(),
    };
    let setup = vec![("blocking_paranoia_level".to_owned(), "1".to_owned())];
    for _ in 0..50 {
        ruleset.evaluate(&request, &setup);
    }
    let started = std::time::Instant::now();
    let rounds: u32 = std::env::var("CRS_BENCH_ROUNDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(2000);
    for _ in 0..rounds {
        ruleset.evaluate(&request, &setup);
    }
    eprintln!("CRS PL1 per request: {:?}", started.elapsed() / rounds);
}
