use bearust::control_plane::models::{WafAction, WafConfig, WafMode, WafRule};
use bearust::waf::{compile_snapshot, evaluate, InspectionContext, WafDecision};

fn rule(category: &str, matcher: &str, action: WafAction) -> WafRule {
    WafRule {
        id: 1,
        name: category.into(),
        source: "builtin".into(),
        category: category.into(),
        severity: "high".into(),
        enabled: true,
        action,
        matcher_json: matcher.into(),
        created_at: String::new(),
        updated_at: String::new(),
    }
}

fn context(path: &str, query: &str, body: &str) -> InspectionContext {
    InspectionContext {
        method: "GET".into(),
        path: path.into(),
        query: query.into(),
        headers: vec![("content-type".into(), "text/plain".into())],
        body: body.as_bytes().to_vec(),
    }
}

#[test]
fn builtins_match_sql_xss_traversal_and_command_signatures() {
    let rules = [
        rule(
            "sqli",
            r#"{"field":"any","builtin":"sqli"}"#,
            WafAction::Inherit,
        ),
        rule(
            "xss",
            r#"{"field":"any","builtin":"xss"}"#,
            WafAction::Inherit,
        ),
        rule(
            "path_traversal",
            r#"{"field":"path","builtin":"path_traversal"}"#,
            WafAction::Inherit,
        ),
        rule(
            "command_injection",
            r#"{"field":"any","builtin":"command_injection"}"#,
            WafAction::Inherit,
        ),
    ];
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::MonitorOnly,
            updated_at: String::new(),
        },
        rules.to_vec(),
    )
    .unwrap();
    let result = evaluate(
        &snapshot,
        &context(
            "/../../etc/passwd",
            "q=' OR 1=1",
            "<script>alert(1)</script>; cat /etc/passwd",
        ),
    );
    assert_eq!(result.decision, WafDecision::Log);
    assert_eq!(result.matched_rule_ids.len(), 4);
}

#[test]
fn monitor_only_logs_matches_while_block_mode_blocks() {
    let rules = vec![rule(
        "custom",
        r#"{"field":"query","pattern":"evil"}"#,
        WafAction::Inherit,
    )];
    let monitor = compile_snapshot(
        WafConfig {
            mode: WafMode::MonitorOnly,
            updated_at: String::new(),
        },
        rules.clone(),
    )
    .unwrap();
    assert_eq!(
        evaluate(&monitor, &context("/", "q=evil", "")).decision,
        WafDecision::Log
    );
    let block = compile_snapshot(
        WafConfig {
            mode: WafMode::Block,
            updated_at: String::new(),
        },
        rules,
    )
    .unwrap();
    assert_eq!(
        evaluate(&block, &context("/", "q=evil", "")).decision,
        WafDecision::Block
    );
}

#[test]
fn disabled_rules_do_not_match_and_precedence_is_deterministic() {
    let mut disabled = rule(
        "disabled",
        r#"{"field":"query","pattern":"evil"}"#,
        WafAction::Block,
    );
    disabled.enabled = false;
    let allow = rule(
        "allow",
        r#"{"field":"query","pattern":"evil"}"#,
        WafAction::Allow,
    );
    let block = rule(
        "block",
        r#"{"field":"query","pattern":"evil"}"#,
        WafAction::Block,
    );
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::MonitorOnly,
            updated_at: String::new(),
        },
        vec![disabled, allow, block],
    )
    .unwrap();
    let result = evaluate(&snapshot, &context("/", "q=evil", ""));
    assert_eq!(result.decision, WafDecision::Block);
    assert_eq!(result.matched_rule_ids, vec![1, 1]);
}

#[test]
fn invalid_regex_is_rejected_and_runtime_diagnostics_are_sanitized() {
    let invalid = rule(
        "custom",
        r#"{"field":"query","pattern":"("}"#,
        WafAction::Block,
    );
    let error = compile_snapshot(
        WafConfig {
            mode: WafMode::Block,
            updated_at: String::new(),
        },
        vec![invalid],
    )
    .unwrap_err();
    assert_eq!(error, "invalid matcher definition");
}

#[test]
fn normalized_one_level_percent_decoding_matches_custom_signatures() {
    let rules = vec![rule(
        "custom",
        r#"{"field":"query","pattern":"../"}"#,
        WafAction::Block,
    )];
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::Block,
            updated_at: String::new(),
        },
        rules,
    )
    .unwrap();
    let result = evaluate(&snapshot, &context("/", "file=%2e%2e%2fsecret", ""));
    assert_eq!(result.decision, WafDecision::Block);
}

#[test]
fn normalized_case_folding_and_separator_normalization_match_builtins() {
    let rules = vec![rule(
        "path_traversal",
        r#"{"field":"path","builtin":"path_traversal"}"#,
        WafAction::Block,
    )];
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::Block,
            updated_at: String::new(),
        },
        rules,
    )
    .unwrap();
    let result = evaluate(&snapshot, &context(r"/safe/%2E%2E%5Cetc%5Cpasswd", "", ""));
    assert_eq!(result.decision, WafDecision::Block);
}

#[test]
fn normalized_malformed_encoding_tolerance_keeps_literal_input() {
    let rules = vec![rule(
        "custom",
        r#"{"field":"query","pattern":"%ZZ"}"#,
        WafAction::Block,
    )];
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::Block,
            updated_at: String::new(),
        },
        rules,
    )
    .unwrap();
    let result = evaluate(&snapshot, &context("/", "value=%ZZ", ""));
    assert_eq!(result.decision, WafDecision::Block);
}

#[test]
fn normalized_body_respects_existing_inspection_cap() {
    let rules = vec![rule(
        "custom",
        r#"{"field":"body","pattern":"needle"}"#,
        WafAction::Block,
    )];
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::Block,
            updated_at: String::new(),
        },
        rules,
    )
    .unwrap();
    let mut body = vec![b'a'; bearust::waf::MAX_INSPECTION_BODY_BYTES];
    body.extend_from_slice(b"needle");
    let result = evaluate(
        &snapshot,
        &InspectionContext {
            method: "POST".into(),
            path: "/".into(),
            query: String::new(),
            headers: Vec::new(),
            body,
        },
    );
    assert_eq!(result.decision, WafDecision::Allow);
}

#[test]
fn normalized_metadata_is_bounded_before_matching() {
    let rules = vec![rule(
        "custom",
        r#"{"field":"query","pattern":"needle"}"#,
        WafAction::Block,
    )];
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::Block,
            updated_at: String::new(),
        },
        rules,
    )
    .unwrap();
    let query = format!(
        "{}needle",
        "a".repeat(bearust::waf::MAX_NORMALIZED_FIELD_BYTES)
    );
    assert_eq!(
        evaluate(&snapshot, &context("/", &query, "")).decision,
        WafDecision::Allow
    );
}

#[test]
fn normalized_metadata_cap_respects_utf8_boundaries() {
    let rules = vec![rule(
        "custom",
        r#"{"field":"query","pattern":"needle"}"#,
        WafAction::Block,
    )];
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::Block,
            updated_at: String::new(),
        },
        rules,
    )
    .unwrap();
    let query = format!(
        "{}éneedle",
        "a".repeat(bearust::waf::MAX_NORMALIZED_FIELD_BYTES - 1)
    );
    assert_eq!(
        evaluate(&snapshot, &context("/", &query, "")).decision,
        WafDecision::Allow
    );
}

#[test]
fn normalized_header_count_is_bounded() {
    let rules = vec![rule(
        "custom",
        r#"{"field":"headers","pattern":"needle"}"#,
        WafAction::Block,
    )];
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::Block,
            updated_at: String::new(),
        },
        rules,
    )
    .unwrap();
    let mut headers: Vec<(String, String)> = (0..bearust::waf::MAX_NORMALIZED_HEADERS)
        .map(|index| (format!("x-{index}"), String::from("benign")))
        .collect();
    headers.push(("x-overflow".into(), "needle".into()));
    let context = InspectionContext {
        method: "GET".into(),
        path: "/".into(),
        query: String::new(),
        headers,
        body: Vec::new(),
    };
    assert_eq!(evaluate(&snapshot, &context).decision, WafDecision::Allow);
}

#[test]
fn semantic_sqli_is_scored_without_raw_input_in_reason() {
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::MonitorOnly,
            updated_at: String::new(),
        },
        Vec::new(),
    )
    .unwrap();
    let result = evaluate(
        &snapshot,
        &context(
            "/login",
            "id=1%20UNION%20SELECT%20password%20FROM%20users",
            "",
        ),
    );
    assert_eq!(result.decision, WafDecision::Log);
    assert_eq!(result.semantic_score, 6);
    assert_eq!(result.categories, vec!["sqli"]);
    assert_eq!(result.severity.as_deref(), Some("medium"));
    assert!(result
        .diagnostic
        .as_deref()
        .unwrap_or_default()
        .contains("sqli"));
    assert!(!result
        .diagnostic
        .as_deref()
        .unwrap_or_default()
        .contains("password"));
}

#[test]
fn semantic_xss_traversal_command_and_protocol_signals_are_stable() {
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::MonitorOnly,
            updated_at: String::new(),
        },
        Vec::new(),
    )
    .unwrap();
    let mut request = context(
        "/assets/../../etc/passwd",
        "",
        "<script>alert(1)</script>; cat /etc/passwd",
    );
    request.method = "TRACE".into();
    let result = evaluate(&snapshot, &request);
    assert_eq!(result.decision, WafDecision::Log);
    assert_eq!(result.semantic_score, 18);
    assert_eq!(
        result.categories,
        vec![
            "xss",
            "path_traversal",
            "command_injection",
            "protocol_anomaly"
        ]
    );
    assert_eq!(result.severity.as_deref(), Some("critical"));
}

#[test]
fn semantic_benign_request_is_allowed_with_no_signals() {
    let snapshot = compile_snapshot(
        WafConfig {
            mode: WafMode::Block,
            updated_at: String::new(),
        },
        Vec::new(),
    )
    .unwrap();
    let result = evaluate(
        &snapshot,
        &context("/products", "page=2&sort=name", "hello world"),
    );
    assert_eq!(result.decision, WafDecision::Allow);
    assert_eq!(result.semantic_score, 0);
    assert!(result.categories.is_empty());
    assert!(result.severity.is_none());
    assert!(result.diagnostic.is_none());
}

#[test]
fn semantic_score_reaches_block_threshold_only_in_block_mode() {
    let monitor = compile_snapshot(
        WafConfig {
            mode: WafMode::MonitorOnly,
            updated_at: String::new(),
        },
        Vec::new(),
    )
    .unwrap();
    let block = compile_snapshot(
        WafConfig {
            mode: WafMode::Block,
            updated_at: String::new(),
        },
        Vec::new(),
    )
    .unwrap();
    let request = context("/download/../../etc/passwd", "q=1%20OR%201=1", "");
    assert_eq!(evaluate(&monitor, &request).decision, WafDecision::Log);
    assert_eq!(evaluate(&block, &request).decision, WafDecision::Block);
}
