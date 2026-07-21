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
        rule("sqli", r#"{"field":"any","builtin":"sqli"}"#, WafAction::Inherit),
        rule("xss", r#"{"field":"any","builtin":"xss"}"#, WafAction::Inherit),
        rule("path_traversal", r#"{"field":"path","builtin":"path_traversal"}"#, WafAction::Inherit),
        rule("command_injection", r#"{"field":"any","builtin":"command_injection"}"#, WafAction::Inherit),
    ];
    let snapshot = compile_snapshot(WafConfig { mode: WafMode::MonitorOnly, updated_at: String::new() }, rules.to_vec()).unwrap();
    let result = evaluate(&snapshot, &context("/../../etc/passwd", "q=' OR 1=1", "<script>alert(1)</script>; cat /etc/passwd"));
    assert_eq!(result.decision, WafDecision::Log);
    assert_eq!(result.matched_rule_ids.len(), 4);
}

#[test]
fn monitor_only_logs_matches_while_block_mode_blocks() {
    let rules = vec![rule("custom", r#"{"field":"query","pattern":"evil"}"#, WafAction::Inherit)];
    let monitor = compile_snapshot(WafConfig { mode: WafMode::MonitorOnly, updated_at: String::new() }, rules.clone()).unwrap();
    assert_eq!(evaluate(&monitor, &context("/", "q=evil", "")).decision, WafDecision::Log);
    let block = compile_snapshot(WafConfig { mode: WafMode::Block, updated_at: String::new() }, rules).unwrap();
    assert_eq!(evaluate(&block, &context("/", "q=evil", "")).decision, WafDecision::Block);
}

#[test]
fn disabled_rules_do_not_match_and_precedence_is_deterministic() {
    let mut disabled = rule("disabled", r#"{"field":"query","pattern":"evil"}"#, WafAction::Block);
    disabled.enabled = false;
    let allow = rule("allow", r#"{"field":"query","pattern":"evil"}"#, WafAction::Allow);
    let block = rule("block", r#"{"field":"query","pattern":"evil"}"#, WafAction::Block);
    let snapshot = compile_snapshot(WafConfig { mode: WafMode::MonitorOnly, updated_at: String::new() }, vec![disabled, allow, block]).unwrap();
    let result = evaluate(&snapshot, &context("/", "q=evil", ""));
    assert_eq!(result.decision, WafDecision::Block);
    assert_eq!(result.matched_rule_ids, vec![1, 1]);
}

#[test]
fn invalid_regex_is_rejected_and_runtime_diagnostics_are_sanitized() {
    let invalid = rule("custom", r#"{"field":"query","pattern":"("}"#, WafAction::Block);
    let error = compile_snapshot(WafConfig { mode: WafMode::Block, updated_at: String::new() }, vec![invalid]).unwrap_err();
    assert_eq!(error, "invalid matcher definition");
}

