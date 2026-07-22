use bearust::bot_protection::*;

fn config(mode: BotMode) -> BotConfig {
    BotConfig {
        mode,
        threshold: 10,
        ttl_seconds: 300,
        fingerprint_key: b"test-key".to_vec(),
    }
}

#[test]
fn canonicalizes_request_fields_and_allowlisted_headers() {
    let context = BotInspectionContext::new(
        " get ",
        " /Foo/%7eBar?x=1 ",
        vec![
            ("User-Agent".into(), " Example/1.0 ".into()),
            ("Cookie".into(), "secret".into()),
        ],
    );
    assert_eq!(context.method, "GET");
    assert_eq!(context.path, "/Foo/~Bar");
    assert_eq!(
        context.headers,
        vec![("user-agent".into(), "Example/1.0".into())]
    );
}

#[test]
fn fingerprint_is_bounded_and_deterministic() {
    let context = BotInspectionContext::new("GET", "/", vec![("User-Agent".into(), "bot".into())]);
    let a = context.fingerprint(b"key");
    assert_eq!(a, context.fingerprint(b"key"));
    assert_eq!(a.len(), 64);
    let huge = BotInspectionContext::new("GET", &"x".repeat(10_000), vec![]);
    assert!(huge.path.len() <= MAX_FIELD_BYTES);
}

#[test]
fn deterministic_score_and_trusted_crawler_match() {
    let snapshot = compile_snapshot(
        config(BotMode::Block),
        vec![BotRule::trusted_crawler("Googlebot", "googlebot.com")],
    )
    .unwrap();
    let context = BotInspectionContext::new(
        "GET",
        "/",
        vec![
            ("User-Agent".into(), "Googlebot/2.1".into()),
            ("X-Forwarded-For".into(), "66.249.66.1".into()),
        ],
    );
    let first = evaluate(&snapshot, &context);
    let second = evaluate(&snapshot, &context);
    assert_eq!(first.score, second.score);
    assert!(first.trusted);
    assert_eq!(first.action, BotAction::Allow);
}

#[test]
fn maps_monitor_challenge_and_block_modes() {
    let context = BotInspectionContext::new("GET", "/", vec![]);
    for (mode, expected) in [
        (BotMode::Monitor, BotAction::Monitor),
        (BotMode::Challenge, BotAction::Challenge),
        (BotMode::Block, BotAction::Block),
    ] {
        let snapshot =
            compile_snapshot(config(mode), vec![BotRule::signal("ua_missing", 20)]).unwrap();
        assert_eq!(evaluate(&snapshot, &context).action, expected);
    }
}

#[test]
fn rejects_invalid_snapshot_limits() {
    assert!(compile_snapshot(
        BotConfig {
            mode: BotMode::Block,
            threshold: 0,
            ttl_seconds: 1,
            fingerprint_key: vec![1]
        },
        vec![]
    )
    .is_err());
    assert!(compile_snapshot(
        BotConfig {
            mode: BotMode::Block,
            threshold: 1,
            ttl_seconds: 0,
            fingerprint_key: vec![1]
        },
        vec![]
    )
    .is_err());
}
