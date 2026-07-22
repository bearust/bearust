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
fn fingerprint_uses_hmac_keyed_hashing() {
    let context = BotInspectionContext::new("GET", "/", vec![]);
    let fingerprint = context.fingerprint(b"key");
    let expected = hex::encode({
        use hmac::{Hmac, Mac};
        use sha2::Sha256;
        let mut mac = Hmac::<Sha256>::new_from_slice(b"key").unwrap();
        mac.update(b"GET");
        mac.update(&[0]);
        mac.update(b"/");
        mac.update(&[0]);
        mac.finalize().into_bytes()
    });
    assert_eq!(fingerprint, expected);
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
            ("Host".into(), "crawl.googlebot.com".into()),
        ],
    )
    .with_verified_trusted_source();
    let first = evaluate(&snapshot, &context);
    let second = evaluate(&snapshot, &context);
    assert_eq!(first.score, second.score);
    assert!(first.trusted);
    assert_eq!(first.action, BotAction::Allow);
}

#[test]
fn trusted_crawler_requires_both_strict_ua_and_host_predicates() {
    let snapshot = compile_snapshot(
        config(BotMode::Block),
        vec![BotRule::trusted_crawler("Googlebot", "googlebot.com")],
    )
    .unwrap();
    let missing_host = BotInspectionContext::new("GET", "/", vec![("User-Agent".into(), "Googlebot".into())]);
    assert!(!evaluate(&snapshot, &missing_host).trusted);
    let ip_bypass = BotInspectionContext::new("GET", "/", vec![("User-Agent".into(), "Googlebot".into()), ("X-Forwarded-For".into(), "googlebot.com".into())]);
    assert!(!evaluate(&snapshot, &ip_bypass).trusted);
    let wrong_host = BotInspectionContext::new("GET", "/", vec![("User-Agent".into(), "Googlebot".into()), ("Host".into(), "evilgooglebot.com".into())]);
    assert!(!evaluate(&snapshot, &wrong_host).trusted);
    let ip_host = BotInspectionContext::new("GET", "/", vec![("User-Agent".into(), "Googlebot".into()), ("Host".into(), "66.249.66.1".into())]);
    assert!(!evaluate(&snapshot, &ip_host).trusted);
}

#[test]
fn trusted_crawler_requires_verified_proxy_source() {
    let snapshot = compile_snapshot(
        config(BotMode::Block),
        vec![
            BotRule::trusted_crawler("Googlebot", "googlebot.com"),
            BotRule::signal("ua_missing", 100),
        ],
    )
    .unwrap();
    let spoofed = BotInspectionContext::new(
        "GET", "/", vec![("User-Agent".into(), "Googlebot/2.1".into()), ("Host".into(), "crawl.googlebot.com".into())],
    );
    assert!(!evaluate(&snapshot, &spoofed).trusted);
    let verified = spoofed.with_verified_trusted_source();
    assert!(evaluate(&snapshot, &verified).trusted);
}

#[test]
fn header_cap_applies_after_allowlist_filtering_and_score_is_capped() {
    let mut headers = (0..MAX_HEADERS).map(|i| (format!("x-noise-{i}"), "x".into())).collect::<Vec<_>>();
    headers.push(("User-Agent".into(), "bot".into()));
    let context = BotInspectionContext::new("GET", "/", headers);
    assert_eq!(context.headers.len(), 1);
    let rules = (0..MAX_RULES).map(|_| BotRule::signal("ua_missing", u16::MAX)).collect();
    let snapshot = compile_snapshot(config(BotMode::Block), rules).unwrap();
    let result = evaluate(&snapshot, &BotInspectionContext::new("GET", "/", vec![]));
    assert_eq!(result.score, MAX_SCORE);
}

#[test]
fn rejects_empty_fingerprint_and_trusted_predicates_and_preserves_utf8() {
    let mut invalid = config(BotMode::Block);
    invalid.fingerprint_key.clear();
    assert!(compile_snapshot(invalid, vec![]).is_err());
    assert!(compile_snapshot(config(BotMode::Block), vec![BotRule::trusted_crawler("", "example.com")]).is_err());
    assert!(compile_snapshot(config(BotMode::Block), vec![BotRule { trusted_user_agent: Some("Googlebot".into()), trusted_domain: None, ..BotRule::trusted_crawler("Googlebot", "example.com") }]).is_err());
    assert!(compile_snapshot(config(BotMode::Block), vec![BotRule { trusted_user_agent: None, trusted_domain: Some("example.com".into()), ..BotRule::trusted_crawler("Googlebot", "example.com") }]).is_err());
    let context = BotInspectionContext::new("GET", "/caf%C3%A9", vec![]);
    assert_eq!(context.path, "/café");
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
