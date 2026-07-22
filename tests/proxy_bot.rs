use bearust::{
    bot_challenge::ChallengeService,
    bot_protection::{
        compile_snapshot, evaluate, BotConfig, BotInspectionContext, BotMode, BotRule,
    },
};

#[tokio::test]
async fn clearance_token_binds_to_fingerprint_and_expires() {
    let service = ChallengeService::from_key(b"proxy-test-key".to_vec()).unwrap();
    let token = service.issue_clearance("abcdef0123456789", 100).unwrap();
    assert!(service
        .verify_clearance(&token, "abcdef0123456789-rest", 101)
        .is_ok());
    assert!(service.verify_clearance(&token, "different", 101).is_err());
    assert!(service
        .verify_clearance(&token, "abcdef0123456789", 401)
        .is_err());
}

#[test]
fn trusted_crawler_is_allowed_even_when_block_mode_is_configured() {
    let snapshot = compile_snapshot(
        BotConfig {
            mode: BotMode::Block,
            threshold: 1,
            ttl_seconds: 300,
            fingerprint_key: b"proxy-test-key".to_vec(),
        },
        vec![
            BotRule::trusted_crawler("Googlebot", "googlebot.com"),
            BotRule::signal("ua_missing", 100),
        ],
    )
    .unwrap();
    let context = BotInspectionContext::new(
        "GET",
        "/",
        vec![
            ("User-Agent".into(), "Googlebot/2.1".into()),
            ("Host".into(), "crawl.googlebot.com".into()),
        ],
    );
    assert!(!evaluate(&snapshot, &context).trusted);
    assert!(evaluate(&snapshot, &context.with_verified_trusted_source()).trusted);
}

#[test]
fn proxy_bot_modes_keep_response_contract_actions() {
    let context = BotInspectionContext::new("GET", "/", vec![]);
    for (mode, expected) in [
        (BotMode::Monitor, bearust::bot_protection::BotAction::Monitor),
        (BotMode::Challenge, bearust::bot_protection::BotAction::Challenge),
        (BotMode::Block, bearust::bot_protection::BotAction::Block),
    ] {
        let snapshot = compile_snapshot(
            BotConfig { mode, threshold: 1, ttl_seconds: 300, fingerprint_key: b"proxy-test-key".to_vec() },
            vec![BotRule::signal("ua_missing", 100)],
        ).unwrap();
        assert_eq!(evaluate(&snapshot, &context).action, expected);
    }
}
