use bearust::ai_advisor::{
    ProviderGuard, Redactor, MAX_REDACTED_JSON_BYTES, MAX_REDACTION_INPUT_BYTES,
};
use serde_json::json;
use std::time::{Duration, Instant};

#[test]
fn nested_credentials_and_request_bodies_never_cross_the_redaction_boundary() {
    let redactor = Redactor::with_secret_keys(["custom_secret"]);
    let input = json!({
        "workflow": "security_summary",
        "event": {
            "method": "POST",
            "path": "/login",
            "headers": {
                "Authorization": "Bearer provider-token",
                "cOoKiE": "session=super-secret"
            },
            "details": {
                "password": "hunter2",
                "access_token": "token-value",
                "custom_secret": "configured-value",
                "status": 401
            },
            "body": "username=alice&password=hunter2",
            "request_body": {"credit_card": "4111111111111111"}
        }
    });

    let redacted = redactor.redact(&input);
    let value = redacted.value();
    let serialized = serde_json::to_string(value).unwrap();

    assert_eq!(
        value.pointer("/event/headers/Authorization"),
        Some(&json!("[REDACTED]"))
    );
    assert_eq!(
        value.pointer("/event/headers/cOoKiE"),
        Some(&json!("[REDACTED]"))
    );
    assert_eq!(
        value.pointer("/event/details/password"),
        Some(&json!("[REDACTED]"))
    );
    assert_eq!(
        value.pointer("/event/details/access_token"),
        Some(&json!("[REDACTED]"))
    );
    assert_eq!(
        value.pointer("/event/details/custom_secret"),
        Some(&json!("[REDACTED]"))
    );
    assert_eq!(value.pointer("/event/details/status"), Some(&json!(401)));
    assert!(value.pointer("/event/body").is_none());
    assert!(value.pointer("/event/request_body").is_none());
    for secret in [
        "provider-token",
        "super-secret",
        "hunter2",
        "token-value",
        "configured-value",
        "4111111111111111",
    ] {
        assert!(
            !serialized.contains(secret),
            "{secret} leaked: {serialized}"
        );
    }
}

#[test]
fn ip_addresses_and_private_key_blocks_are_replaced_inside_safe_text() {
    let input = json!({
        "workflow": "incident_explanation",
        "message": concat!(
            "client 192.0.2.42 connected to 2001:db8::1\n",
            "-----BEGIN PRIVATE KEY-----\n",
            "very-secret-key-material\n",
            "-----END PRIVATE KEY-----\n",
            "request denied"
        )
    });

    let redacted = Redactor::default().redact(&input);
    let message = redacted
        .value()
        .get("message")
        .and_then(serde_json::Value::as_str)
        .unwrap();

    assert_eq!(
        message,
        concat!(
            "client [REDACTED_IP] connected to [REDACTED_IP]\n",
            "[REDACTED_PRIVATE_KEY]\n",
            "request denied"
        )
    );
}

#[test]
fn redaction_and_hashing_are_deterministic_without_retaining_raw_input() {
    let first_input = json!({
        "message": "source 198.51.100.10",
        "method": "GET",
        "path": "/health"
    });
    let same_input_different_key_order = json!({
        "path": "/health",
        "method": "GET",
        "message": "source 198.51.100.10"
    });
    let changed_input = json!({
        "message": "source 198.51.100.11",
        "method": "GET",
        "path": "/health"
    });
    let redactor = Redactor::default();

    let first = redactor.redact(&first_input);
    let same = redactor.redact(&same_input_different_key_order);
    let changed = redactor.redact(&changed_input);

    assert_eq!(first.value(), same.value());
    assert_eq!(first.correlation_hash(), same.correlation_hash());
    assert_ne!(first.correlation_hash(), changed.correlation_hash());
    assert_eq!(first.correlation_hash().len(), 64);
    assert!(first
        .correlation_hash()
        .bytes()
        .all(|byte| byte.is_ascii_hexdigit()));
    assert!(!format!("{first:?}").contains("198.51.100.10"));
}

#[test]
fn serialized_output_is_bounded_and_over_large_input_is_rejected() {
    let bounded_input = json!({
        "events": (0..200)
            .map(|index| json!({
                "method": "GET",
                "path": format!("/very/long/path/{index}/{}", "x".repeat(900)),
                "status": 200
            }))
            .collect::<Vec<_>>()
    });
    let redactor = Redactor::default();
    let bounded = redactor.redact(&bounded_input);
    assert_eq!(
        bounded.value(),
        &json!({"redaction_status": "output_truncated"})
    );
    assert!(serde_json::to_vec(bounded.value()).unwrap().len() <= MAX_REDACTED_JSON_BYTES);

    let oversized = json!({"message": "x".repeat(MAX_REDACTION_INPUT_BYTES + 1)});
    let rejected = redactor.redact(&oversized);
    assert_eq!(
        rejected.value(),
        &json!({"redaction_status": "input_too_large"})
    );
    assert!(serde_json::to_vec(rejected.value()).unwrap().len() <= MAX_REDACTED_JSON_BYTES);
}

#[test]
fn provider_guard_opens_allows_one_half_open_probe_and_recovers() {
    let cooldown = Duration::from_secs(30);
    let guard = ProviderGuard::new(2, cooldown);
    let now = Instant::now();

    assert!(guard.allow_request());
    guard.record_failure(now);
    assert!(guard.allow_request());

    guard.record_failure(now);
    assert!(!guard.allow_request());

    guard.record_failure(now.checked_sub(cooldown + Duration::from_secs(1)).unwrap());
    assert!(guard.allow_request());
    assert!(!guard.allow_request());

    guard.record_failure(Instant::now());
    assert!(!guard.allow_request());

    guard.record_failure(
        Instant::now()
            .checked_sub(cooldown + Duration::from_secs(1))
            .unwrap(),
    );
    assert!(guard.allow_request());
    guard.record_success();
    assert!(guard.allow_request());

    guard.record_failure(Instant::now());
    assert!(guard.allow_request());
}
