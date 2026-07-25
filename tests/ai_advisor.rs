use bearust::ai_advisor::{
    AdvisorConfigError, AdvisorStatus, AiAdvisorService, DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
    DEFAULT_QUEUE_CAPACITY, DEFAULT_REQUEST_TIMEOUT, DEFAULT_RESPONSE_LIMIT_BYTES,
    DEFAULT_WORKER_COUNT,
};
use serde_json::json;

#[test]
fn config_requires_both_provider_environment_variables() {
    let missing_url = AiAdvisorService::from_env_with(|name| match name {
        "LLM_API_KEY" => Some("not-a-real-key".to_owned()),
        _ => None,
    });
    assert!(matches!(
        missing_url,
        Err(AdvisorConfigError::MissingRequired)
    ));

    let missing_key = AiAdvisorService::from_env_with(|name| match name {
        "LLM_API_URL" => Some("https://llm.example.test".to_owned()),
        _ => None,
    });
    assert!(matches!(
        missing_key,
        Err(AdvisorConfigError::MissingRequired)
    ));
}

#[test]
fn config_rejects_whitespace_only_provider_values() {
    let url = AiAdvisorService::from_env_with(|name| match name {
        "LLM_API_URL" => Some(" \t ".to_owned()),
        "LLM_API_KEY" => Some("not-a-real-key".to_owned()),
        _ => None,
    });
    assert!(matches!(url, Err(AdvisorConfigError::MissingRequired)));

    let key = AiAdvisorService::from_env_with(|name| match name {
        "LLM_API_URL" => Some("https://llm.example.test".to_owned()),
        "LLM_API_KEY" => Some("\n ".to_owned()),
        _ => None,
    });
    assert!(matches!(key, Err(AdvisorConfigError::MissingRequired)));
}

#[test]
fn config_normalizes_an_openai_compatible_endpoint_and_uses_finite_defaults() {
    let service = AiAdvisorService::from_env_with(|name| match name {
        "LLM_API_URL" => Some(" https://llm.example.test/custom/v1/ ".to_owned()),
        "LLM_API_KEY" => Some("not-a-real-key".to_owned()),
        _ => None,
    })
    .expect("valid provider configuration");

    let config = service.config().expect("enabled service has configuration");
    assert_eq!(
        config.chat_completions_url(),
        "https://llm.example.test/custom/v1/chat/completions"
    );
    assert_eq!(config.request_timeout, DEFAULT_REQUEST_TIMEOUT);
    assert_eq!(config.response_limit_bytes, DEFAULT_RESPONSE_LIMIT_BYTES);
    assert_eq!(config.queue_capacity, DEFAULT_QUEUE_CAPACITY);
    assert_eq!(config.worker_count, DEFAULT_WORKER_COUNT);
    assert_eq!(
        config.circuit_failure_threshold,
        DEFAULT_CIRCUIT_FAILURE_THRESHOLD
    );
    assert!(config.request_timeout > std::time::Duration::ZERO);
    assert!(config.queue_capacity > 0);
    assert!(!format!("{service:?}").contains("not-a-real-key"));
}

#[test]
fn disabled_status_serializes_without_provider_details() {
    let service = AiAdvisorService::disabled();

    assert_eq!(service.status(), AdvisorStatus { enabled: false });
    assert_eq!(
        serde_json::to_value(service.status()).unwrap(),
        json!({"enabled": false})
    );
}
