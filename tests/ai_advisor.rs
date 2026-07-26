use async_trait::async_trait;
use bearust::ai_advisor::{
    AdvisorConfigError, AdvisorStatus, AiAdvisorService, DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
    DEFAULT_QUEUE_CAPACITY, DEFAULT_REQUEST_TIMEOUT, DEFAULT_RESPONSE_LIMIT_BYTES,
    DEFAULT_WORKER_COUNT,
};
use bearust::ai_advisor_provider::{
    ChatChoice, ChatCompletionRequest, ChatCompletionResponse, ChatMessage, LlmProvider,
    ProviderError,
};
use serde_json::json;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

struct TestProvider {
    calls: Arc<AtomicUsize>,
    delay: Duration,
}
#[async_trait]
impl LlmProvider for TestProvider {
    async fn complete(
        &self,
        _: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        tokio::time::sleep(self.delay).await;
        Ok(ChatCompletionResponse {
            id: "x".into(),
            choices: vec![ChatChoice {
                message: ChatMessage {
                    content: serde_json::json!({
                        "workflow": "incident_explanation",
                        "summary": "Validated test insight",
                        "severity": "info",
                        "signals": [],
                        "reason_ids": [],
                        "score": 0
                    })
                    .to_string(),
                },
            }],
        })
    }
}

struct BlockingProvider {
    started: Arc<tokio::sync::Notify>,
}
#[async_trait]
impl LlmProvider for BlockingProvider {
    async fn complete(
        &self,
        _: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError> {
        self.started.notify_one();
        std::future::pending().await
    }
}

fn enabled_service() -> AiAdvisorService {
    AiAdvisorService::from_env_with(|name| match name {
        "LLM_API_URL" => Some("https://llm.example.test".into()),
        "LLM_API_KEY" => Some("key".into()),
        _ => None,
    })
    .unwrap()
}

fn request() -> bearust::ai_advisor::AdvisorRequest {
    bearust::ai_advisor::AdvisorRequest {
        workflow: bearust::ai_advisor::AdvisorWorkflow::IncidentExplanation,
        host_id: None,
        from: None,
        to: None,
        command: Some("hello".into()),
    }
}

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

#[tokio::test]
async fn bounded_queue_reports_terminal_result_once_and_shutdowns() {
    let calls = Arc::new(AtomicUsize::new(0));
    let service = enabled_service().with_provider(
        Arc::new(TestProvider {
            calls: calls.clone(),
            delay: Duration::from_millis(5),
        }),
        1,
        1,
    );
    let job = service.enqueue(request()).unwrap();
    tokio::time::sleep(Duration::from_millis(30)).await;
    let result = service.result(&job).unwrap();
    assert_eq!(
        result.status,
        bearust::ai_advisor::AdvisorJobStatus::Completed
    );
    assert_eq!(service.result(&job).unwrap().status, result.status);
    service.shutdown();
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn bounded_queue_rejects_when_capacity_is_full() {
    let service = enabled_service().with_provider(
        Arc::new(TestProvider {
            calls: Arc::new(AtomicUsize::new(0)),
            delay: Duration::from_secs(1),
        }),
        1,
        1,
    );
    let _ = service.enqueue(request()).unwrap();
    let second = service.enqueue(request());
    assert!(matches!(
        second,
        Err(bearust::ai_advisor::AdvisorErrorCode::Busy)
    ));
    service.shutdown();
}

#[tokio::test]
async fn shutdown_cancels_inflight_job_to_one_terminal_result() {
    let started = Arc::new(tokio::sync::Notify::new());
    let service = enabled_service().with_provider(
        Arc::new(BlockingProvider {
            started: started.clone(),
        }),
        2,
        1,
    );
    let job = service.enqueue(request()).unwrap();
    started.notified().await;
    service.shutdown();
    tokio::time::sleep(Duration::from_millis(20)).await;
    let result = service.result(&job).unwrap();
    assert_eq!(result.status, bearust::ai_advisor::AdvisorJobStatus::Failed);
    assert_eq!(
        result.error_code,
        Some(bearust::ai_advisor::AdvisorErrorCode::Timeout)
    );
}
