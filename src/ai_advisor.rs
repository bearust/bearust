//! Domain contracts and safe configuration for the optional AI Advisor.
//!
//! This module deliberately has no provider client or worker in the initial
//! increment.  A disabled service is therefore allocation-light and cannot
//! affect the proxy request path.
#[path = "ai_advisor_redaction.rs"]
mod redaction;

use crate::ai_advisor_provider::{ChatCompletionMessage, ChatCompletionRequest, LlmProvider};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::{fmt, sync::Arc, time::Duration};
use tokio::sync::mpsc;
use tokio::sync::watch;
use uuid::Uuid;

pub use redaction::{
    ProviderGuard, RedactedValue, Redactor, MAX_REDACTED_JSON_BYTES, MAX_REDACTION_INPUT_BYTES,
};

pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
pub const DEFAULT_RESPONSE_LIMIT_BYTES: usize = 2 * 1024 * 1024;
pub const DEFAULT_QUEUE_CAPACITY: usize = 32;
pub const DEFAULT_WORKER_COUNT: usize = 2;
pub const DEFAULT_CIRCUIT_FAILURE_THRESHOLD: u8 = 3;
pub const MAX_ADVISOR_COMMAND_BYTES: usize = 4 * 1024;
pub const MAX_ADVISOR_RESULT_BYTES: usize = 64 * 1024;

const DEFAULT_MODEL: &str = "gpt-4o-mini";
const MAX_API_KEY_BYTES: usize = 4096;
const MAX_MODEL_BYTES: usize = 128;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisorWorkflow {
    IncidentExplanation,
    SecuritySummary,
    RuleTuning,
    ConfigurationDraft,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AdvisorJobId(pub String);

impl AdvisorJobId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }
}

impl Default for AdvisorJobId {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisorJobStatus {
    Queued,
    Running,
    Completed,
    Failed,
    Approved,
    Rejected,
    Expired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AdvisorErrorCode {
    #[serde(rename = "advisor_disabled")]
    Disabled,
    #[serde(rename = "advisor_busy")]
    Busy,
    #[serde(rename = "advisor_timeout")]
    Timeout,
    #[serde(rename = "advisor_provider_unavailable")]
    ProviderUnavailable,
    #[serde(rename = "advisor_invalid_response")]
    InvalidResponse,
    #[serde(rename = "advisor_response_too_large")]
    ResponseTooLarge,
    #[serde(rename = "advisor_circuit_open")]
    CircuitOpen,
    #[serde(rename = "advisor_invalid_request")]
    InvalidRequest,
    #[serde(rename = "advisor_stale_draft")]
    StaleDraft,
    #[serde(rename = "advisor_expired")]
    Expired,
}

/// A request envelope that future queue and persistence layers can safely
/// accept after [`Self::validate`] succeeds.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdvisorRequest {
    pub workflow: AdvisorWorkflow,
    pub host_id: Option<i64>,
    pub from: Option<DateTime<Utc>>,
    pub to: Option<DateTime<Utc>>,
    pub command: Option<String>,
}

impl AdvisorRequest {
    pub fn validate(&self) -> Result<(), AdvisorErrorCode> {
        if self
            .command
            .as_deref()
            .is_some_and(|command| command.len() > MAX_ADVISOR_COMMAND_BYTES)
            || self.from.zip(self.to).is_some_and(|(from, to)| from > to)
        {
            return Err(AdvisorErrorCode::InvalidRequest);
        }
        Ok(())
    }
}

/// Stable, provider-neutral response envelope. Provider text is introduced
/// only after later redaction and schema-validation stages.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdvisorResponse {
    pub job_id: AdvisorJobId,
    pub status: AdvisorJobStatus,
    pub error_code: Option<AdvisorErrorCode>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdvisorStatus {
    pub enabled: bool,
}

/// Sanitized reasons for declining a provider configuration. Neither the
/// original environment value nor an API key is retained in this error.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum AdvisorConfigError {
    #[error("AI advisor provider configuration is incomplete")]
    MissingRequired,
    #[error("AI advisor provider URL is invalid")]
    InvalidUrl,
    #[error("AI advisor provider configuration is invalid")]
    InvalidValue,
}

#[derive(Clone)]
pub struct AdvisorConfig {
    endpoint: Arc<str>,
    api_key: Secret,
    pub model: Arc<str>,
    pub request_timeout: Duration,
    pub response_limit_bytes: usize,
    pub queue_capacity: usize,
    pub worker_count: usize,
    pub circuit_failure_threshold: u8,
}

impl fmt::Debug for AdvisorConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AdvisorConfig")
            .field("endpoint", &self.endpoint)
            .field("api_key", &self.api_key)
            .field("model", &self.model)
            .field("request_timeout", &self.request_timeout)
            .field("response_limit_bytes", &self.response_limit_bytes)
            .field("queue_capacity", &self.queue_capacity)
            .field("worker_count", &self.worker_count)
            .field("circuit_failure_threshold", &self.circuit_failure_threshold)
            .finish()
    }
}

impl AdvisorConfig {
    pub fn chat_completions_url(&self) -> &str {
        &self.endpoint
    }

    /// Provider adapters should use this only to construct an authorization
    /// header and must never log or serialize the returned secret.
    #[allow(dead_code)] // Used by the provider adapter added in the next increment.
    pub(crate) fn api_key(&self) -> &str {
        self.api_key.expose()
    }
}

#[derive(Clone)]
struct Secret(#[allow(dead_code)] Arc<str>);

impl Secret {
    #[allow(dead_code)]
    fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Optional advisor service. It intentionally owns no workers until the
/// provider/queue increment attaches them; cloning simply clones an `Arc`.
#[derive(Clone, Default)]
pub struct AiAdvisorService {
    config: Option<Arc<AdvisorConfig>>,
    runtime: Option<Arc<AdvisorRuntime>>,
}

struct AdvisorRuntime {
    sender: mpsc::Sender<(AdvisorJobId, AdvisorRequest)>,
    results: Arc<std::sync::Mutex<HashMap<String, AdvisorResponse>>>,
    terminal_order: Arc<std::sync::Mutex<VecDeque<String>>>,
    shutdown: watch::Sender<bool>,
}

const MAX_RETAINED_ADVISOR_RESULTS: usize = 1024;

fn store_result(
    results: &std::sync::Mutex<HashMap<String, AdvisorResponse>>,
    terminal_order: &std::sync::Mutex<VecDeque<String>>,
    response: AdvisorResponse,
) -> bool {
    let mut results = results.lock().unwrap();
    let is_terminal = |status| {
        matches!(
            status,
            AdvisorJobStatus::Completed
                | AdvisorJobStatus::Failed
                | AdvisorJobStatus::Approved
                | AdvisorJobStatus::Rejected
                | AdvisorJobStatus::Expired
        )
    };
    if results
        .get(&response.job_id.0)
        .is_some_and(|existing| is_terminal(existing.status))
    {
        return false;
    }

    let terminal = is_terminal(response.status);
    if terminal {
        let mut order = terminal_order.lock().unwrap();
        order.push_back(response.job_id.0.clone());
        while order.len() > MAX_RETAINED_ADVISOR_RESULTS {
            if let Some(old) = order.pop_front() {
                if results
                    .get(&old)
                    .is_some_and(|existing| is_terminal(existing.status))
                {
                    results.remove(&old);
                }
            }
        }
    }
    results.insert(response.job_id.0.clone(), response);
    true
}

fn remove_queued_result(
    results: &std::sync::Mutex<HashMap<String, AdvisorResponse>>,
    job_id: &AdvisorJobId,
) {
    let mut results = results.lock().unwrap();
    if matches!(
        results.get(&job_id.0).map(|response| response.status),
        Some(AdvisorJobStatus::Queued)
    ) {
        results.remove(&job_id.0);
    }
}

impl fmt::Debug for AiAdvisorService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AiAdvisorService")
            .field("enabled", &self.config.is_some())
            .finish()
    }
}

impl AiAdvisorService {
    pub fn disabled() -> Self {
        Self::default()
    }

    pub fn from_env() -> Result<Self, AdvisorConfigError> {
        Self::from_env_with(|name| std::env::var(name).ok())
    }

    pub fn with_provider(
        mut self,
        provider: Arc<dyn LlmProvider>,
        capacity: usize,
        worker_count: usize,
    ) -> Self {
        let (sender, mut receiver) =
            mpsc::channel::<(AdvisorJobId, AdvisorRequest)>(capacity.max(1));
        let results = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let terminal_order = Arc::new(std::sync::Mutex::new(VecDeque::new()));
        let worker_terminal_order = terminal_order.clone();
        let (shutdown, mut worker_shutdown) = watch::channel(false);
        let worker_results = results.clone();
        let concurrency = Arc::new(tokio::sync::Semaphore::new(worker_count.max(1)));
        tokio::spawn(async move {
            loop {
                if *worker_shutdown.borrow() {
                    while let Ok((queued_id, _)) = receiver.try_recv() {
                        store_result(
                            &worker_results,
                            &worker_terminal_order,
                            AdvisorResponse {
                                job_id: queued_id,
                                status: AdvisorJobStatus::Failed,
                                error_code: Some(AdvisorErrorCode::Timeout),
                            },
                        );
                    }
                    break;
                }
                let next = tokio::select! {
                    value = receiver.recv() => value,
                    _ = worker_shutdown.changed() => None,
                };
                let Some((job_id, request)) = next else {
                    while let Ok((queued_id, _)) = receiver.try_recv() {
                        store_result(
                            &worker_results,
                            &worker_terminal_order,
                            AdvisorResponse {
                                job_id: queued_id,
                                status: AdvisorJobStatus::Failed,
                                error_code: Some(AdvisorErrorCode::Timeout),
                            },
                        );
                    }
                    break;
                };
                store_result(
                    &worker_results,
                    &worker_terminal_order,
                    AdvisorResponse {
                        job_id: job_id.clone(),
                        status: AdvisorJobStatus::Running,
                        error_code: None,
                    },
                );
                let permit = tokio::select! {
                    permit = concurrency.clone().acquire_owned() => permit,
                    _ = worker_shutdown.changed() => { store_result(&worker_results, &worker_terminal_order, AdvisorResponse { job_id, status: AdvisorJobStatus::Failed, error_code: Some(AdvisorErrorCode::Timeout) }); continue; }
                };
                let Ok(_permit) = permit else { break };
                let provider = provider.clone();
                let result = tokio::select! {
                    result = provider
                        .complete(ChatCompletionRequest {
                            messages: vec![ChatCompletionMessage {
                                role: "user".into(),
                                content: request.command.unwrap_or_default(),
                            }],
                        }) => result,
                    _ = worker_shutdown.changed() => {
                        store_result(&worker_results, &worker_terminal_order, AdvisorResponse { job_id: job_id.clone(), status: AdvisorJobStatus::Failed, error_code: Some(AdvisorErrorCode::Timeout) });
                        continue;
                    },
                };
                let (status, error_code) = match result {
                    Ok(_) => (AdvisorJobStatus::Completed, None),
                    Err(_) => (
                        AdvisorJobStatus::Failed,
                        Some(AdvisorErrorCode::ProviderUnavailable),
                    ),
                };
                store_result(
                    &worker_results,
                    &worker_terminal_order,
                    AdvisorResponse {
                        job_id,
                        status,
                        error_code,
                    },
                );
            }
        });
        self.runtime = Some(Arc::new(AdvisorRuntime {
            sender,
            results,
            terminal_order,
            shutdown,
        }));
        self
    }

    /// Parses configuration through an injected lookup function so callers
    /// can test configuration without mutating process-global environment.
    pub fn from_env_with<F>(lookup: F) -> Result<Self, AdvisorConfigError>
    where
        F: Fn(&str) -> Option<String>,
    {
        let provider_url = required_value(lookup("LLM_API_URL"))?;
        let api_key = required_value(lookup("LLM_API_KEY"))?;
        if api_key.len() > MAX_API_KEY_BYTES {
            return Err(AdvisorConfigError::InvalidValue);
        }

        let model = optional_value(lookup("LLM_MODEL")).unwrap_or_else(|| DEFAULT_MODEL.to_owned());
        if model.len() > MAX_MODEL_BYTES {
            return Err(AdvisorConfigError::InvalidValue);
        }

        let config = AdvisorConfig {
            endpoint: normalize_chat_completions_url(&provider_url)?.into(),
            api_key: Secret(api_key.into()),
            model: model.into(),
            request_timeout: Duration::from_secs(parse_bounded(
                lookup("LLM_REQUEST_TIMEOUT_SECONDS"),
                DEFAULT_REQUEST_TIMEOUT.as_secs(),
                1,
                300,
            )?),
            response_limit_bytes: parse_bounded(
                lookup("LLM_RESPONSE_LIMIT_BYTES"),
                DEFAULT_RESPONSE_LIMIT_BYTES,
                1024,
                8 * 1024 * 1024,
            )?,
            queue_capacity: parse_bounded(
                lookup("LLM_QUEUE_CAPACITY"),
                DEFAULT_QUEUE_CAPACITY,
                1,
                1024,
            )?,
            worker_count: parse_bounded(lookup("LLM_WORKER_COUNT"), DEFAULT_WORKER_COUNT, 1, 16)?,
            circuit_failure_threshold: parse_bounded(
                lookup("LLM_CIRCUIT_FAILURE_THRESHOLD"),
                DEFAULT_CIRCUIT_FAILURE_THRESHOLD,
                1,
                10,
            )?,
        };

        Ok(Self {
            config: Some(Arc::new(config)),
            runtime: None,
        })
    }

    pub fn status(&self) -> AdvisorStatus {
        AdvisorStatus {
            enabled: self.config.is_some(),
        }
    }

    pub fn config(&self) -> Option<&AdvisorConfig> {
        self.config.as_deref()
    }

    pub fn enqueue(&self, request: AdvisorRequest) -> Result<AdvisorJobId, AdvisorErrorCode> {
        request.validate()?;
        let runtime = self.runtime.as_ref().ok_or(AdvisorErrorCode::Disabled)?;
        let id = AdvisorJobId::new();
        store_result(
            &runtime.results,
            &runtime.terminal_order,
            AdvisorResponse {
                job_id: id.clone(),
                status: AdvisorJobStatus::Queued,
                error_code: None,
            },
        );
        match runtime.sender.try_send((id.clone(), request)) {
            Ok(()) => Ok(id),
            Err(_) => {
                remove_queued_result(&runtime.results, &id);
                Err(AdvisorErrorCode::Busy)
            }
        }
    }

    pub fn result(&self, job_id: &AdvisorJobId) -> Option<AdvisorResponse> {
        self.runtime
            .as_ref()?
            .results
            .lock()
            .ok()?
            .get(&job_id.0)
            .cloned()
    }

    pub fn shutdown(&self) {
        if let Some(runtime) = &self.runtime {
            let _ = runtime.shutdown.send(true);
        }
    }
}

fn required_value(value: Option<String>) -> Result<String, AdvisorConfigError> {
    optional_value(value).ok_or(AdvisorConfigError::MissingRequired)
}

fn optional_value(value: Option<String>) -> Option<String> {
    value.and_then(|value| {
        let value = value.trim();
        (!value.is_empty()).then(|| value.to_owned())
    })
}

fn parse_bounded<T>(
    value: Option<String>,
    default: T,
    minimum: T,
    maximum: T,
) -> Result<T, AdvisorConfigError>
where
    T: std::str::FromStr + PartialOrd + Copy,
{
    let Some(value) = optional_value(value) else {
        return Ok(default);
    };
    let value = value
        .parse::<T>()
        .map_err(|_| AdvisorConfigError::InvalidValue)?;
    if value < minimum || value > maximum {
        return Err(AdvisorConfigError::InvalidValue);
    }
    Ok(value)
}

fn normalize_chat_completions_url(value: &str) -> Result<String, AdvisorConfigError> {
    let mut parsed = reqwest::Url::parse(value).map_err(|_| AdvisorConfigError::InvalidUrl)?;
    if !matches!(parsed.scheme(), "http" | "https")
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(AdvisorConfigError::InvalidUrl);
    }

    let normalized_path = parsed.path().trim_end_matches('/').to_owned();
    parsed.set_path(&normalized_path);
    let base = parsed.as_str().trim_end_matches('/');
    if base.ends_with("/v1/chat/completions") {
        Ok(base.to_owned())
    } else if base.ends_with("/v1") {
        Ok(format!("{base}/chat/completions"))
    } else {
        Ok(format!("{base}/v1/chat/completions"))
    }
}

#[cfg(test)]
mod worker_state_tests {
    use super::*;
    use crate::ai_advisor_provider::{ChatCompletionResponse, ProviderError};
    use async_trait::async_trait;

    struct PendingProvider {
        started: Arc<tokio::sync::Notify>,
    }

    #[async_trait]
    impl LlmProvider for PendingProvider {
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

    fn request() -> AdvisorRequest {
        AdvisorRequest {
            workflow: AdvisorWorkflow::IncidentExplanation,
            host_id: None,
            from: None,
            to: None,
            command: Some("hello".into()),
        }
    }

    fn response(id: impl Into<String>, status: AdvisorJobStatus) -> AdvisorResponse {
        AdvisorResponse {
            job_id: AdvisorJobId(id.into()),
            status,
            error_code: None,
        }
    }

    #[tokio::test]
    async fn repeated_rejected_enqueue_rolls_back_every_queued_state() {
        let started = Arc::new(tokio::sync::Notify::new());
        let service = enabled_service().with_provider(
            Arc::new(PendingProvider {
                started: Arc::clone(&started),
            }),
            1,
            1,
        );
        let running = service.enqueue(request()).unwrap();
        tokio::time::timeout(Duration::from_secs(1), started.notified())
            .await
            .unwrap();
        let queued = service.enqueue(request()).unwrap();

        for _ in 0..2048 {
            assert_eq!(service.enqueue(request()), Err(AdvisorErrorCode::Busy));
        }

        let runtime = service.runtime.as_ref().unwrap();
        let results = runtime.results.lock().unwrap();
        assert_eq!(
            results.len(),
            2,
            "rejected enqueue attempts must not retain queued job state"
        );
        assert_eq!(
            results.get(&running.0).unwrap().status,
            AdvisorJobStatus::Running
        );
        assert_eq!(
            results.get(&queued.0).unwrap().status,
            AdvisorJobStatus::Queued
        );
        drop(results);
        service.shutdown();
    }

    #[test]
    fn second_terminal_transition_is_rejected_and_cannot_overwrite_the_first() {
        let results = std::sync::Mutex::new(HashMap::new());
        let terminal_order = std::sync::Mutex::new(VecDeque::new());
        let id = "terminal-once";

        assert!(store_result(
            &results,
            &terminal_order,
            response(id, AdvisorJobStatus::Running),
        ));
        assert!(store_result(
            &results,
            &terminal_order,
            response(id, AdvisorJobStatus::Completed),
        ));
        assert!(!store_result(
            &results,
            &terminal_order,
            AdvisorResponse {
                job_id: AdvisorJobId(id.into()),
                status: AdvisorJobStatus::Failed,
                error_code: Some(AdvisorErrorCode::Timeout),
            },
        ));

        let result = results.lock().unwrap().get(id).cloned().unwrap();
        assert_eq!(result.status, AdvisorJobStatus::Completed);
        assert_eq!(result.error_code, None);
        assert_eq!(
            terminal_order.lock().unwrap().iter().collect::<Vec<_>>(),
            vec![id]
        );
    }

    #[test]
    fn retention_evicts_oldest_terminal_only_and_preserves_active_jobs() {
        let results = std::sync::Mutex::new(HashMap::new());
        let terminal_order = std::sync::Mutex::new(VecDeque::new());
        store_result(
            &results,
            &terminal_order,
            response("active-queued", AdvisorJobStatus::Queued),
        );
        store_result(
            &results,
            &terminal_order,
            response("active-running", AdvisorJobStatus::Running),
        );

        for index in 0..=MAX_RETAINED_ADVISOR_RESULTS {
            store_result(
                &results,
                &terminal_order,
                response(format!("terminal-{index:04}"), AdvisorJobStatus::Completed),
            );
        }

        let results = results.lock().unwrap();
        assert_eq!(results.len(), MAX_RETAINED_ADVISOR_RESULTS + 2);
        assert_eq!(
            results.get("active-queued").unwrap().status,
            AdvisorJobStatus::Queued
        );
        assert_eq!(
            results.get("active-running").unwrap().status,
            AdvisorJobStatus::Running
        );
        assert!(!results.contains_key("terminal-0000"));
        assert!(results.contains_key("terminal-0001"));
        assert!(results.contains_key("terminal-1024"));
        drop(results);

        let terminal_order = terminal_order.lock().unwrap();
        assert_eq!(terminal_order.len(), MAX_RETAINED_ADVISOR_RESULTS);
        assert_eq!(terminal_order.front().unwrap(), "terminal-0001");
        assert_eq!(terminal_order.back().unwrap(), "terminal-1024");
    }
}
