//! Domain contracts and safe configuration for the optional AI Advisor.
//!
//! This module deliberately has no provider client or worker in the initial
//! increment.  A disabled service is therefore allocation-light and cannot
//! affect the proxy request path.
#[path = "ai_advisor_redaction.rs"]
mod redaction;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc, time::Duration};
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
