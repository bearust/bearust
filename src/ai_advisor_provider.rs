use crate::ai_advisor::{ProviderGuard, Redactor};
use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{fmt, sync::Arc, time::Duration};
use thiserror::Error;

#[derive(Clone)]
pub struct ProviderConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub request_timeout: Duration,
    pub response_limit_bytes: usize,
    pub guard: Arc<ProviderGuard>,
}

impl fmt::Debug for ProviderConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProviderConfig")
            .field("base_url", &self.base_url)
            .field("api_key", &"[REDACTED]")
            .field("model", &self.model)
            .field("request_timeout", &self.request_timeout)
            .field("response_limit_bytes", &self.response_limit_bytes)
            .finish()
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatCompletionRequest {
    pub messages: Vec<ChatCompletionMessage>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatCompletionMessage {
    pub role: String,
    pub content: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ChatCompletionResponse {
    pub id: String,
    pub choices: Vec<ChatChoice>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ChatChoice {
    pub message: ChatMessage,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ChatMessage {
    pub content: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProviderError {
    #[error("provider circuit is open")]
    CircuitOpen,
    #[error("provider request timed out")]
    Timeout,
    #[error("provider is unavailable")]
    Unavailable,
    #[error("provider returned HTTP status {0}")]
    HttpStatus(u16),
    #[error("provider response is malformed")]
    InvalidResponse,
    #[error("provider response exceeds configured limit")]
    ResponseTooLarge,
}

#[async_trait]
pub trait LlmProvider: Send + Sync {
    async fn complete(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError>;
}

pub struct OpenAiCompatibleProvider {
    client: Client,
    config: ProviderConfig,
}

impl OpenAiCompatibleProvider {
    pub fn new(client: Client, config: ProviderConfig) -> Self {
        Self { client, config }
    }

    fn endpoint(&self) -> String {
        format!(
            "{}/v1/chat/completions",
            self.config.base_url.trim_end_matches('/')
        )
    }
}

#[async_trait]
impl LlmProvider for OpenAiCompatibleProvider {
    async fn complete(
        &self,
        request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError> {
        if !self.config.guard.allow_request() {
            return Err(ProviderError::CircuitOpen);
        }
        let redactor = Redactor::default();
        let messages = request
            .messages
            .iter()
            .map(|message| {
                let redacted = redactor.redact(&serde_json::json!({
                    "message": message.content,
                }));
                serde_json::json!({
                    "role": if matches!(message.role.as_str(), "system" | "user" | "assistant") { message.role.clone() } else { "user".to_owned() },
                    "content": redacted.value().get("message").and_then(serde_json::Value::as_str).unwrap_or("[REDACTED]"),
                })
            })
            .collect::<Vec<_>>();
        let body = serde_json::json!({
            "model": self.config.model,
            "messages": messages,
        });
        let result = tokio::time::timeout(self.config.request_timeout, async {
            self.client
                .post(self.endpoint())
                .bearer_auth(&self.config.api_key)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&body)
                .send()
                .await
        })
        .await
        .map_err(|_| ProviderError::Timeout)
        .and_then(|result| result.map_err(|_| ProviderError::Unavailable));
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                self.config.guard.record_failure(std::time::Instant::now());
                return Err(error);
            }
        };
        if !response.status().is_success() {
            let error = ProviderError::HttpStatus(response.status().as_u16());
            self.config.guard.record_failure(std::time::Instant::now());
            return Err(error);
        }
        let limit = self.config.response_limit_bytes;
        let read_result = tokio::time::timeout(self.config.request_timeout, async {
            let mut stream = response.bytes_stream();
            let mut bytes = Vec::new();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|_| ProviderError::Unavailable)?;
                if bytes.len().saturating_add(chunk.len()) > limit {
                    return Err(ProviderError::ResponseTooLarge);
                }
                bytes.extend_from_slice(&chunk);
            }
            Ok::<_, ProviderError>(bytes)
        })
        .await
        .map_err(|_| ProviderError::Timeout);
        let bytes = match read_result {
            Ok(Ok(bytes)) => bytes,
            Ok(Err(error)) | Err(error) => {
                self.config.guard.record_failure(std::time::Instant::now());
                return Err(error);
            }
        };
        let decoded = serde_json::from_slice(&bytes).map_err(|_| ProviderError::InvalidResponse);
        match decoded {
            Ok(value) => {
                self.config.guard.record_success();
                Ok(value)
            }
            Err(error) => {
                self.config.guard.record_failure(std::time::Instant::now());
                Err(error)
            }
        }
    }
}
