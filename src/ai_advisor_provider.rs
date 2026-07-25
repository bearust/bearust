use crate::ai_advisor::ProviderGuard;
use async_trait::async_trait;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::{sync::Arc, time::Duration};
use thiserror::Error;

#[derive(Clone, Debug)]
pub struct ProviderConfig {
    pub base_url: String,
    pub api_key: String,
    pub model: String,
    pub request_timeout: Duration,
    pub response_limit_bytes: usize,
    pub guard: Arc<ProviderGuard>,
}

#[derive(Clone, Debug, Serialize)]
pub struct ChatCompletionRequest {
    pub messages: Vec<serde_json::Value>,
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
        mut request: ChatCompletionRequest,
    ) -> Result<ChatCompletionResponse, ProviderError> {
        if !self.config.guard.allow_request() {
            return Err(ProviderError::CircuitOpen);
        }
        let body = serde_json::json!({
            "model": self.config.model,
            "messages": request.messages.drain(..).collect::<Vec<_>>(),
        });
        let result = tokio::time::timeout(
            self.config.request_timeout,
            self.client
                .post(self.endpoint())
                .bearer_auth(&self.config.api_key)
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .json(&body)
                .send(),
        )
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
        let bytes = response
            .bytes()
            .await
            .map_err(|_| ProviderError::Unavailable)?;
        if bytes.len() > self.config.response_limit_bytes {
            self.config.guard.record_failure(std::time::Instant::now());
            return Err(ProviderError::ResponseTooLarge);
        }
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
