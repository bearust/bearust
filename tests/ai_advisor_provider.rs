use bearust::ai_advisor::ProviderGuard;
use bearust::ai_advisor_provider::{
    ChatCompletionRequest, ChatCompletionResponse, LlmProvider, OpenAiCompatibleProvider,
    ProviderConfig, ProviderError,
};
use reqwest::Client;
use serde_json::json;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

async fn mock_server(response: &'static str) -> (String, tokio::task::JoinHandle<Vec<u8>>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = vec![0u8; 8192];
        let size = stream.read(&mut request).await.unwrap();
        stream.write_all(response.as_bytes()).await.unwrap();
        request.truncate(size);
        request
    });
    (format!("http://{address}"), task)
}

fn config(base_url: String) -> ProviderConfig {
    ProviderConfig {
        base_url,
        api_key: "secret-key".into(),
        model: "test-model".into(),
        request_timeout: Duration::from_secs(2),
        response_limit_bytes: 4096,
        guard: Arc::new(ProviderGuard::new(3, Duration::from_secs(30))),
    }
}

#[tokio::test]
async fn adapter_posts_openai_payload_with_bearer_auth() {
    let response = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"id\":\"x\",\"choices\":[{\"message\":{\"content\":\"done\"}}]}";
    let (base_url, server) = mock_server(response).await;
    let provider = OpenAiCompatibleProvider::new(Client::new(), config(base_url));
    let result = provider
        .complete(ChatCompletionRequest {
            messages: vec![json!({"role":"user","content":"hello"})],
        })
        .await
        .unwrap();
    assert_eq!(result.choices[0].message.content, "done");
    let request = String::from_utf8(server.await.unwrap()).unwrap();
    assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1"));
    assert!(request.contains("authorization: Bearer secret-key"));
    assert!(request.contains("\"model\":\"test-model\""));
}

#[tokio::test]
async fn adapter_maps_non_success_and_malformed_responses_without_body_leakage() {
    let (base_url, server) =
        mock_server("HTTP/1.1 502 Bad Gateway\r\nContent-Length: 16\r\n\r\nsecret-provider").await;
    let provider = OpenAiCompatibleProvider::new(Client::new(), config(base_url));
    let error = provider
        .complete(ChatCompletionRequest { messages: vec![] })
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::HttpStatus(502)));
    assert!(!error.to_string().contains("secret-provider"));
    server.await.unwrap();

    let (base_url, server) = mock_server("HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nno!").await;
    let provider = OpenAiCompatibleProvider::new(Client::new(), config(base_url));
    let error = provider
        .complete(ChatCompletionRequest { messages: vec![] })
        .await
        .unwrap_err();
    assert!(matches!(error, ProviderError::InvalidResponse));
    server.await.unwrap();
}

#[test]
fn response_type_is_bounded_and_deserializable() {
    let response: ChatCompletionResponse = serde_json::from_value(json!({
        "id":"x", "choices":[{"message":{"content":"ok"}}]
    }))
    .unwrap();
    assert_eq!(response.choices[0].message.content, "ok");
}
