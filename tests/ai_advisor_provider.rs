use bearust::ai_advisor::ProviderGuard;
use bearust::ai_advisor_provider::{
    ChatCompletionMessage, ChatCompletionRequest, ChatCompletionResponse, LlmProvider,
    OpenAiCompatibleProvider, ProviderConfig, ProviderError,
};
use reqwest::Client;
use serde_json::json;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};
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

async fn scripted_server(
    responses: Vec<&'static str>,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let server_requests = Arc::clone(&requests);
    let task = tokio::spawn(async move {
        for response in responses {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0u8; 4096];
            let _ = stream.read(&mut request).await.unwrap();
            server_requests.fetch_add(1, Ordering::SeqCst);
            stream.write_all(response.as_bytes()).await.unwrap();
        }
    });
    (format!("http://{address}"), requests, task)
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
            messages: vec![ChatCompletionMessage {
                role: "user".into(),
                content: "hello password=hunter2".into(),
            }],
        })
        .await
        .unwrap();
    assert_eq!(result.choices[0].message.content, "done");
    let request = String::from_utf8(server.await.unwrap()).unwrap();
    assert!(request.starts_with("POST /v1/chat/completions HTTP/1.1"));
    assert!(request.contains("authorization: Bearer secret-key"));
    assert!(request.contains("\"model\":\"test-model\""));
    assert!(!request.contains("hunter2"));
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

#[tokio::test]
async fn adapter_enforces_body_limit_and_deadline() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await;
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = stream
            .write_all(b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n{}")
            .await;
    });
    let mut provider_config = config(format!("http://{address}"));
    provider_config.request_timeout = Duration::from_millis(10);
    let provider = OpenAiCompatibleProvider::new(Client::new(), provider_config);
    assert!(matches!(
        provider
            .complete(ChatCompletionRequest { messages: vec![] })
            .await,
        Err(ProviderError::Timeout)
    ));
}

#[tokio::test]
async fn adapter_rejects_oversized_stream_before_buffering() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = [0u8; 1024];
        let _ = stream.read(&mut request).await;
        let body = vec![b'x'; 5000];
        let mut response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n".to_vec();
        response.extend_from_slice(&body);
        let _ = stream.write_all(&response).await;
    });
    let provider =
        OpenAiCompatibleProvider::new(Client::new(), config(format!("http://{address}")));
    assert!(matches!(
        provider
            .complete(ChatCompletionRequest { messages: vec![] })
            .await,
        Err(ProviderError::ResponseTooLarge)
    ));
}

#[test]
fn response_schema_deserializes_expected_completion_shape() {
    let response: ChatCompletionResponse = serde_json::from_value(json!({
        "id":"x", "choices":[{"message":{"content":"ok"}}]
    }))
    .unwrap();
    assert_eq!(response.choices[0].message.content, "ok");
}

#[test]
fn provider_debug_never_formats_api_key() {
    let value = format!("{:?}", config("http://127.0.0.1".into()));
    assert!(!value.contains("secret-key"));
    assert!(value.contains("REDACTED"));
}

#[tokio::test]
async fn adapter_short_circuits_open_breaker_until_real_success_resets_failures() {
    const FAILURE: &str =
        "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    const SUCCESS: &str = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{\"id\":\"x\",\"choices\":[{\"message\":{\"content\":\"done\"}}]}";
    let (base_url, requests, server) =
        scripted_server(vec![FAILURE, FAILURE, FAILURE, SUCCESS, FAILURE, SUCCESS]).await;
    let cooldown = Duration::from_millis(100);
    let guard = Arc::new(ProviderGuard::new(2, cooldown));
    let provider = OpenAiCompatibleProvider::new(
        Client::new(),
        ProviderConfig {
            base_url,
            api_key: "secret-key".into(),
            model: "test-model".into(),
            request_timeout: Duration::from_secs(2),
            response_limit_bytes: 4096,
            guard,
        },
    );
    let request = || ChatCompletionRequest { messages: vec![] };

    assert!(matches!(
        provider.complete(request()).await,
        Err(ProviderError::HttpStatus(502))
    ));
    assert!(matches!(
        provider.complete(request()).await,
        Err(ProviderError::HttpStatus(502))
    ));
    assert!(matches!(
        provider.complete(request()).await,
        Err(ProviderError::CircuitOpen)
    ));
    assert_eq!(
        requests.load(Ordering::SeqCst),
        2,
        "an open circuit must not reach the mock server"
    );

    tokio::time::sleep(cooldown + Duration::from_millis(10)).await;
    assert!(matches!(
        provider.complete(request()).await,
        Err(ProviderError::HttpStatus(502))
    ));
    assert!(matches!(
        provider.complete(request()).await,
        Err(ProviderError::CircuitOpen)
    ));
    assert_eq!(
        requests.load(Ordering::SeqCst),
        3,
        "a short-circuit must not reset the failure count"
    );

    tokio::time::sleep(cooldown + Duration::from_millis(10)).await;
    provider.complete(request()).await.unwrap();
    assert!(matches!(
        provider.complete(request()).await,
        Err(ProviderError::HttpStatus(502))
    ));
    provider.complete(request()).await.unwrap();

    tokio::time::timeout(Duration::from_secs(1), server)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(requests.load(Ordering::SeqCst), 6);
}
