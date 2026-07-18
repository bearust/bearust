use axum::{
    extract::State,
    http::StatusCode,
    response::IntoResponse,
    routing::{delete, get, post},
    Json, Router,
};
use bearust::acme::{CloudflareProvider, DnsProvider, TxtRecord};
use serde_json::Value;
use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::net::TcpListener;

#[derive(Clone, Default)]
struct Seen(Arc<Mutex<Vec<String>>>);

async fn spawn_app(router: Router<Seen>) -> (String, Seen) {
    let seen = Seen::default();
    let app = router.with_state(seen.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr: SocketAddr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (format!("http://{addr}"), seen)
}

fn provider(base: String) -> CloudflareProvider {
    CloudflareProvider::with_endpoint(
        "test-token",
        base,
        Duration::from_secs(2),
        Duration::from_millis(20),
        Duration::from_millis(1),
    )
    .unwrap()
}

#[tokio::test]
async fn partial_present_failure_still_cleans_created_record() {
    let router = Router::new()
        .route(
            "/zones",
            get(|| async { Json(serde_json::json!({"success":true,"result":[{"id":"zone-1"}]})) }),
        )
        .route(
            "/zones/zone-1/dns_records",
            post(|State(seen): State<Seen>, Json(body): Json<Value>| async move {
                let mut calls = seen.0.lock().unwrap();
                calls.push(format!("create:{}", body["content"]));
                if calls.iter().filter(|call| call.starts_with("create:")).count() == 2 {
                    (StatusCode::BAD_GATEWAY, "temporary failure").into_response()
                } else {
                    Json(serde_json::json!({"success":true,"result":{"id":"owned-1"}})).into_response()
                }
            }),
        )
        .route(
            "/zones/zone-1/dns_records/owned-1",
            delete(|State(seen): State<Seen>| async move {
                seen.0.lock().unwrap().push("delete:owned-1".into());
                Json(serde_json::json!({"success":true,"result":{}}))
            }),
        );
    let (base, seen) = spawn_app(router).await;
    let provider = provider(base);
    let first = TxtRecord::new("_acme-challenge.example.com", "proof-1");
    let second = TxtRecord::new("_acme-challenge.example.com", "proof-2");
    provider.present(first.clone()).await.unwrap();
    assert!(provider.present(second).await.is_err());
    provider.cleanup(first).await.unwrap();
    assert!(seen.0.lock().unwrap().iter().any(|call| call == "delete:owned-1"));
}

#[tokio::test]
async fn concurrent_same_challenge_keeps_both_record_ids() {
    let router = Router::new()
        .route(
            "/zones",
            get(|| async { Json(serde_json::json!({"success":true,"result":[{"id":"zone-1"}]})) }),
        )
        .route(
            "/zones/zone-1/dns_records",
            post(|State(seen): State<Seen>| async move {
                let mut calls = seen.0.lock().unwrap();
                let id = if calls.iter().any(|call| call == "create:1") { "record-2" } else { "record-1" };
                calls.push("create:1".into());
                Json(serde_json::json!({"success":true,"result":{"id":id}}))
            }),
        )
        .route(
            "/zones/zone-1/dns_records/{id}",
            delete(|State(seen): State<Seen>, axum::extract::Path(id): axum::extract::Path<String>| async move {
                seen.0.lock().unwrap().push(format!("delete:{id}"));
                Json(serde_json::json!({"success":true,"result":{}}))
            }),
        );
    let (base, seen) = spawn_app(router).await;
    let provider = provider(base);
    let record = TxtRecord::new("_acme-challenge.example.com", "same-proof");
    provider.present(record.clone()).await.unwrap();
    provider.present(record.clone()).await.unwrap();
    provider.cleanup(record.clone()).await.unwrap();
    provider.cleanup(record).await.unwrap();
    let calls = seen.0.lock().unwrap().join(",");
    assert!(calls.contains("delete:record-1") && calls.contains("delete:record-2"));
}
