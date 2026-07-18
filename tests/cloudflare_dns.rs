use axum::{
    extract::State,
    http::StatusCode,
    routing::{delete, get, post},
    Json, Router,
};
use bearust::acme::{dns01_record_name, CloudflareProvider, DnsProvider, TxtRecord};
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
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (format!("http://{addr}"), seen)
}

#[tokio::test]
async fn cloudflare_presents_and_cleans_txt_record() {
    let router = Router::new()
        .route("/zones", get(|State(seen): State<Seen>| async move {
            seen.0.lock().unwrap().push("zones".into());
            Json(serde_json::json!({"success":true,"result":[{"id":"zone-1","name":"example.com"}]}))
        }))
        .route("/zones/zone-1/dns_records", post(|State(seen): State<Seen>, Json(body): Json<Value>| async move {
            seen.0.lock().unwrap().push(format!("create:{}", body["name"]));
            Json(serde_json::json!({"success":true,"result":{"id":"record-1"}}))
        }).get(|| async {
            Json(serde_json::json!({"success":true,"result":[{"id":"record-1","name":"_acme-challenge.example.com","content":"proof"}]}))
        }))
        .route("/zones/zone-1/dns_records/record-1", delete(|State(seen): State<Seen>| async move {
            seen.0.lock().unwrap().push("delete".into());
            Json(serde_json::json!({"success":true,"result":{}}))
        }));
    let (base, seen) = spawn_app(router).await;
    let provider = CloudflareProvider::with_endpoint(
        "secret-token",
        base,
        Duration::from_secs(2),
        Duration::from_millis(20),
        Duration::from_millis(5),
    )
    .unwrap();
    let record = TxtRecord::new("_acme-challenge.example.com", "proof");
    provider.present(record.clone()).await.unwrap();
    provider.cleanup(record).await.unwrap();
    let calls = seen.0.lock().unwrap().join(",");
    assert!(calls.contains("zones") && calls.contains("create") && calls.contains("delete"));
}

#[test]
fn wildcard_names_use_base_acme_challenge_record() {
    assert_eq!(
        dns01_record_name("*.example.com"),
        "_acme-challenge.example.com"
    );
    assert_eq!(
        dns01_record_name("example.com."),
        "_acme-challenge.example.com"
    );
}

#[tokio::test]
async fn non_2xx_errors_are_redacted() {
    let router = Router::new().route(
        "/zones",
        get(|| async { (StatusCode::UNAUTHORIZED, "token=secret-token leaked") }),
    );
    let (base, _) = spawn_app(router).await;
    let provider = CloudflareProvider::with_endpoint(
        "secret-token",
        base,
        Duration::from_secs(2),
        Duration::from_millis(20),
        Duration::from_millis(5),
    )
    .unwrap();
    let err = provider
        .present(TxtRecord::new("_acme-challenge.example.com", "proof"))
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(!text.contains("secret-token") && !text.contains("leaked"));
}

#[tokio::test]
async fn propagation_times_out_when_record_is_not_visible() {
    let router = Router::new()
        .route("/zones", get(|| async { Json(serde_json::json!({"success":true,"result":[{"id":"zone-1","name":"example.com"}]})) }))
        .route("/zones/zone-1/dns_records", post(|| async { Json(serde_json::json!({"success":true,"result":{"id":"record-1"}})) }))
        .route("/zones/zone-1/dns_records/record-1", delete(|| async { StatusCode::NOT_FOUND }))
        .route("/zones/zone-1/dns_records", get(|| async { Json(serde_json::json!({"success":true,"result":[]})) }));
    let (base, _) = spawn_app(router).await;
    let provider = CloudflareProvider::with_endpoint(
        "secret-token",
        base,
        Duration::from_secs(2),
        Duration::from_millis(30),
        Duration::from_millis(5),
    )
    .unwrap();
    let err = provider
        .wait_for_propagation(TxtRecord::new("_acme-challenge.example.com", "proof"))
        .await
        .unwrap_err();
    assert!(err.to_string().contains("propagation"));
}

#[tokio::test]
async fn cleanup_ignores_only_not_found() {
    let router = Router::new()
        .route("/zones", get(|| async {
            Json(serde_json::json!({"success":true,"result":[{"id":"zone-1"}]}))
        }))
        .route(
            "/zones/zone-1/dns_records",
            get(|| async {
                Json(serde_json::json!({"success":true,"result":[{"id":"record-1","name":"_acme-challenge.example.com","content":"proof"}]}))
            }),
        )
        .route(
            "/zones/zone-1/dns_records/record-1",
            delete(|| async { StatusCode::NOT_FOUND }),
        );
    let (base, _) = spawn_app(router).await;
    let provider = CloudflareProvider::with_endpoint(
        "secret-token",
        base,
        Duration::from_secs(2),
        Duration::from_millis(20),
        Duration::from_millis(5),
    )
    .unwrap();
    provider
        .cleanup(TxtRecord::new("_acme-challenge.example.com", "proof"))
        .await
        .unwrap();
}

#[tokio::test]
async fn cleanup_preserves_server_errors() {
    let router = Router::new()
        .route("/zones", get(|| async {
            Json(serde_json::json!({"success":true,"result":[{"id":"zone-1"}]}))
        }))
        .route(
            "/zones/zone-1/dns_records",
            get(|| async {
                Json(serde_json::json!({"success":true,"result":[{"id":"record-1","name":"_acme-challenge.example.com","content":"proof"}]}))
            }),
        )
        .route(
            "/zones/zone-1/dns_records/record-1",
            delete(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
        );
    let (base, _) = spawn_app(router).await;
    let provider = CloudflareProvider::with_endpoint(
        "secret-token",
        base,
        Duration::from_secs(2),
        Duration::from_millis(20),
        Duration::from_millis(5),
    )
    .unwrap();
    assert!(matches!(
        provider
            .cleanup(TxtRecord::new("_acme-challenge.example.com", "proof"))
            .await,
        Err(bearust::acme::DnsError::Api)
    ));
}
