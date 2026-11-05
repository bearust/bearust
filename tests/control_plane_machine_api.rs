use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use bearust::{
    acme::Http01Store,
    control_plane::{
        auth::{hash_password, token_hash},
        build_state, repository, router,
    },
    runtime::RuntimeStore,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tempfile::tempdir;
use tower::ServiceExt;

async fn setup() -> (Router, Arc<RuntimeStore>, tempfile::TempDir, Http01Store) {
    let directory = tempdir().unwrap();
    let config_path = directory.path().join("bearust.toml");
    std::fs::write(&config_path, include_str!("fixtures/valid.toml")).unwrap();
    let runtime = Arc::new(RuntimeStore::from_path(&config_path).await.unwrap());
    let state = build_state("sqlite::memory:", directory.path(), "setup-token")
        .await
        .unwrap();
    let admin = repository::insert_initial_admin(
        &state.db,
        "admin@example.test",
        &hash_password("admin-password-123").unwrap(),
    )
    .await
    .unwrap()
    .unwrap();
    repository::create_session(
        &state.db,
        admin.id,
        &token_hash("admin-session"),
        "2099-01-01T00:00:00Z",
    )
    .await
    .unwrap();
    let http01 = state.http01.clone();
    let state = state.with_runtime(
        Arc::clone(&runtime),
        Arc::new(config_path),
        Arc::new(directory.path().join("missing.pid")),
    );
    (router(state), runtime, directory, http01)
}

enum Caller<'a> {
    Anonymous,
    Session,
    Token(&'a str),
}

async fn call(
    app: &Router,
    method: &str,
    path: &str,
    caller: Caller<'_>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = Request::builder().method(method).uri(path);
    match caller {
        Caller::Anonymous => {}
        Caller::Session => request = request.header("Cookie", "bearust_session=admin-session"),
        Caller::Token(token) => {
            request = request.header("Authorization", format!("Bearer {token}"))
        }
    }
    let body = match body {
        Some(value) => {
            request = request.header("Content-Type", "application/json");
            Body::from(value.to_string())
        }
        None => Body::empty(),
    };
    let response = app
        .clone()
        .oneshot(request.body(body).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

async fn create_token(app: &Router, scope: &str) -> (i64, String) {
    let (status, body) = call(
        app,
        "POST",
        "/api/api-tokens",
        Caller::Session,
        Some(json!({"name": format!("cloud-{scope}"), "scope": scope})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let secret = body["secret"].as_str().unwrap().to_string();
    assert!(secret.starts_with("brt_"));
    (body["id"].as_i64().unwrap(), secret)
}

fn document(generation: i64, pool: &str, host: &str) -> Value {
    json!({
        "generation": generation,
        "pools": [{
            "name": pool,
            "algorithm": "round_robin",
            "backends": [{"address": "127.0.0.1:19005", "health_check": "tcp", "health_path": null}]
        }],
        "routes": [{"name": pool, "host": host, "path_prefix": "/", "upstream_pool": pool}]
    })
}

#[tokio::test]
async fn api_tokens_are_scoped_and_cannot_manage_identity() {
    let (app, runtime, _directory, _) = setup().await;

    let (status, _) = call(
        &app,
        "POST",
        "/api/api-tokens",
        Caller::Anonymous,
        Some(json!({"name": "x", "scope": "write"})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (read_id, read) = create_token(&app, "read").await;
    let (_, write) = create_token(&app, "write").await;

    let (status, _) = call(
        &app,
        "GET",
        "/api/load-balancer",
        Caller::Token(&read),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, body) = call(
        &app,
        "PUT",
        "/api/desired-state",
        Caller::Token(&read),
        Some(document(1, "edge", "edge.example.test")),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body["code"], "insufficient_scope");

    for (method, path) in [
        ("GET", "/api/api-tokens"),
        ("GET", "/api/users"),
        ("GET", "/api/auth/me"),
    ] {
        let (status, body) = call(&app, method, path, Caller::Token(&write), None).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}");
        assert_eq!(body["code"], "token_forbidden");
    }
    let (status, _) = call(
        &app,
        "POST",
        "/api/api-tokens",
        Caller::Token(&write),
        Some(json!({"name": "escalate", "scope": "write"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    let (status, body) = call(&app, "GET", "/api/api-tokens", Caller::Session, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2);
    assert!(
        body.to_string().find("brt_").is_none(),
        "secrets must not be listed"
    );
    assert!(body[0]["last_used_at"].is_string());

    let (status, body) = call(
        &app,
        "GET",
        "/api/load-balancer",
        Caller::Token("brt_unknown"),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["code"], "invalid_token");

    let (status, _) = call(
        &app,
        "DELETE",
        &format!("/api/api-tokens/{read_id}"),
        Caller::Session,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _) = call(
        &app,
        "GET",
        "/api/load-balancer",
        Caller::Token(&read),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, body) = call(&app, "GET", "/api/audit-logs", Caller::Session, None).await;
    assert_eq!(status, StatusCode::OK);
    let events = body.to_string();
    assert!(events.contains("api_token_created") && events.contains("api_token_revoked"));
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn desired_state_applies_atomically_with_generation_guard() {
    let (app, runtime, _directory, _) = setup().await;
    let (_, token) = create_token(&app, "write").await;

    // A dashboard proxy host must survive desired-state pushes.
    let (status, host) = call(
        &app,
        "POST",
        "/api/proxy-hosts",
        Caller::Session,
        Some(json!({
            "name": "Status page", "domain": "status.example.test",
            "upstream_host": "127.0.0.1", "upstream_port": 19002,
            "tls_mode": "disabled", "certificate_id": null, "enabled": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let host_pool = format!("proxy-host-{}", host["id"]);

    let (status, body) = call(
        &app,
        "GET",
        "/api/desired-state",
        Caller::Token(&token),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["generation"], 0);

    let (status, body) = call(
        &app,
        "PUT",
        "/api/desired-state",
        Caller::Token(&token),
        Some(document(1, "tenant-a", "a.example.test")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["generation"], 1);
    {
        let snapshot = runtime.load();
        let names: Vec<_> = snapshot
            .config()
            .upstream_pools
            .iter()
            .map(|pool| pool.name.clone())
            .collect();
        assert!(names.contains(&"tenant-a".to_string()), "{names:?}");
        assert!(names.contains(&host_pool), "{names:?}");
        assert!(
            !names.contains(&"api".to_string()),
            "old pools are replaced: {names:?}"
        );
        assert!(snapshot.route("a.example.test", "/").is_some());
    }

    // Replayed or older generations are refused.
    let (status, body) = call(
        &app,
        "PUT",
        "/api/desired-state",
        Caller::Token(&token),
        Some(document(1, "tenant-b", "b.example.test")),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "stale_generation");
    assert_eq!(body["generation"], 1);

    // An invalid document changes nothing, including the generation.
    let mut invalid = document(2, "tenant-b", "b.example.test");
    invalid["routes"][0]["upstream_pool"] = json!("missing");
    let (status, body) = call(
        &app,
        "PUT",
        "/api/desired-state",
        Caller::Token(&token),
        Some(invalid),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "invalid_desired_state");
    assert!(runtime.load().route("a.example.test", "/").is_some());
    let (_, body) = call(
        &app,
        "GET",
        "/api/desired-state",
        Caller::Token(&token),
        None,
    )
    .await;
    assert_eq!(body["generation"], 1);

    let (status, body) = call(
        &app,
        "PUT",
        "/api/desired-state",
        Caller::Token(&token),
        Some(document(2, "proxy-host-99", "x.example.test")),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "reserved_name");

    let (status, _) = call(
        &app,
        "PUT",
        "/api/desired-state",
        Caller::Token(&token),
        Some(document(5, "tenant-b", "b.example.test")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let snapshot = runtime.load();
    assert!(snapshot.route("b.example.test", "/").is_some());
    assert!(snapshot.route("a.example.test", "/").is_none());
    assert!(snapshot.route("status.example.test", "/").is_some());
    drop(snapshot);
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn desired_state_carries_managed_certificates_and_challenges() {
    let (app, runtime, _directory, http01) = setup().await;
    let (_, token) = create_token(&app, "write").await;
    let cert = rcgen::generate_simple_self_signed(vec!["shop.example.test".to_string()]).unwrap();
    let digest = "a".repeat(43);
    let mut doc = document(1, "tenant-a", "shop.example.test");
    doc["certificates"] = json!([{
        "name": "t-abc.shop",
        "cert_pem": cert.cert.pem(),
        "key_pem": cert.key_pair.serialize_pem(),
    }]);
    doc["acme_challenges"] = json!([{
        "host": "shop.example.test",
        "token": "tok_1",
        "key_authorization": format!("tok_1.{digest}"),
    }]);
    let (status, body) = call(
        &app,
        "PUT",
        "/api/desired-state",
        Caller::Token(&token),
        Some(doc),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        http01.get_for_hostname("shop.example.test", "tok_1"),
        Some(format!("tok_1.{digest}"))
    );
    let (_, certs) = call(&app, "GET", "/api/certificates", Caller::Session, None).await;
    let names: Vec<&str> = certs
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|c| c["name"].as_str())
        .collect();
    assert!(names.contains(&"managed-t-abc.shop"), "{certs}");

    // A key that does not match is refused and nothing changes.
    let other = rcgen::generate_simple_self_signed(vec!["x.example.test".to_string()]).unwrap();
    let mut bad = document(2, "tenant-a", "shop.example.test");
    bad["certificates"] = json!([{
        "name": "t-abc.shop",
        "cert_pem": cert.cert.pem(),
        "key_pem": other.key_pair.serialize_pem(),
    }]);
    let (status, body) = call(
        &app,
        "PUT",
        "/api/desired-state",
        Caller::Token(&token),
        Some(bad),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // A document without them removes both.
    let (status, _) = call(
        &app,
        "PUT",
        "/api/desired-state",
        Caller::Token(&token),
        Some(document(3, "tenant-a", "shop.example.test")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(http01.get_for_hostname("shop.example.test", "tok_1"), None);
    let (_, certs) = call(&app, "GET", "/api/certificates", Caller::Session, None).await;
    assert!(!certs.to_string().contains("managed-t-abc.shop"), "{certs}");
    runtime.shutdown().await.unwrap();
}

#[tokio::test]
async fn usage_reports_desired_state_hosts_to_read_tokens() {
    let (app, _runtime, _dir, _http01) = setup().await;
    let (_, writer) = create_token(&app, "write").await;
    let (_, reader) = create_token(&app, "read").await;
    let (status, _) = call(
        &app,
        "PUT",
        "/api/desired-state",
        Caller::Token(&writer),
        Some(document(1, "tenant-pool", "tenant.example")),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    bearust::metering::global().record(bearust::metering::UsageSample {
        host: Some("tenant.example"),
        path: "/",
        status: 200,
        bytes_in: 5,
        bytes_out: 50,
    });
    bearust::metering::global().record(bearust::metering::UsageSample {
        host: Some("not-in-desired-state.example"),
        path: "/",
        status: 200,
        bytes_in: 5,
        bytes_out: 50,
    });

    let (status, body) = call(&app, "GET", "/api/usage", Caller::Token(&reader), None).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["boot_id"].as_str().is_some());
    let hosts = body["hosts"].as_object().unwrap();
    assert!(hosts["tenant.example"]["requests"].as_u64().unwrap() >= 1);
    assert!(hosts["tenant.example"]["bytes_out"].as_u64().unwrap() >= 50);
    assert!(!hosts.contains_key("not-in-desired-state.example"));

    let (status, _) = call(&app, "GET", "/api/usage", Caller::Anonymous, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
