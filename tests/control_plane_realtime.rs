use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use bearust::control_plane::realtime::RealtimeHub;
use bearust::control_plane::{audit, auth, build_state, repository, router};
use http_body_util::BodyExt;
use tower::util::ServiceExt;

#[tokio::test]
async fn hub_assigns_monotonic_ids_and_drops_slow_subscribers_without_blocking() {
    let hub = RealtimeHub::new(1);
    let mut receiver = hub.subscribe();
    hub.publish("users.changed");
    let first = receiver.recv().await.unwrap();
    assert_eq!(first.id, 1);
    hub.publish("roles.changed");
    hub.publish("certificates.changed");
    assert!(matches!(
        receiver.recv().await,
        Err(tokio::sync::broadcast::error::RecvError::Lagged(1))
    ));
}

async fn authenticated_app() -> (axum::Router, bearust::control_plane::AppState, String) {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let state = build_state("sqlite::memory:", dir.path(), "setup-token")
        .await
        .unwrap();
    let app = router(state.clone());
    let setup = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/api/setup/initialize")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#))
        .unwrap()).await.unwrap();
    assert_eq!(setup.status(), StatusCode::CREATED);
    let login = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/auth/login")
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"admin@example.com","password":"correct horse battery"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    let cookie = login
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    (app, state, cookie)
}

#[tokio::test]
async fn events_endpoint_requires_auth_and_streams_ready_and_published_events() {
    let (app, state, cookie) = authenticated_app().await;
    let unauthenticated = app
        .clone()
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/events")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "text/event-stream"
    );
    assert_eq!(
        response.headers().get("cache-control").unwrap(),
        "no-cache, no-transform"
    );
    let mut body = response.into_body();
    let ready = body.frame().await.unwrap().unwrap().into_data().unwrap();
    let ready = String::from_utf8(ready.to_vec()).unwrap();
    assert!(ready.starts_with("event: ready\n"));
    state.realtime.publish("users.changed");
    let event = body.frame().await.unwrap().unwrap().into_data().unwrap();
    let event = String::from_utf8(event.to_vec()).unwrap();
    assert!(event.lines().any(|line| line.starts_with("id: ")));
    assert!(event.contains("event: users.changed\n"));
}

#[tokio::test]
async fn events_endpoint_ignores_last_event_id_and_does_not_replay_history() {
    let (app, _state, cookie) = authenticated_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/events")
                .header("cookie", &cookie)
                .header("last-event-id", "17")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let ready = body.frame().await.unwrap().unwrap().into_data().unwrap();
    let ready = String::from_utf8(ready.to_vec()).unwrap();
    assert!(ready.starts_with("event: ready\n"));
    assert!(!ready.contains("17"));
}

#[tokio::test]
async fn events_stream_closes_after_session_revocation() {
    let (app, state, cookie) = authenticated_app().await;
    let response = app
        .oneshot(
            Request::builder()
                .method("GET")
                .uri("/api/events")
                .header("cookie", &cookie)
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let ready = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(String::from_utf8(ready.to_vec())
        .unwrap()
        .starts_with("event: ready\n"));

    let token = cookie.strip_prefix("bearust_session=").unwrap();
    repository::revoke_session(&state.db, &auth::token_hash(token))
        .await
        .unwrap();

    let closed = tokio::time::timeout(std::time::Duration::from_secs(18), async {
        loop {
            match body.frame().await {
                None => break true,
                Some(Ok(_)) => {}
                Some(Err(_)) => break true,
            }
        }
    })
    .await
    .expect("SSE stream did not close after session revocation");
    assert!(closed);
}

#[tokio::test]
async fn state_audit_record_publishes_redacted_audit_event() {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let state = build_state("sqlite::memory:", dir.path(), "setup-token")
        .await
        .unwrap();
    let mut events = state.realtime.subscribe();
    audit::record_state(&state, Some(7), "user_created", "user_id=8").await;
    let event = events.recv().await.unwrap();
    assert_eq!(event.kind, "audit");
    let serialized = serde_json::to_string(&event).unwrap();
    assert!(!serialized.contains("password"));
    assert!(!serialized.contains("setup-token"));
    assert!(!serialized.contains("private key"));
}

#[tokio::test]
async fn publishes_domain_events_without_secrets() {
    let (app, state, cookie) = authenticated_app().await;
    let mut events = state.realtime.subscribe();

    let create_user = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/api/users")
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"email":"operator@example.com","password":"operator password 123","role":"operator"}"#))
        .unwrap()).await.unwrap();
    assert_eq!(create_user.status(), StatusCode::CREATED);
    let created_user: serde_json::Value =
        serde_json::from_slice(&create_user.into_body().collect().await.unwrap().to_bytes())
            .unwrap();
    let created_user_id = created_user["id"].as_i64().unwrap();

    let audit = events.recv().await.unwrap();
    let users = events.recv().await.unwrap();
    assert_eq!(audit.kind, "audit");
    assert_eq!(users.kind, "users.changed");

    let update_user = app
        .clone()
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri(format!("/api/users/{created_user_id}"))
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"disabled":true}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(update_user.status(), StatusCode::OK);
    assert_eq!(events.recv().await.unwrap().kind, "audit");
    assert_eq!(events.recv().await.unwrap().kind, "users.changed");
    assert_eq!(events.recv().await.unwrap().kind, "sessions.changed");

    let invalid_user = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/users")
                .header("cookie", &cookie)
                .header("content-type", "application/json")
                .body(Body::from(
                    r#"{"email":"invalid","password":"short","role":"missing"}"#,
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(invalid_user.status(), StatusCode::BAD_REQUEST);
    let denied = events.recv().await.unwrap();
    assert_eq!(denied.kind, "audit");

    for event in [audit, users, denied] {
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(!serialized.contains("operator password 123"));
        assert!(!serialized.contains("setup-token"));
        assert!(!serialized.contains("private key"));
        assert!(!serialized.contains("-----BEGIN"));
    }
}

#[tokio::test]
async fn role_scope_changes_publish_redacted_invalidation_and_audit_events() {
    let (app, state, cookie) = authenticated_app().await;
    sqlx::query("INSERT INTO proxy_hosts(name,domain,upstream_host,upstream_port,tls_mode,created_at,updated_at) VALUES(?,?,?,?,?,datetime('now'),datetime('now'))")
        .bind("internal-admin-host")
        .bind("internal.example.test")
        .bind("10.0.0.9")
        .bind(8443_i64)
        .bind("disabled")
        .execute(&state.db)
        .await
        .unwrap();

    let mut events = state.realtime.subscribe();
    let response = app.oneshot(Request::builder()
        .method("POST")
        .uri("/api/roles")
        .header("cookie", &cookie)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"slug":"host-auditor","name":"Host Auditor","permissions":["proxy_hosts.read"],"scopes":[{"permission":"proxy_hosts.read","proxy_host_ids":[1]}]}"#))
        .unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::CREATED);

    // Each audit write publishes only a kind/id event; request bodies and role
    // scope details never cross the realtime boundary.
    let mut kinds = Vec::new();
    for _ in 0..4 {
        let event = events.recv().await.unwrap();
        let serialized = serde_json::to_string(&event).unwrap();
        assert!(!serialized.contains("internal.example.test"));
        assert!(!serialized.contains("10.0.0.9"));
        assert!(!serialized.contains("proxy_host_ids"));
        kinds.push(event.kind);
    }
    assert_eq!(
        kinds.iter().map(String::as_str).collect::<Vec<_>>(),
        ["audit", "audit", "audit", "roles.changed"]
    );

    let details: Vec<String> =
        sqlx::query_scalar("SELECT details FROM audit_logs WHERE event='role_scopes_changed'")
            .fetch_all(&state.db)
            .await
            .unwrap();
    assert_eq!(details.len(), 1);
    assert!(details[0].contains("\"role_id\""));
    assert!(details[0].contains("\"read_assignments\":1"));
    assert!(details[0].contains("\"write_assignments\":0"));
    assert!(!details[0].contains("proxy_host_ids"));
    assert!(!details[0].contains("internal.example.test"));
    assert!(!details[0].contains("10.0.0.9"));
}
