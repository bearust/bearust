use axum::{body::Body, http::{Request, StatusCode}};
use bearust::control_plane::{auth, audit, build_state, repository, router};
use bearust::control_plane::realtime::RealtimeHub;
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
    let state = build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap();
    let app = router(state.clone());
    let setup = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/api/setup/initialize")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#))
        .unwrap()).await.unwrap();
    assert_eq!(setup.status(), StatusCode::CREATED);
    let login = app.clone().oneshot(Request::builder()
        .method("POST")
        .uri("/api/auth/login")
        .header("content-type", "application/json")
        .body(Body::from(r#"{"email":"admin@example.com","password":"correct horse battery"}"#))
        .unwrap()).await.unwrap();
    let cookie = login.headers().get("set-cookie").unwrap().to_str().unwrap()
        .split(';').next().unwrap().to_owned();
    (app, state, cookie)
}

#[tokio::test]
async fn events_endpoint_requires_auth_and_streams_ready_and_published_events() {
    let (app, state, cookie) = authenticated_app().await;
    let unauthenticated = app.clone().oneshot(Request::builder()
        .method("GET").uri("/api/events").body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let response = app.oneshot(Request::builder()
        .method("GET").uri("/api/events")
        .header("cookie", &cookie).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers().get("content-type").unwrap(), "text/event-stream");
    assert_eq!(response.headers().get("cache-control").unwrap(), "no-cache, no-transform");
    let mut body = response.into_body();
    let ready = body.frame().await.unwrap().unwrap().into_data().unwrap();
    let ready = String::from_utf8(ready.to_vec()).unwrap();
    assert!(ready.starts_with("event: ready\n"));
    state.realtime.publish("users.changed");
    let event = body.frame().await.unwrap().unwrap().into_data().unwrap();
    let event = String::from_utf8(event.to_vec()).unwrap();
    assert!(event.contains("id: 1\n"));
    assert!(event.contains("event: users.changed\n"));
}

#[tokio::test]
async fn events_endpoint_ignores_last_event_id_and_does_not_replay_history() {
    let (app, _state, cookie) = authenticated_app().await;
    let response = app.oneshot(Request::builder()
        .method("GET").uri("/api/events")
        .header("cookie", &cookie)
        .header("last-event-id", "17")
        .body(Body::empty()).unwrap()).await.unwrap();
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
    let response = app.oneshot(Request::builder()
        .method("GET").uri("/api/events")
        .header("cookie", &cookie).body(Body::empty()).unwrap()).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let mut body = response.into_body();
    let ready = body.frame().await.unwrap().unwrap().into_data().unwrap();
    assert!(String::from_utf8(ready.to_vec()).unwrap().starts_with("event: ready\n"));

    let token = cookie.strip_prefix("bearust_session=").unwrap();
    repository::revoke_session(&state.db, &auth::token_hash(token)).await.unwrap();

    let closed = tokio::time::timeout(std::time::Duration::from_secs(18), async {
        loop {
            match body.frame().await {
                None => break true,
                Some(Ok(_)) => {}
                Some(Err(_)) => break true,
            }
        }
    }).await.expect("SSE stream did not close after session revocation");
    assert!(closed);
}

#[tokio::test]
async fn state_audit_record_publishes_redacted_audit_event() {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let state = build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap();
    let mut events = state.realtime.subscribe();
    audit::record_state(&state, Some(7), "user_created", "user_id=8").await;
    let event = events.recv().await.unwrap();
    assert_eq!(event.kind, "audit");
    let serialized = serde_json::to_string(&event).unwrap();
    assert!(!serialized.contains("password"));
    assert!(!serialized.contains("setup-token"));
    assert!(!serialized.contains("private key"));
}
