use axum::{body::{to_bytes, Body}, http::{Request, StatusCode}, Router};
use bearust::control_plane::{build_state, router};
use tower::util::ServiceExt;

async fn app() -> (Router, String, String) {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let app = router(build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap());
    let setup = app.clone().oneshot(Request::builder().method("POST").uri("/api/setup/initialize").header("content-type", "application/json").body(Body::from(r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#)).unwrap()).await.unwrap();
    assert_eq!(setup.status(), StatusCode::CREATED);
    let login = app.clone().oneshot(Request::builder().method("POST").uri("/api/auth/login").header("content-type", "application/json").body(Body::from(r#"{"email":"admin@example.com","password":"correct horse battery"}"#)).unwrap()).await.unwrap();
    let admin = login.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_owned();
    let create = app.clone().oneshot(Request::builder().method("POST").uri("/api/users").header("cookie", &admin).header("content-type", "application/json").body(Body::from(r#"{"email":"viewer@example.com","password":"viewer password 123","role":"viewer"}"#)).unwrap()).await.unwrap();
    assert_eq!(create.status(), StatusCode::CREATED);
    let viewer_login = app.clone().oneshot(Request::builder().method("POST").uri("/api/auth/login").header("content-type", "application/json").body(Body::from(r#"{"email":"viewer@example.com","password":"viewer password 123"}"#)).unwrap()).await.unwrap();
    let viewer = viewer_login.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_owned();
    (app, admin, viewer)
}

async fn response(app: Router, method: &str, uri: &str, cookie: &str, body: Body) -> (StatusCode, String) {
    let response = app.oneshot(Request::builder().method(method).uri(uri).header("cookie", cookie).header("content-type", "application/json").body(body).unwrap()).await.unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn waf_config_and_rules_require_admin_and_support_custom_crud() {
    let (app, admin, viewer) = app().await;
    assert_eq!(response(app.clone(), "GET", "/api/waf/config", &viewer, Body::empty()).await.0, StatusCode::FORBIDDEN);
    let (status, body) = response(app.clone(), "GET", "/api/waf/config", &admin, Body::empty()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("monitor-only"));
    assert_eq!(response(app.clone(), "PATCH", "/api/waf/config", &admin, Body::from(r#"{"mode":"block"}"#)).await.0, StatusCode::OK);
    let (status, body) = response(app.clone(), "POST", "/api/waf/rules", &admin, Body::from(r#"{"name":"custom","category":"custom","severity":"medium","action":"block","matcher":{"field":"query","pattern":"evil"}}"#)).await;
    assert_eq!(status, StatusCode::CREATED);
    let rule_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"].as_i64().unwrap();
    assert_eq!(response(app.clone(), "PATCH", &format!("/api/waf/rules/{rule_id}"), &admin, Body::from(r#"{"enabled":false}"#)).await.0, StatusCode::OK);
    assert_eq!(response(app, "DELETE", &format!("/api/waf/rules/{rule_id}"), &admin, Body::empty()).await.0, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn toml_import_is_atomic_and_export_round_trips() {
    let (app, admin, _) = app().await;
    let toml = "version = 1\nmode = 'monitor-only'\n\n[[rules]]\nname = 'imported'\ncategory = 'custom'\nseverity = 'low'\naction = 'log'\nfield = 'query'\npattern = 'safe'\n";
    assert_eq!(response(app.clone(), "POST", "/api/waf/rules/import", &admin, Body::from(toml)).await.0, StatusCode::OK);
    let (status, exported) = response(app.clone(), "GET", "/api/waf/rules/export", &admin, Body::empty()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(exported.contains("imported"));
    let bad = "version = 1\n\n[[rules]]\nname = 'bad'\ncategory = 'custom'\nseverity = 'low'\naction = 'block'\nfield = 'query'\npattern = '('\n";
    assert_eq!(response(app.clone(), "POST", "/api/waf/rules/import", &admin, Body::from(bad)).await.0, StatusCode::BAD_REQUEST);
    let (_, after) = response(app, "GET", "/api/waf/rules/export", &admin, Body::empty()).await;
    assert!(after.contains("imported"));
    assert!(!after.contains("name = 'bad'"));
}

#[tokio::test]
async fn waf_mutations_publish_redacted_audit_and_realtime_events() {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let state = bearust::control_plane::build_state("sqlite::memory:", dir.path(), "setup-token").await.unwrap();
    let db = state.db.clone();
    let realtime = state.realtime.clone();
    let app = router(state);
    let setup = app.clone().oneshot(Request::builder().method("POST").uri("/api/setup/initialize").header("content-type", "application/json").body(Body::from(r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#)).unwrap()).await.unwrap();
    assert_eq!(setup.status(), StatusCode::CREATED);
    let login = app.clone().oneshot(Request::builder().method("POST").uri("/api/auth/login").header("content-type", "application/json").body(Body::from(r#"{"email":"admin@example.com","password":"correct horse battery"}"#)).unwrap()).await.unwrap();
    let cookie = login.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_owned();
    let mut events = realtime.subscribe();
    assert_eq!(response(app, "PATCH", "/api/waf/config", &cookie, Body::from(r#"{"mode":"block"}"#)).await.0, StatusCode::OK);
    let first = events.recv().await.unwrap();
    let second = events.recv().await.unwrap();
    assert!(first.kind == "audit" || second.kind == "audit");
    assert!(first.kind == "waf.changed" || second.kind == "waf.changed");
    let details: String = sqlx::query_scalar("SELECT details FROM audit_logs WHERE event='waf_config_updated' ORDER BY created_at DESC LIMIT 1").fetch_one(&db).await.unwrap();
    assert!(!details.contains("token"));
    assert!(!details.contains("body"));
}
