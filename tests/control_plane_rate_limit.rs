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
    let viewer_create = app.clone().oneshot(Request::builder().method("POST").uri("/api/users").header("cookie", &admin).header("content-type", "application/json").body(Body::from(r#"{"email":"viewer@example.com","password":"viewer password 123","role":"viewer"}"#)).unwrap()).await.unwrap();
    assert_eq!(viewer_create.status(), StatusCode::CREATED);
    let viewer_login = app.clone().oneshot(Request::builder().method("POST").uri("/api/auth/login").header("content-type", "application/json").body(Body::from(r#"{"email":"viewer@example.com","password":"viewer password 123"}"#)).unwrap()).await.unwrap();
    let viewer = viewer_login.headers().get("set-cookie").unwrap().to_str().unwrap().split(';').next().unwrap().to_owned();
    (app, admin, viewer)
}

async fn request(app: Router, method: &str, cookie: &str, body: Body) -> (StatusCode, String) {
    let response = app.oneshot(Request::builder().method(method).uri("/api/rate-limit/config").header("cookie", cookie).header("content-type", "application/json").body(body).unwrap()).await.unwrap();
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

#[tokio::test]
async fn defaults_are_monitor_only_and_mutations_are_admin_only() {
    let (app, admin, viewer) = app().await;
    assert_eq!(request(app.clone(), "GET", &viewer, Body::empty()).await.0, StatusCode::FORBIDDEN);
    let (status, body) = request(app.clone(), "GET", &admin, Body::empty()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"enabled\":false"));
    assert!(body.contains("\"action\":\"monitor\""));
    assert_eq!(request(app.clone(), "PATCH", &admin, Body::from(r#"{"capacity":0}"#)).await.0, StatusCode::BAD_REQUEST);
    let (status, body) = request(app, "PATCH", &admin, Body::from(r#"{"enabled":true,"action":"block","capacity":10,"refill_per_second":2.5,"key_scope":"proxy_host_ip"}"#)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("\"action\":\"block\""));
}
