use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
};
use bearust::control_plane::{build_state, repository, router};
use tower::util::ServiceExt;

#[tokio::test]
async fn fresh_install_waf_defaults_and_admin_mode_change_are_persistent() {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let state = build_state("sqlite::memory:", dir.path(), "setup-token")
        .await
        .unwrap();
    assert_eq!(
        repository::get_waf_config(&state.db).await.unwrap().mode,
        bearust::control_plane::models::WafMode::MonitorOnly
    );
    let app = router(state.clone());
    let setup = app.clone().oneshot(Request::builder().method("POST").uri("/api/setup/initialize").header("content-type", "application/json").body(Body::from(r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#)).unwrap()).await.unwrap();
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
    let response = app
        .oneshot(
            Request::builder()
                .method("PATCH")
                .uri("/api/waf/config")
                .header("cookie", cookie)
                .header("content-type", "application/json")
                .body(Body::from(r#"{"mode":"block"}"#))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    let _ = to_bytes(response.into_body(), 1024).await.unwrap();
    assert_eq!(
        repository::get_waf_config(&state.db).await.unwrap().mode,
        bearust::control_plane::models::WafMode::Block
    );
}
