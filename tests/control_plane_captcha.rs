//! CAPTCHA-backed bot challenges against a mock provider siteverify.

use axum::{
    body::{to_bytes, Body},
    extract::Form,
    http::{Request, StatusCode},
    routing::post,
    Json, Router,
};
use bearust::control_plane::{build_state, router};
use serde_json::{json, Value};
use std::collections::HashMap;
use tower::util::ServiceExt;

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, String, Option<String>) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    let response = app
        .clone()
        .oneshot(
            req.body(body.map_or_else(Body::empty, |b| Body::from(b.to_string())))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get("set-cookie")
        .map(|v| v.to_str().unwrap().split(';').next().unwrap().to_owned());
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, String::from_utf8_lossy(&body).into_owned(), cookie)
}

async fn spawn_siteverify() -> String {
    let app = Router::new().route(
        "/siteverify",
        post(|Form(form): Form<HashMap<String, String>>| async move {
            let ok = form.get("secret").map(String::as_str) == Some("s3cret")
                && form.get("response").map(String::as_str) == Some("good-token");
            Json(json!({ "success": ok }))
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/siteverify", listener.local_addr().unwrap());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    url
}

#[tokio::test]
async fn configured_captcha_replaces_proof_of_work_and_keeps_token_binding() {
    let dir = tempfile::tempdir().unwrap();
    let mut state = build_state("sqlite::memory:", dir.path(), "setup-token")
        .await
        .unwrap();
    state.captcha_verify_url = Some(spawn_siteverify().await);
    let app = router(state);
    call(&app, "POST", "/api/setup/initialize", None, Some(json!({
        "email": "admin@example.com", "password": "correct horse battery", "setup_token": "setup-token"
    }))).await;
    let (_, _, admin) = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "email": "admin@example.com", "password": "correct horse battery"
        })),
    )
    .await;
    let admin = admin.unwrap();

    let fingerprint = "abcdef0123456789abcdef0123456789";
    // No CAPTCHA configured: proof-of-work challenge, no captcha field.
    let (_, body, _) = call(
        &app,
        "POST",
        "/api/bot/challenge",
        None,
        Some(json!({ "fingerprint": fingerprint })),
    )
    .await;
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["captcha"],
        Value::Null
    );

    for bad in [
        json!({ "provider": "turnstile", "site_key": "" }),
        json!({ "provider": "turnstile", "site_key": "has spaces" }),
        json!({ "provider": "nope", "site_key": "x" }),
    ] {
        let (status, _, _) = call(
            &app,
            "PUT",
            "/api/bot/captcha",
            Some(&admin),
            Some(bad.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{bad}");
    }
    let (status, body, _) = call(
        &app,
        "PUT",
        "/api/bot/captcha",
        Some(&admin),
        Some(json!({
            "provider": "turnstile", "site_key": "0x4AAAAAAA-site", "secret": "s3cret"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains(r#""has_secret":true"#) && !body.contains("s3cret"));

    let challenge = |app: Router| async move {
        let (_, body, _) = call(
            &app,
            "POST",
            "/api/bot/challenge",
            None,
            Some(json!({ "fingerprint": fingerprint })),
        )
        .await;
        serde_json::from_str::<Value>(&body).unwrap()
    };
    let issued = challenge(app.clone()).await;
    assert_eq!(
        issued["captcha"],
        json!({ "provider": "turnstile", "site_key": "0x4AAAAAAA-site" })
    );
    let token = issued["token"].as_str().unwrap().to_owned();

    // A wrong provider response fails; proof-of-work is not accepted instead.
    let (status, _, _) = call(
        &app,
        "POST",
        "/api/bot/challenge/verify",
        None,
        Some(json!({
            "token": token, "fingerprint": fingerprint, "captcha_response": "bad-token"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, cookie) = call(
        &app,
        "POST",
        "/api/bot/challenge/verify",
        None,
        Some(json!({
            "token": token, "fingerprint": fingerprint, "captcha_response": "good-token"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(cookie.unwrap().starts_with("bearust_bot_clear="));
    // Single use.
    let (status, _, _) = call(
        &app,
        "POST",
        "/api/bot/challenge/verify",
        None,
        Some(json!({
            "token": token, "fingerprint": fingerprint, "captcha_response": "good-token"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // Bound to the fingerprint it was issued for.
    let other = challenge(app.clone()).await["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _, _) = call(
        &app,
        "POST",
        "/api/bot/challenge/verify",
        None,
        Some(json!({
            "token": other, "fingerprint": "ffffffffffffffff0000", "captcha_response": "good-token"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}
