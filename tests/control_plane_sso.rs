//! OIDC single sign-on against an in-process mock identity provider.

use axum::{
    body::{to_bytes, Body},
    extract::{Form, State},
    http::{Request, StatusCode},
    routing::{get, post},
    Json, Router,
};
use bearust::control_plane::{build_state, router};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tower::util::ServiceExt;

fn b64url(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            n |= u32::from(*b) << (16 - 8 * i);
        }
        for i in 0..=chunk.len() {
            out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

#[derive(Default)]
struct IdpState {
    /// code -> (code_challenge, nonce)
    codes: HashMap<String, (String, String)>,
    /// Overrides applied to the next ID token.
    tamper: Option<&'static str>,
    email: String,
}

struct Idp {
    issuer: String,
    key: jsonwebtoken::EncodingKey,
    state: Mutex<IdpState>,
}

async fn spawn_idp() -> Arc<Idp> {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let issuer = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
    let keypair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let raw = keypair.public_key_raw();
    let jwk = json!({
        "kty": "EC", "crv": "P-256", "kid": "k1", "alg": "ES256", "use": "sig",
        "x": b64url(&raw[1..33]), "y": b64url(&raw[33..65]),
    });
    let idp = Arc::new(Idp {
        issuer: issuer.clone(),
        key: jsonwebtoken::EncodingKey::from_ec_pem(keypair.serialize_pem().as_bytes()).unwrap(),
        state: Mutex::new(IdpState {
            email: "Alice@Example.com".into(),
            ..Default::default()
        }),
    });
    let discovery = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "jwks_uri": format!("{issuer}/jwks"),
    });
    let app = Router::new()
        .route(
            "/.well-known/openid-configuration",
            get(move || async move { Json(discovery) }),
        )
        .route(
            "/jwks",
            get(move || async move { Json(json!({ "keys": [jwk] })) }),
        )
        .route("/token", post(token))
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

async fn token(
    State(idp): State<Arc<Idp>>,
    Form(form): Form<HashMap<String, String>>,
) -> Result<Json<Value>, StatusCode> {
    let mut state = idp.state.lock().unwrap();
    let (challenge, nonce) = state
        .codes
        .remove(form.get("code").ok_or(StatusCode::BAD_REQUEST)?)
        .ok_or(StatusCode::BAD_REQUEST)?;
    // PKCE: the verifier must hash to the challenge sent at /authorize.
    let verifier = form.get("code_verifier").ok_or(StatusCode::BAD_REQUEST)?;
    if b64url(&Sha256::digest(verifier.as_bytes())) != challenge
        || form.get("client_secret").map(String::as_str) != Some("s3cret")
    {
        return Err(StatusCode::BAD_REQUEST);
    }
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "iss": idp.issuer, "aud": "bearust", "sub": "user-123",
        "iat": now, "exp": now + 300, "nonce": nonce,
        "email": state.email, "email_verified": true,
    });
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    header.kid = Some("k1".into());
    match state.tamper.take() {
        Some("nonce") => claims["nonce"] = json!("other"),
        Some("audience") => claims["aud"] = json!("someone-else"),
        Some("unverified") => claims["email_verified"] = json!(false),
        Some("hs256") => {
            let token = jsonwebtoken::encode(
                &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
                &claims,
                &jsonwebtoken::EncodingKey::from_secret(b"bearust"),
            )
            .unwrap();
            return Ok(Json(json!({ "id_token": token })));
        }
        _ => {}
    }
    let token = jsonwebtoken::encode(&header, &claims, &idp.key).unwrap();
    Ok(Json(json!({ "id_token": token, "access_token": "unused" })))
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, HashMap<String, Vec<String>>, String) {
    let mut req = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    let body = match body {
        Some(body) => {
            req = req.header("content-type", "application/json");
            Body::from(body.to_string())
        }
        None => Body::empty(),
    };
    let response = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    for (name, value) in response.headers() {
        headers
            .entry(name.as_str().to_owned())
            .or_default()
            .push(value.to_str().unwrap().to_owned());
    }
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn cookie_value(headers: &HashMap<String, Vec<String>>, name: &str) -> Option<String> {
    headers.get("set-cookie")?.iter().find_map(|c| {
        let pair = c.split(';').next()?;
        pair.strip_prefix(&format!("{name}="))
            .filter(|v| !v.is_empty())
            .map(|v| format!("{name}={v}"))
    })
}

/// Run `/start`, record the authorization at the IdP, and return
/// `(state, state_cookie)`.
async fn start_login(app: &Router, idp: &Idp) -> (String, String) {
    let (status, headers, _) = call(app, "GET", "/api/auth/sso/corp/start", None, None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let location = &headers["location"][0];
    assert!(
        location.starts_with(&format!("{}/authorize?", idp.issuer)),
        "{location}"
    );
    let query: HashMap<String, String> =
        serde_urlencoded::from_str(location.split_once('?').unwrap().1).unwrap();
    assert_eq!(query["code_challenge_method"], "S256");
    assert_eq!(
        query["redirect_uri"],
        "https://bearust.example.com/api/auth/sso/corp/callback"
    );
    idp.state.lock().unwrap().codes.insert(
        "code-1".into(),
        (query["code_challenge"].clone(), query["nonce"].clone()),
    );
    (
        query["state"].clone(),
        cookie_value(&headers, "bearust_sso").unwrap(),
    )
}

#[tokio::test]
async fn oidc_login_provisions_links_and_rejects_tampered_callbacks() {
    let idp = spawn_idp().await;
    let dir = tempfile::tempdir().unwrap();
    let app = router(
        build_state("sqlite::memory:", dir.path(), "setup-token")
            .await
            .unwrap(),
    );
    let (status, _, _) = call(&app, "POST", "/api/setup/initialize", None, Some(json!({
        "email": "admin@example.com", "password": "correct horse battery", "setup_token": "setup-token"
    }))).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, headers, _) = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "email": "admin@example.com", "password": "correct horse battery"
        })),
    )
    .await;
    let admin = cookie_value(&headers, "bearust_session").unwrap();

    let provider = json!({
        "slug": "corp", "kind": "oidc", "name": "Corp SSO", "client_secret": "s3cret",
        "config": {
            "issuer": idp.issuer, "client_id": "bearust",
            "redirect_base_url": "https://bearust.example.com",
            "default_role": "viewer", "auto_provision": true,
            "allowed_domains": ["example.com"]
        }
    });
    let (status, _, body) = call(
        &app,
        "PUT",
        "/api/sso/providers/corp",
        Some(&admin),
        Some(provider.clone()),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body.contains(r#""has_secret":true"#) && !body.contains("s3cret"));
    let (_, _, public) = call(&app, "GET", "/api/auth/sso/providers", None, None).await;
    assert_eq!(
        public,
        r#"[{"slug":"corp","name":"Corp SSO","kind":"oidc"}]"#
    );

    // Happy path: provisions a viewer and issues a session.
    let (state, state_cookie) = start_login(&app, &idp).await;
    let callback = format!("/api/auth/sso/corp/callback?code=code-1&state={state}");
    let (status, headers, _) = call(&app, "GET", &callback, Some(&state_cookie), None).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers["location"][0], "/");
    let session = cookie_value(&headers, "bearust_session").expect("session issued");
    let (status, _, me) = call(&app, "GET", "/api/auth/me", Some(&session), None).await;
    assert_eq!(status, StatusCode::OK);
    let me: Value = serde_json::from_str(&me).unwrap();
    assert_eq!(
        (me["email"].as_str(), me["role"].as_str()),
        (Some("alice@example.com"), Some("viewer"))
    );
    // The provisioned account has no usable password.
    let (status, _, _) = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        Some(json!({
            "email": "alice@example.com", "password": "!sso-only"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    // The state is single-use.
    let (_, headers, _) = call(&app, "GET", &callback, Some(&state_cookie), None).await;
    assert_eq!(headers["location"][0], "/login?sso_error=state_expired");

    // Callback from a different browser (no or wrong state cookie).
    let (state, _) = start_login(&app, &idp).await;
    let (_, headers, _) = call(
        &app,
        "GET",
        &format!("/api/auth/sso/corp/callback?code=code-1&state={state}"),
        Some("bearust_sso=forged"),
        None,
    )
    .await;
    assert_eq!(headers["location"][0], "/login?sso_error=state_mismatch");

    // Tampered ID tokens are rejected.
    for tamper in ["nonce", "audience", "hs256"] {
        let (state, cookie) = start_login(&app, &idp).await;
        idp.state.lock().unwrap().tamper = Some(tamper);
        let (_, headers, _) = call(
            &app,
            "GET",
            &format!("/api/auth/sso/corp/callback?code=code-1&state={state}"),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(
            headers["location"][0], "/login?sso_error=token_rejected",
            "{tamper}"
        );
        assert!(cookie_value(&headers, "bearust_session").is_none());
    }

    // A second login reuses the link even if the email changes.
    idp.state.lock().unwrap().email = "alice.renamed@example.com".into();
    let (state, cookie) = start_login(&app, &idp).await;
    let (_, headers, _) = call(
        &app,
        "GET",
        &format!("/api/auth/sso/corp/callback?code=code-1&state={state}"),
        Some(&cookie),
        None,
    )
    .await;
    let session = cookie_value(&headers, "bearust_session").expect("linked login");
    let (_, _, me) = call(&app, "GET", "/api/auth/me", Some(&session), None).await;
    assert!(me.contains("alice@example.com"));

    // Disallowed domains and unverified emails cannot provision accounts.
    let mut other = provider.clone();
    other["slug"] = json!("other");
    let (status, _, _) = call(
        &app,
        "PUT",
        "/api/sso/providers/other",
        Some(&admin),
        Some(other),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    for (email, tamper) in [
        ("mallory@evil.test", None),
        ("bob@example.com", Some("unverified")),
    ] {
        let (_, headers, _) = call(&app, "GET", "/api/auth/sso/other/start", None, None).await;
        let location = &headers["location"][0];
        let query: HashMap<String, String> =
            serde_urlencoded::from_str(location.split_once('?').unwrap().1).unwrap();
        {
            let mut state = idp.state.lock().unwrap();
            state.codes.insert(
                "code-1".into(),
                (query["code_challenge"].clone(), query["nonce"].clone()),
            );
            state.email = email.into();
            state.tamper = tamper;
        }
        let cookie = cookie_value(&headers, "bearust_sso").unwrap();
        let (_, headers, _) = call(
            &app,
            "GET",
            &format!(
                "/api/auth/sso/other/callback?code=code-1&state={}",
                query["state"]
            ),
            Some(&cookie),
            None,
        )
        .await;
        assert_eq!(
            headers["location"][0], "/login?sso_error=domain_not_allowed",
            "{email}"
        );
    }

    // Only settings administrators manage providers.
    let (status, _, _) = call(&app, "GET", "/api/sso/providers", Some(&session), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let (status, _, _) = call(
        &app,
        "DELETE",
        "/api/sso/providers/corp",
        Some(&admin),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (_, headers, _) = call(&app, "GET", "/api/auth/sso/corp/start", None, None).await;
    assert_eq!(headers["location"][0], "/login?sso_error=unknown_provider");
}
