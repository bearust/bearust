use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use bearust::control_plane::repository;
use bearust::control_plane::{build_state, router};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    x509::{X509NameBuilder, X509},
};
use sqlx::Row;
use tower::util::ServiceExt;

async fn app() -> (Router, repository::DbPool) {
    let dir = Box::leak(Box::new(tempfile::tempdir().unwrap()));
    let state = build_state("sqlite::memory:", dir.path(), "setup-token")
        .await
        .unwrap();
    (router(state.clone()), state.db)
}

#[tokio::test]
async fn custom_role_permission_changes_apply_without_relogin() {
    let (app, db) = app().await;
    assert_eq!(json(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await.0, StatusCode::CREATED);
    let (_, admin_cookie) = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let admin_cookie = admin_cookie.unwrap();
    repository::insert_role(&db, "host-writer", "Host Writer", "")
        .await
        .unwrap();
    let role_id: i64 = sqlx::query_scalar("SELECT id FROM roles WHERE slug='host-writer'")
        .fetch_one(&db)
        .await
        .unwrap();
    repository::set_role_permissions(&db, role_id, &["proxy_hosts.read"])
        .await
        .unwrap();
    let (_, body, _) = json(
        app.clone(),
        "POST",
        "/api/users",
        Some(&admin_cookie),
        r#"{"email":"custom@example.com","password":"custom password 123","role":"host-writer"}"#,
    )
    .await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["role"],
        "host-writer"
    );
    let (_, cookie) = login(app.clone(), "custom@example.com", "custom password 123").await;
    let cookie = cookie.unwrap();
    let host = r#"{"name":"custom-host","domain":"custom.example.com","upstream_host":"127.0.0.1","upstream_port":8080}"#;
    assert_eq!(
        json(app.clone(), "POST", "/api/proxy-hosts", Some(&cookie), host)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    repository::set_role_permissions(&db, role_id, &["proxy_hosts.read", "proxy_hosts.write"])
        .await
        .unwrap();
    assert_eq!(
        json(app, "POST", "/api/proxy-hosts", Some(&cookie), host)
            .await
            .0,
        StatusCode::CREATED
    );
}

#[tokio::test]
async fn scoped_proxy_host_routes_filter_and_enforce_mutations() {
    let (app, db) = app().await;
    assert_eq!(json(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await.0, StatusCode::CREATED);
    let (_, admin_cookie) = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let admin_cookie = admin_cookie.unwrap();
    let host = r#"{"name":"scoped-host","domain":"scoped.example.com","upstream_host":"127.0.0.1","upstream_port":8080}"#;
    let (_, first_body, _) = json(
        app.clone(),
        "POST",
        "/api/proxy-hosts",
        Some(&admin_cookie),
        host,
    )
    .await;
    let first_id = serde_json::from_str::<serde_json::Value>(&first_body).unwrap()["id"]
        .as_i64()
        .unwrap();
    let other = r#"{"name":"hidden-host","domain":"hidden.example.com","upstream_host":"127.0.0.1","upstream_port":8081}"#;
    let (_, other_body, _) = json(
        app.clone(),
        "POST",
        "/api/proxy-hosts",
        Some(&admin_cookie),
        other,
    )
    .await;
    let other_id = serde_json::from_str::<serde_json::Value>(&other_body).unwrap()["id"]
        .as_i64()
        .unwrap();
    repository::insert_role(&db, "scoped-route", "Scoped Route", "")
        .await
        .unwrap();
    let role_id: i64 = sqlx::query_scalar("SELECT id FROM roles WHERE slug='scoped-route'")
        .fetch_one(&db)
        .await
        .unwrap();
    repository::set_role_permissions(&db, role_id, &["proxy_hosts.write"])
        .await
        .unwrap();
    sqlx::query("DELETE FROM role_permissions WHERE role_id=? AND scope_type='' AND scope_id=0")
        .bind(role_id)
        .execute(&db)
        .await
        .unwrap();
    let (_, user_body, _) = json(app.clone(), "POST", "/api/users", Some(&admin_cookie), r#"{"email":"scoped-route@example.com","password":"scoped password 123","role":"scoped-route"}"#).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&user_body).unwrap()["role"],
        "scoped-route"
    );
    let permission_id: i64 =
        sqlx::query_scalar("SELECT id FROM permissions WHERE key='proxy_hosts.write'")
            .fetch_one(&db)
            .await
            .unwrap();
    sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) VALUES(?,?, 'proxy_host',?)").bind(role_id).bind(permission_id).bind(first_id).execute(&db).await.unwrap();
    let read_permission_id: i64 =
        sqlx::query_scalar("SELECT id FROM permissions WHERE key='proxy_hosts.read'")
            .fetch_one(&db)
            .await
            .unwrap();
    sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) VALUES(?,?, 'proxy_host',?)").bind(role_id).bind(read_permission_id).bind(first_id).execute(&db).await.unwrap();

    repository::insert_role(&db, "scoped-reader", "Scoped Reader", "")
        .await
        .unwrap();
    let reader_role_id: i64 = sqlx::query_scalar("SELECT id FROM roles WHERE slug='scoped-reader'")
        .fetch_one(&db)
        .await
        .unwrap();
    let (_, reader_body, _) = json(app.clone(), "POST", "/api/users", Some(&admin_cookie), r#"{"email":"scoped-reader@example.com","password":"reader password 123","role":"scoped-reader"}"#).await;
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&reader_body).unwrap()["role"],
        "scoped-reader"
    );
    sqlx::query("INSERT INTO role_permissions(role_id,permission_id,scope_type,scope_id) VALUES(?,?, 'proxy_host',?)").bind(reader_role_id).bind(read_permission_id).bind(first_id).execute(&db).await.unwrap();
    let (_, cookie) = login(
        app.clone(),
        "scoped-route@example.com",
        "scoped password 123",
    )
    .await;
    let cookie = cookie.unwrap();
    let (_, reader_cookie) = login(
        app.clone(),
        "scoped-reader@example.com",
        "reader password 123",
    )
    .await;
    let reader_cookie = reader_cookie.unwrap();
    let (status, body, _) = json(app.clone(), "GET", "/api/proxy-hosts", Some(&cookie), "").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        json(
            app.clone(),
            "GET",
            &format!("/api/proxy-hosts/{other_id}"),
            Some(&cookie),
            ""
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let read_only_update = r#"{"name":"should-not-update","domain":"scoped.example.com","upstream_host":"127.0.0.1","upstream_port":8083}"#;
    assert_eq!(
        json(
            app.clone(),
            "PATCH",
            &format!("/api/proxy-hosts/{first_id}"),
            Some(&reader_cookie),
            read_only_update
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let updated = r#"{"name":"scoped-updated","domain":"scoped.example.com","upstream_host":"127.0.0.1","upstream_port":8082}"#;
    assert_eq!(
        json(
            app.clone(),
            "PATCH",
            &format!("/api/proxy-hosts/{first_id}"),
            Some(&cookie),
            updated
        )
        .await
        .0,
        StatusCode::OK
    );
    let other_updated = r#"{"name":"hidden-updated","domain":"hidden-updated.example.com","upstream_host":"127.0.0.1","upstream_port":8082}"#;
    assert_eq!(
        json(
            app.clone(),
            "PATCH",
            &format!("/api/proxy-hosts/{other_id}"),
            Some(&cookie),
            other_updated
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        json(
            app.clone(),
            "DELETE",
            &format!("/api/proxy-hosts/{other_id}"),
            Some(&cookie),
            ""
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        json(app.clone(), "POST", "/api/proxy-hosts", Some(&cookie), host)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        json(
            app,
            "DELETE",
            &format!("/api/proxy-hosts/{first_id}"),
            Some(&cookie),
            ""
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
}

async fn json(
    app: Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: &str,
) -> (StatusCode, String, Option<String>) {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        request = request.header("cookie", cookie);
    }
    let response = app
        .oneshot(request.body(Body::from(body.to_owned())).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let cookie = response
        .headers()
        .get("set-cookie")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap(), cookie)
}

async fn login(app: Router, email: &str, password: &str) -> (StatusCode, Option<String>) {
    let (status, _, cookie) = json(
        app,
        "POST",
        "/api/auth/login",
        None,
        &format!(r#"{{"email":"{email}","password":"{password}"}}"#),
    )
    .await;
    (
        status,
        cookie.map(|v| v.split(';').next().unwrap().to_owned()),
    )
}

fn certificate_material() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "operator.example.com")
        .unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(openssl::asn1::Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    builder
        .set_not_after(openssl::asn1::Asn1Time::days_from_now(30).unwrap().as_ref())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    (
        builder.build().to_pem().unwrap(),
        key.private_key_to_pem_pkcs8().unwrap(),
    )
}

async fn multipart_certificate(
    app: Router,
    cookie: &str,
    certificate: &[u8],
    key: &[u8],
) -> (StatusCode, String) {
    let boundary = "rbac-boundary";
    let mut body = Vec::new();
    for (name, value) in [
        ("name", b"operator-cert".as_slice()),
        ("certificate", certificate),
        ("key", key),
    ] {
        body.extend_from_slice(
            format!("--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n")
                .as_bytes(),
        );
        body.extend_from_slice(value);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/certificates")
                .header("cookie", cookie)
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

#[tokio::test]
async fn operator_can_write_hosts_and_certificates_while_viewer_is_read_only() {
    let (app, _) = app().await;
    assert_eq!(json(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await.0, StatusCode::CREATED);
    let (_, admin_cookie) = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let admin_cookie = admin_cookie.unwrap();
    let (_, op_body, _) = json(
        app.clone(),
        "POST",
        "/api/users",
        Some(&admin_cookie),
        r#"{"email":"operator@example.com","password":"operator password 123","role":"operator"}"#,
    )
    .await;
    assert!(!op_body.is_empty());
    let (_, viewer_body, _) = json(
        app.clone(),
        "POST",
        "/api/users",
        Some(&admin_cookie),
        r#"{"email":"viewer@example.com","password":"viewer password 123","role":"viewer"}"#,
    )
    .await;
    assert!(!viewer_body.is_empty());
    let (_, op_cookie) = login(app.clone(), "operator@example.com", "operator password 123").await;
    let (_, viewer_cookie) = login(app.clone(), "viewer@example.com", "viewer password 123").await;
    let op_cookie = op_cookie.unwrap();
    let viewer_cookie = viewer_cookie.unwrap();
    let host = r#"{"name":"operator-host","domain":"operator.example.com","upstream_host":"127.0.0.1","upstream_port":8080}"#;
    let (status, host_body, _) = json(
        app.clone(),
        "POST",
        "/api/proxy-hosts",
        Some(&op_cookie),
        host,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let host_id = serde_json::from_str::<serde_json::Value>(&host_body).unwrap()["id"]
        .as_i64()
        .unwrap();
    assert_eq!(
        json(
            app.clone(),
            "POST",
            "/api/proxy-hosts",
            Some(&viewer_cookie),
            host
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let updated_host = r#"{"name":"operator-host-updated","domain":"operator.example.com","upstream_host":"127.0.0.1","upstream_port":8081}"#;
    assert_eq!(
        json(
            app.clone(),
            "PATCH",
            &format!("/api/proxy-hosts/{host_id}"),
            Some(&op_cookie),
            updated_host
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        json(
            app.clone(),
            "PATCH",
            &format!("/api/proxy-hosts/{host_id}"),
            Some(&viewer_cookie),
            updated_host
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        json(
            app.clone(),
            "DELETE",
            &format!("/api/proxy-hosts/{host_id}"),
            Some(&viewer_cookie),
            ""
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        json(
            app.clone(),
            "DELETE",
            &format!("/api/proxy-hosts/{host_id}"),
            Some(&op_cookie),
            ""
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    let (certificate, key) = certificate_material();
    let (status, certificate_body) =
        multipart_certificate(app.clone(), &op_cookie, &certificate, &key).await;
    assert_eq!(status, StatusCode::CREATED);
    let certificate_id = serde_json::from_str::<serde_json::Value>(&certificate_body).unwrap()
        ["id"]
        .as_i64()
        .unwrap();
    assert_eq!(
        json(
            app.clone(),
            "POST",
            &format!("/api/certificates/{certificate_id}/activate"),
            Some(&op_cookie),
            ""
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        json(
            app.clone(),
            "POST",
            &format!("/api/certificates/{certificate_id}/activate"),
            Some(&viewer_cookie),
            ""
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        multipart_certificate(app, &viewer_cookie, &certificate, &key)
            .await
            .0,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn initial_setup_normalizes_email_like_admin_user_creation() {
    let (app, _) = app().await;
    assert_eq!(json(app.clone(), "POST", "/api/setup/initialize", None,
        r#"{"email":"  Admin@Example.COM ","password":"correct horse battery","setup_token":"setup-token"}"#).await.0, StatusCode::CREATED);
    let (status, body, _) = json(app.clone(), "GET", "/api/auth/me", None, "").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body.is_empty() || body.contains("Unauthorized") || body.contains("unauthorized"));
    let (status, cookie) =
        login(app.clone(), "  ADMIN@EXAMPLE.COM ", "correct horse battery").await;
    assert_eq!(status, StatusCode::OK);
    assert!(cookie.is_some());
}

#[tokio::test]
async fn concurrent_initial_setup_creates_exactly_one_admin() {
    let (app, db) = app().await;
    let request = |email: &'static str| {
        let app = app.clone();
        async move {
            json(app, "POST", "/api/setup/initialize", None,
                &format!(r#"{{"email":"{email}","password":"correct horse battery","setup_token":"setup-token"}}"#)).await
        }
    };
    let (first, second) = tokio::join!(request("first@example.com"), request("second@example.com"));
    assert_eq!(
        [first.0, second.0]
            .into_iter()
            .filter(|s| *s == StatusCode::CREATED)
            .count(),
        1
    );
    assert_eq!(
        [first.0, second.0]
            .into_iter()
            .filter(|s| *s == StatusCode::CONFLICT)
            .count(),
        1
    );
    let rows = sqlx::query("SELECT email,role FROM users")
        .fetch_all(&db)
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].get::<String, _>("role"), "admin");
}

#[tokio::test]
async fn admin_user_crud_redacts_secrets_and_enforces_invariants() {
    let (app, db) = app().await;
    let (status, _, _) = json(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await;
    assert_eq!(status, StatusCode::CREATED);
    let (_, cookie) = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let cookie = cookie.unwrap();
    let (status, body, _) = json(app.clone(), "GET", "/api/users", Some(&cookie), "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("password_hash"));
    let (status, body, _) = json(
        app.clone(),
        "POST",
        "/api/users",
        Some(&cookie),
        r#"{"email":"operator@example.com","password":"operator password 123","role":"operator"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert!(!body.contains("password_hash"));
    let id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_i64()
        .unwrap();
    let (status, _, _) = json(
        app.clone(),
        "PATCH",
        &format!("/api/users/{id}"),
        Some(&cookie),
        r#"{"disabled":true}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = login(app.clone(), "operator@example.com", "operator password 123").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let (status, _, _) = json(
        app.clone(),
        "DELETE",
        &format!("/api/users/{id}"),
        Some(&cookie),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let admin_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE email='admin@example.com'")
        .fetch_one(&db)
        .await
        .unwrap();
    let (status, _, _) = json(
        app.clone(),
        "DELETE",
        &format!("/api/users/{admin_id}"),
        Some(&cookie),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let rows =
        sqlx::query("SELECT event,details FROM audit_logs WHERE event LIKE 'user_%' ORDER BY id")
            .fetch_all(&db)
            .await
            .unwrap();
    assert!(rows
        .iter()
        .any(|r| r.get::<String, _>("event") == "user_created"));
    assert!(rows
        .iter()
        .any(|r| r.get::<String, _>("event") == "user_disabled"));
    assert!(rows
        .iter()
        .any(|r| r.get::<String, _>("event") == "user_deleted"));
    for row in rows {
        assert!(!row.get::<String, _>("details").contains("password"));
    }
}

#[tokio::test]
async fn role_authorization_and_denials_are_enforced_and_audited() {
    let (app, db) = app().await;
    assert_eq!(json(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await.0, StatusCode::CREATED);
    let (_, admin_cookie) = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let admin_cookie = admin_cookie.unwrap();
    let (_, op_body, _) = json(
        app.clone(),
        "POST",
        "/api/users",
        Some(&admin_cookie),
        r#"{"email":"operator@example.com","password":"operator password 123","role":"operator"}"#,
    )
    .await;
    let op_id = serde_json::from_str::<serde_json::Value>(&op_body).unwrap()["id"]
        .as_i64()
        .unwrap();
    let (_, viewer_body, _) = json(
        app.clone(),
        "POST",
        "/api/users",
        Some(&admin_cookie),
        r#"{"email":"viewer@example.com","password":"viewer password 123","role":"viewer"}"#,
    )
    .await;
    let viewer_id = serde_json::from_str::<serde_json::Value>(&viewer_body).unwrap()["id"]
        .as_i64()
        .unwrap();
    let (_, op_cookie) = login(app.clone(), "operator@example.com", "operator password 123").await;
    let (_, viewer_cookie) = login(app.clone(), "viewer@example.com", "viewer password 123").await;
    for cookie in [op_cookie.as_deref(), viewer_cookie.as_deref()] {
        assert_eq!(
            json(app.clone(), "GET", "/api/users", cookie, "").await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            json(
                app.clone(),
                "PATCH",
                &format!("/api/users/{op_id}"),
                cookie,
                r#"{"disabled":true}"#
            )
            .await
            .0,
            StatusCode::FORBIDDEN
        );
    }
    let admin_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE email='admin@example.com'")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        json(
            app.clone(),
            "PATCH",
            &format!("/api/users/{admin_id}"),
            Some(&admin_cookie),
            r#"{"disabled":true}"#
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        json(
            app.clone(),
            "DELETE",
            &format!("/api/users/{admin_id}"),
            Some(&admin_cookie),
            ""
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        json(
            app.clone(),
            "PATCH",
            &format!("/api/users/{viewer_id}"),
            Some(&admin_cookie),
            r#"{"role":"bogus","disabled":true}"#
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        json(
            app.clone(),
            "PATCH",
            "/api/users/9999",
            Some(&admin_cookie),
            r#"{"disabled":true}"#
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    let rows = sqlx::query("SELECT event,details FROM audit_logs WHERE event LIKE '%denied' OR event LIKE 'user_%_denied'").fetch_all(&db).await.unwrap();
    assert!(rows.len() >= 5);
    assert!(rows
        .iter()
        .all(|r| r.get::<String, _>("details").contains("reason=")));
}

#[tokio::test]
async fn admin_can_create_and_update_users_with_custom_roles_but_rejects_unknown_roles() {
    let (app, db) = app().await;
    assert_eq!(json(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await.0, StatusCode::CREATED);
    let (_, cookie) = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let cookie = cookie.unwrap();
    let role = repository::insert_role(&db, "security-auditor", "Security Auditor", "custom role")
        .await
        .unwrap();
    let (status, body, _) = json(app.clone(), "POST", "/api/users", Some(&cookie), r#"{"email":"auditor@example.com","password":"auditor password 123","role":"security-auditor"}"#).await;
    assert_eq!(status, StatusCode::CREATED);
    let user_id = serde_json::from_str::<serde_json::Value>(&body).unwrap()["id"]
        .as_i64()
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["role"],
        role.slug
    );
    let (status, body, _) = json(
        app.clone(),
        "PATCH",
        &format!("/api/users/{user_id}"),
        Some(&cookie),
        r#"{"role":"security-auditor"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["role"],
        "security-auditor"
    );
    assert_eq!(json(app.clone(), "POST", "/api/users", Some(&cookie), r#"{"email":"unknown@example.com","password":"unknown password 123","role":"missing-role"}"#).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(
        json(
            app,
            "PATCH",
            &format!("/api/users/{user_id}"),
            Some(&cookie),
            r#"{"role":"missing-role"}"#
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn administrator_can_revoke_target_sessions_but_not_own_or_viewer_sessions() {
    let (app, db) = app().await;
    assert_eq!(json(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await.0, StatusCode::CREATED);
    let (_, admin_cookie) = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let admin_cookie = admin_cookie.unwrap();
    let (_, target_body, _) = json(
        app.clone(),
        "POST",
        "/api/users",
        Some(&admin_cookie),
        r#"{"email":"target@example.com","password":"target password 123","role":"viewer"}"#,
    )
    .await;
    let target_id = serde_json::from_str::<serde_json::Value>(&target_body).unwrap()["id"]
        .as_i64()
        .unwrap();
    let (_, target_cookie) = login(app.clone(), "target@example.com", "target password 123").await;
    let target_cookie = target_cookie.unwrap();
    repository::create_session(&db, target_id, "target-extra", "2999-01-01T00:00:00Z")
        .await
        .unwrap();
    let (status, body, _) = json(
        app.clone(),
        "POST",
        &format!("/api/users/{target_id}/sessions/revoke"),
        Some(&admin_cookie),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).unwrap()["revoked"],
        2
    );
    assert_eq!(
        json(app.clone(), "GET", "/api/auth/me", Some(&target_cookie), "")
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    let admin_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE email='admin@example.com'")
        .fetch_one(&db)
        .await
        .unwrap();
    assert_eq!(
        json(
            app.clone(),
            "POST",
            &format!("/api/users/{admin_id}/sessions/revoke"),
            Some(&admin_cookie),
            ""
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let rows = sqlx::query("SELECT event,details FROM audit_logs WHERE event IN ('sessions_revoked','session_revoke_denied')").fetch_all(&db).await.unwrap();
    assert!(rows
        .iter()
        .any(|r| r.get::<String, _>("event") == "sessions_revoked"));
    assert!(rows
        .iter()
        .all(|r| !r.get::<String, _>("details").contains("target-extra")));
}

#[tokio::test]
async fn combined_patch_is_atomic_when_last_admin_would_be_removed() {
    let (app, db) = app().await;
    assert_eq!(json(app.clone(), "POST", "/api/setup/initialize", None, r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#).await.0, StatusCode::CREATED);
    let (_, cookie) = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let cookie = cookie.unwrap();
    let admin_id: i64 = sqlx::query_scalar("SELECT id FROM users WHERE email='admin@example.com'")
        .fetch_one(&db)
        .await
        .unwrap();
    let (status, _body, _) = json(
        app.clone(),
        "PATCH",
        &format!("/api/users/{admin_id}"),
        Some(&cookie),
        r#"{"role":"viewer"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body, _) = json(app.clone(), "GET", "/api/auth/me", Some(&cookie), "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("admin"));
}
