mod support;

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use bearust::{
    config::PluginConfig,
    control_plane::{audit, build_state, repository, router},
    plugin_runtime::PluginManager,
};
use serde_json::Value;
use std::{fs, path::Path, sync::Once};
use tower::util::ServiceExt;

async fn app() -> (Router, repository::DbPool, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let mut state = build_state("sqlite::memory:", dir.path(), "setup-token")
        .await
        .unwrap();
    let manager = PluginManager::new(PluginConfig {
        enabled: true,
        directory: dir.path().join("plugins"),
        ..PluginConfig::default()
    });
    manager.attach_realtime(state.realtime.clone());
    manager.attach_audit_sink(std::sync::Arc::new(audit::PluginAuditDbSink::new(
        state.db.clone(),
        state.realtime.clone(),
    )));
    state.plugin_manager = manager;
    (router(state.clone()), state.db, dir)
}

async fn request(
    app: Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
) -> (StatusCode, String) {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let response = app
        .oneshot(builder.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = response.status();
    let body = to_bytes(response.into_body(), 1024 * 1024).await.unwrap();
    (status, String::from_utf8(body.to_vec()).unwrap())
}

async fn json_request(
    app: Router,
    method: &str,
    uri: &str,
    body: &str,
    cookie: Option<&str>,
) -> (StatusCode, String, Option<String>) {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    let response = app
        .oneshot(builder.body(Body::from(body.to_owned())).unwrap())
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

async fn login(app: Router, email: &str, password: &str) -> String {
    json_request(
        app,
        "POST",
        "/api/auth/login",
        &format!(r#"{{"email":"{email}","password":"{password}"}}"#),
        None,
    )
    .await
    .2
    .unwrap()
    .split(';')
    .next()
    .unwrap()
    .to_owned()
}

fn write_plugin(root: &Path) {
    let plugin = root.join("plugins/demo");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        r#"id = "demo-plugin"
display_name = "Demo plugin"
abi_version = 1
module = "demo.wasm"
capabilities = ["health_check"]
[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1024
"#,
    )
    .unwrap();
    fs::write(
        plugin.join("demo.wasm"),
        wat::parse_str(
            r#"(module
      (func (export "bearust_abi_version") (result i32) i32.const 1)
      (func (export "bearust_health_check") (result i32) i32.const 7))"#,
        )
        .unwrap(),
    )
    .unwrap();
}

fn write_plugin_v2(root: &Path) {
    let plugin = root.join("plugins/demo-v2");
    fs::create_dir_all(&plugin).unwrap();
    fs::write(
        plugin.join("plugin.toml"),
        r#"id = "demo-plugin-v2"
display_name = "Demo plugin v2"
abi_version = 2
module = "demo.wasm"
capabilities = ["health_check"]
[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1024
"#,
    )
    .unwrap();
    fs::write(
        plugin.join("demo.wasm"),
        wat::parse_str(
            r#"(module
      (memory (export "memory") 1)
      (data (i32.const 0) "{\22healthy\22:true,\22detail\22:\22from-api\22}")
      (func (export "bearust_abi_version") (result i32) i32.const 2)
      (func (export "bearust_alloc") (param i32) (result i32) i32.const 1024)
      (func (export "bearust_dealloc") (param i32 i32))
      (func (export "bearust_health_check_v2") (param i32 i32) (result i64)
        (i64.or
          (i64.shl (i64.extend_i32_u (i32.const 0)) (i64.const 32))
          (i64.extend_i32_u (i32.const 36)))))"#,
        )
        .unwrap(),
    )
    .unwrap();
}

#[tokio::test]
async fn admin_can_run_bounded_plugin_lifecycle() {
    let (app, db, dir) = app().await;
    write_plugin(dir.path());
    assert_eq!(json_request(app.clone(), "POST", "/api/setup/initialize", r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#, None).await.0, StatusCode::CREATED);
    let admin = login(app.clone(), "admin@example.com", "correct horse battery").await;
    let (status, body) = request(app.clone(), "GET", "/api/plugins", Some(&admin)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        serde_json::from_str::<Value>(&body)
            .unwrap()
            .as_array()
            .unwrap()
            .len(),
        0
    );
    let (status, body, _) =
        json_request(app.clone(), "POST", "/api/plugins/reload", "", Some(&admin)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["loaded"], 1);
    let audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE event='plugin_lifecycle'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(audit_count, 1);
    let (status, body) = request(app.clone(), "GET", "/api/plugins", Some(&admin)).await;
    assert_eq!(status, StatusCode::OK);
    let listed = serde_json::from_str::<Value>(&body).unwrap();
    assert!(listed[0].get("source_dir").is_none());
    assert!(listed[0].get("module").is_none());
    let (status, body) = request(
        app.clone(),
        "POST",
        "/api/plugins/demo-plugin/health-check",
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let health = serde_json::from_str::<Value>(&body).unwrap();
    assert_eq!(health["status"], 7);
    assert!(health.get("source_dir").is_none() && health.get("module").is_none());
    assert_eq!(
        request(
            app.clone(),
            "POST",
            "/api/plugins/demo-plugin/disable",
            Some(&admin)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            app.clone(),
            "POST",
            "/api/plugins/demo-plugin/health-check",
            Some(&admin)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    assert_eq!(
        request(
            app.clone(),
            "POST",
            "/api/plugins/demo-plugin/enable",
            Some(&admin)
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        request(
            app.clone(),
            "DELETE",
            "/api/plugins/demo-plugin",
            Some(&admin)
        )
        .await
        .0,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        request(app, "GET", "/api/plugins", Some(&admin)).await.1,
        "[]"
    );
    let audit_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE event='plugin_lifecycle'")
            .fetch_one(&db)
            .await
            .unwrap();
    assert_eq!(audit_count, 6);
}

#[tokio::test]
async fn operator_and_viewer_are_denied_and_errors_are_safe() {
    let (app, _db, _dir) = app().await;
    json_request(app.clone(), "POST", "/api/setup/initialize", r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#, None).await;
    let admin = login(app.clone(), "admin@example.com", "correct horse battery").await;
    for (email, password, role) in [
        ("operator@example.com", "operator password 123", "operator"),
        ("viewer@example.com", "viewer password 123", "viewer"),
    ] {
        json_request(
            app.clone(),
            "POST",
            "/api/users",
            &format!(r#"{{"email":"{email}","password":"{password}","role":"{role}"}}"#),
            Some(&admin),
        )
        .await;
    }
    for (email, password) in [
        ("operator@example.com", "operator password 123"),
        ("viewer@example.com", "viewer password 123"),
    ] {
        let token = login(app.clone(), email, password).await;
        assert_eq!(
            request(app.clone(), "GET", "/api/plugins", Some(&token))
                .await
                .0,
            StatusCode::FORBIDDEN
        );
    }
    let (status, body) = request(
        app.clone(),
        "POST",
        "/api/plugins/Bad/health-check",
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        serde_json::from_str::<Value>(&body).unwrap()["code"],
        "invalid_input"
    );
    assert_eq!(
        request(
            app.clone(),
            "POST",
            "/api/plugins/missing/health-check",
            Some(&admin)
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        request(app, "POST", "/api/plugins/missing/disable", Some(&admin))
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn plugin_permission_migration_is_idempotent_on_sqlite() {
    static DRIVERS: Once = Once::new();
    DRIVERS.call_once(sqlx::any::install_default_drivers);
    let pool = repository::connect("sqlite::memory:").await.unwrap();
    repository::migrate(&pool).await.unwrap();
    repository::migrate(&pool).await.unwrap();
    let keys: Vec<String> =
        sqlx::query_scalar("SELECT key FROM permissions WHERE key LIKE 'plugins.%' ORDER BY key")
            .fetch_all(&pool)
            .await
            .unwrap();
    assert_eq!(keys, ["plugins.manage", "plugins.read"]);
    assert_eq!(
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM permissions")
            .fetch_one(&pool)
            .await
            .unwrap(),
        16
    );
}

#[tokio::test]
async fn health_check_response_includes_bounded_v2_detail() {
    let (app, _db, dir) = app().await;
    write_plugin_v2(dir.path());
    assert_eq!(
        json_request(
            app.clone(),
            "POST",
            "/api/setup/initialize",
            r#"{"email":"admin@example.com","password":"correct horse battery","setup_token":"setup-token"}"#,
            None
        )
        .await
        .0,
        StatusCode::CREATED
    );
    let admin = login(app.clone(), "admin@example.com", "correct horse battery").await;
    // Reload is a global, not per-plugin, operation: POST /api/plugins/reload
    // scans the configured plugin directory and (re)loads everything in it.
    let (status, body, _) =
        json_request(app.clone(), "POST", "/api/plugins/reload", "", Some(&admin)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(serde_json::from_str::<Value>(&body).unwrap()["loaded"], 1);
    let (status, body) = request(
        app.clone(),
        "POST",
        "/api/plugins/demo-plugin-v2/health-check",
        Some(&admin),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let health = serde_json::from_str::<Value>(&body).unwrap();
    assert_eq!(health["status"], 1);
    assert_eq!(health["detail"], "from-api");
}
