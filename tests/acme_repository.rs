use bearust::control_plane::{
    models::{AcmeChallenge, AcmeEnvironment, AcmeRequest},
    repository,
};
use sqlx::Row;
use uuid::Uuid;

async fn db() -> (repository::DbPool, i64) {
    let database_url = format!(
        "sqlite:file:acme_repository_test_{}?mode=memory&cache=shared",
        Uuid::new_v4()
    );
    let p = repository::connect(&database_url).await.unwrap();
    repository::migrate(&p).await.unwrap();
    let id = repository::insert_certificate(
        &p,
        "acme",
        "letsencrypt",
        "[]",
        "2099-01-01",
        "/tmp/cert",
        "/tmp/key",
    )
    .await
    .unwrap();
    assert!(id > 0);
    (p, id)
}

#[tokio::test]
async fn stores_redacted_lifecycle_metadata_and_due_rows() {
    let (p, certificate_id) = db().await;
    let req = AcmeRequest {
        environment: AcmeEnvironment::Staging,
        challenge: AcmeChallenge::Http01,
        hostnames: vec![" Example.COM ".into(), "example.com".into()],
    };
    let status = repository::insert_acme_certificate(&p, certificate_id, &req)
        .await
        .unwrap();
    assert_eq!(status.hostnames, vec!["example.com"]);
    assert_eq!(status.renewal_state, "pending");
    repository::update_acme_status(
        &p,
        certificate_id,
        "retrying",
        Some("2026-01-01T00:00:00Z"),
        Some("2025-12-01T00:00:00Z"),
        Some("timeout"),
    )
    .await
    .unwrap();
    let status = repository::get_acme_status(&p, certificate_id)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(status.last_error_code.as_deref(), Some("timeout"));
    let due = repository::list_due_acme_certificates(&p, "2026-02-01T00:00:00Z")
        .await
        .unwrap();
    assert_eq!(due.len(), 1);
    let json = serde_json::to_string(&status).unwrap();
    assert!(!json.contains("token"));
    assert!(!json.contains("secret"));
}

#[test]
fn validates_challenge_and_normalizes_names() {
    let req = AcmeRequest {
        environment: AcmeEnvironment::Production,
        challenge: AcmeChallenge::Http01,
        hostnames: vec!["*.example.com".into()],
    };
    assert!(req.normalized().is_err());
    let req = AcmeRequest {
        environment: AcmeEnvironment::Production,
        challenge: AcmeChallenge::CloudflareDns01,
        hostnames: vec![" *.Example.COM ".into(), "example.com".into()],
    };
    assert_eq!(
        req.normalized().unwrap().hostnames,
        vec!["*.example.com", "example.com"]
    );
}

#[test]
fn rejects_malformed_labels_and_unsafe_wildcards() {
    for hostname in [
        "example..com",
        ".example.com",
        "example.com.",
        "-example.com",
        "example-.com",
        "exa_mple.com",
        "*.com",
        "*.example.*.com",
    ] {
        let req = AcmeRequest {
            environment: AcmeEnvironment::Production,
            challenge: AcmeChallenge::CloudflareDns01,
            hostnames: vec![hostname.into()],
        };
        assert!(
            req.normalized().is_err(),
            "accepted invalid hostname {hostname}"
        );
    }
}

#[tokio::test]
async fn insert_requires_existing_certificate() {
    let (p, _) = db().await;
    let req = AcmeRequest {
        environment: AcmeEnvironment::Production,
        challenge: AcmeChallenge::Http01,
        hostnames: vec!["example.com".into()],
    };
    assert!(matches!(
        repository::insert_acme_certificate(&p, -1, &req).await,
        Err(sqlx::Error::RowNotFound)
    ));
    let row = sqlx::query("SELECT COUNT(*) AS count FROM acme_certificates")
        .fetch_one(&p)
        .await
        .unwrap();
    assert_eq!(row.get::<i64, _>("count"), 0);
}
