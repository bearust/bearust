use bearust::control_plane::{models::{AcmeChallenge, AcmeEnvironment, AcmeRequest}, repository};

async fn db() -> sqlx::SqlitePool {
    let p = repository::connect("sqlite:file:acme_repository_test?mode=memory&cache=shared")
        .await
        .unwrap();
    repository::migrate(&p).await.unwrap();
    let id = repository::insert_certificate(&p, "acme", "letsencrypt", "[]", "2099-01-01", "/tmp/cert", "/tmp/key").await.unwrap();
    assert_eq!(id, 1);
    p
}

#[tokio::test]
async fn stores_redacted_lifecycle_metadata_and_due_rows() {
    let p = db().await;
    let req = AcmeRequest { environment: AcmeEnvironment::Staging, challenge: AcmeChallenge::Http01, hostnames: vec![" Example.COM ".into(), "example.com".into()] };
    let status = repository::insert_acme_certificate(&p, 1, &req).await.unwrap();
    assert_eq!(status.hostnames, vec!["example.com"]);
    assert_eq!(status.renewal_state, "pending");
    repository::update_acme_status(&p, 1, "retrying", Some("2026-01-01T00:00:00Z"), Some("2025-12-01T00:00:00Z"), Some("timeout")).await.unwrap();
    let status = repository::get_acme_status(&p, 1).await.unwrap().unwrap();
    assert_eq!(status.last_error_code.as_deref(), Some("timeout"));
    let due = repository::list_due_acme_certificates(&p, "2026-02-01T00:00:00Z").await.unwrap();
    assert_eq!(due.len(), 1);
    let json = serde_json::to_string(&status).unwrap();
    assert!(!json.contains("token"));
    assert!(!json.contains("secret"));
}

#[test]
fn validates_challenge_and_normalizes_names() {
    let req = AcmeRequest { environment: AcmeEnvironment::Production, challenge: AcmeChallenge::Http01, hostnames: vec!["*.example.com".into()] };
    assert!(req.normalized().is_err());
    let req = AcmeRequest { environment: AcmeEnvironment::Production, challenge: AcmeChallenge::CloudflareDns01, hostnames: vec![" *.Example.COM ".into(), "example.com".into()] };
    assert_eq!(req.normalized().unwrap().hostnames, vec!["*.example.com", "example.com"]);
}
