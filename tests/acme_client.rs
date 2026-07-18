use bearust::{
    acme::{AcmeEnvironment, AcmeOrder, AcmeTransport, CertificateRequest, LetsEncryptClient},
    secrets::{SecretError, SecretStore},
};
use reqwest::Client;
use std::{fs, os::unix::fs::PermissionsExt};
use tempfile::tempdir;

#[test]
fn secret_files_are_private_and_reused() {
    let dir = tempdir().unwrap();
    let store = SecretStore::open(dir.path()).unwrap();
    store.put("token", b"super-secret").unwrap();
    assert_eq!(
        store.get("token").unwrap().as_deref(),
        Some(&b"super-secret"[..])
    );
    assert_eq!(
        fs::metadata(dir.path().join("token"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    assert!(matches!(
        store.put("../token", b"x"),
        Err(SecretError::InvalidName)
    ));
    let one =
        LetsEncryptClient::new(AcmeEnvironment::Staging, store.clone(), Client::new()).unwrap();
    let two = LetsEncryptClient::new(AcmeEnvironment::Staging, store, Client::new()).unwrap();
    assert_eq!(one.account_key(), two.account_key());
}

#[tokio::test]
async fn staging_and_production_accounts_are_namespaced() {
    let dir = tempdir().unwrap();
    let store = SecretStore::open(dir.path()).unwrap();
    store.put("acme-account-key-staging", b"staging").unwrap();
    store
        .put("acme-account-key-production", b"production")
        .unwrap();
    let staging =
        LetsEncryptClient::new(AcmeEnvironment::Staging, store.clone(), Client::new()).unwrap();
    let production =
        LetsEncryptClient::new(AcmeEnvironment::Production, store, Client::new()).unwrap();
    assert_eq!(staging.account_key(), b"staging");
    assert_eq!(production.account_key(), b"production");
}

#[tokio::test]
async fn production_client_rejects_multi_hostname_orders_until_challenges_are_tracked() {
    let dir = tempdir().unwrap();
    let client = LetsEncryptClient::new(
        AcmeEnvironment::Production,
        SecretStore::open(dir.path()).unwrap(),
        Client::new(),
    )
    .unwrap();
    let request = CertificateRequest::new("san", vec!["one.example".into(), "two.example".into()]);
    assert!(matches!(
        client.new_order(&request).await,
        Err(bearust::acme::AcmeError::InvalidRequest)
    ));
}

#[test]
fn environment_and_debug_are_safe() {
    let dir = tempdir().unwrap();
    let client = LetsEncryptClient::new(
        AcmeEnvironment::Production,
        SecretStore::open(dir.path()).unwrap(),
        Client::new(),
    )
    .unwrap();
    assert!(client.directory_url().contains("acme-v02"));
    let order = AcmeOrder {
        id: "id".into(),
        token: "token-secret".into(),
        key_authorization: "key-secret".into(),
    };
    let debug = format!("{order:?}{client:?}");
    assert!(!debug.contains("token-secret"));
    assert!(!debug.contains("key-secret"));
}
