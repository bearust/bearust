use bearust::{acme::{AcmeEnvironment, AcmeOrder, LetsEncryptClient}, secrets::{SecretError, SecretStore}};
use reqwest::Client;
use std::{fs, os::unix::fs::PermissionsExt};
use tempfile::tempdir;

#[test]
fn secret_files_are_private_and_reused() {
    let dir = tempdir().unwrap();
    let store = SecretStore::open(dir.path()).unwrap();
    store.put("token", b"super-secret").unwrap();
    assert_eq!(store.get("token").unwrap().as_deref(), Some(&b"super-secret"[..]));
    assert_eq!(fs::metadata(dir.path().join("token")).unwrap().permissions().mode() & 0o777, 0o600);
    assert!(matches!(store.put("../token", b"x"), Err(SecretError::InvalidName)));
    let one = LetsEncryptClient::new(AcmeEnvironment::Staging, store.clone(), Client::new().unwrap()).unwrap();
    let two = LetsEncryptClient::new(AcmeEnvironment::Staging, store, Client::new().unwrap()).unwrap();
    assert_eq!(one.account_key(), two.account_key());
}

#[test]
fn environment_and_debug_are_safe() {
    let dir = tempdir().unwrap();
    let client = LetsEncryptClient::new(AcmeEnvironment::Production, SecretStore::open(dir.path()).unwrap(), Client::new().unwrap()).unwrap();
    assert!(client.directory_url().contains("acme-v02"));
    let order = AcmeOrder { id: "id".into(), token: "token-secret".into(), key_authorization: "key-secret".into() };
    let debug = format!("{order:?}{client:?}");
    assert!(!debug.contains("token-secret"));
    assert!(!debug.contains("key-secret"));
}
