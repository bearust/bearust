use std::sync::Arc;

use openssl::{
    asn1::Asn1Time,
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    x509::{X509NameBuilder, X509},
};

use bearust::{config, runtime::RuntimeStore};

#[tokio::test]
async fn invalid_reload_keeps_current_generation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let store = RuntimeStore::new(
        bearust::runtime::RuntimeSnapshot::build(config::load(&path).unwrap(), None).unwrap(),
    );
    let before = store.load();

    std::fs::write(&path, "[server]\nbind = \"broken\"").unwrap();
    assert!(store.reload(&path).await.is_err());
    assert_eq!(store.load().generation(), before.generation());
    assert!(Arc::ptr_eq(&store.load(), &before));
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn successful_reload_increments_generation() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let snapshot =
        bearust::runtime::RuntimeSnapshot::build(config::load(&path).unwrap(), None).unwrap();
    let store = RuntimeStore::new(snapshot);

    let outcome = store.reload(&path).await.unwrap();
    assert_eq!(outcome.old_generation, 1);
    assert_eq!(outcome.new_generation, 2);
    assert_eq!(store.load().generation(), 2);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn http_reload_keeps_tls_disabled() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let snapshot =
        bearust::runtime::RuntimeSnapshot::build(config::load(&path).unwrap(), None).unwrap();
    let store = RuntimeStore::new(snapshot);
    assert!(store.load().tls().is_none());
    store.reload(&path).await.unwrap();
    assert!(store.load().tls().is_none());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_tls_reload_keeps_previous_snapshot() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let snapshot =
        bearust::runtime::RuntimeSnapshot::build(config::load(&path).unwrap(), None).unwrap();
    let store = RuntimeStore::new(snapshot);
    let before = store.load();
    let invalid = format!(
        "{}\n[server.tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\n",
        include_str!("fixtures/valid.toml"),
        temp.path().join("bad-cert.pem").display(),
        temp.path().join("bad-key.pem").display()
    );
    std::fs::write(&path, invalid).unwrap();
    assert!(store.reload(&path).await.is_err());
    assert!(Arc::ptr_eq(&before, &store.load()));
    assert!(store.load().tls().is_none());
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn valid_tls_reload_replaces_immutable_material() {
    let temp = tempfile::tempdir().unwrap();
    let (cert_a, key_a) = write_certificate(temp.path(), "a");
    let (cert_b, key_b) = write_certificate(temp.path(), "b");
    let path = temp.path().join("bearust.toml");
    let config = |cert: &std::path::Path, key: &std::path::Path| {
        format!(
            "{}\n[server.tls]\ncert_path = \"{}\"\nkey_path = \"{}\"\n",
            include_str!("fixtures/valid.toml"),
            cert.display(),
            key.display()
        )
    };
    std::fs::write(&path, config(&cert_a, &key_a)).unwrap();
    let snapshot =
        bearust::runtime::RuntimeSnapshot::build(config::load(&path).unwrap(), None).unwrap();
    let store = RuntimeStore::new(snapshot);
    let before = store.load().tls().unwrap();
    std::fs::write(&path, config(&cert_b, &key_b)).unwrap();
    store.reload(&path).await.unwrap();
    let after = store.load().tls().unwrap();
    assert_ne!(before, after);
    assert_eq!(after.cert_path, cert_b);
    assert_eq!(after.key_path, key_b);
    store.shutdown().await.unwrap();
}

#[tokio::test]
async fn old_snapshot_remains_usable_after_reload() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let snapshot =
        bearust::runtime::RuntimeSnapshot::build(config::load(&path).unwrap(), None).unwrap();
    let store = RuntimeStore::new(snapshot);
    let old = store.load();

    let changed = include_str!("fixtures/valid.toml").replace("18080", "18081");
    std::fs::write(&path, changed).unwrap();
    store.reload(&path).await.unwrap();

    assert_eq!(old.generation(), 1);
    assert!(old.route("api.example.com", "/health").is_some());
    assert!(!Arc::ptr_eq(&old, &store.load()));
    assert_eq!(store.load().generation(), 2);
    store.shutdown().await.unwrap();
}

#[test]
fn unchanged_backend_identity_preserves_health_eligibility() {
    let config = config::load(std::path::Path::new("tests/fixtures/valid.toml")).unwrap();
    let before = bearust::runtime::RuntimeSnapshot::build(config.clone(), None).unwrap();
    let old_pool = before.pools().next().unwrap();
    old_pool.set_healthy(0.into(), true);

    let after = bearust::runtime::RuntimeSnapshot::build(config, Some(&before)).unwrap();
    assert!(after.pools().next().unwrap().is_healthy(0.into()));
}

#[test]
fn changed_backend_definition_resets_health_eligibility() {
    let mut config = config::load(std::path::Path::new("tests/fixtures/valid.toml")).unwrap();
    let before = bearust::runtime::RuntimeSnapshot::build(config.clone(), None).unwrap();
    before.pools().next().unwrap().set_healthy(0.into(), true);

    config.upstream_pools[0].backends[0].address = "127.0.0.1:19002".parse().unwrap();
    let after = bearust::runtime::RuntimeSnapshot::build(config, Some(&before)).unwrap();
    assert!(!after.pools().next().unwrap().is_healthy(0.into()));
}

#[test]
fn snapshot_routes_to_pool() {
    let config = config::load(std::path::Path::new("tests/fixtures/valid.toml")).unwrap();
    let snapshot = bearust::runtime::RuntimeSnapshot::build(config, None).unwrap();
    let (route, pool) = snapshot.route("api.example.com", "/").unwrap();
    assert_eq!(route.upstream_pool, pool.name());
}

fn write_certificate(
    root: &std::path::Path,
    suffix: &str,
) -> (std::path::PathBuf, std::path::PathBuf) {
    let rsa = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "localhost").unwrap();
    let name = name.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&name).unwrap();
    builder.set_issuer_name(&name).unwrap();
    builder.set_pubkey(&key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(&key, MessageDigest::sha256()).unwrap();
    let cert = root.join(format!("cert-{suffix}.pem"));
    let private = root.join(format!("key-{suffix}.pem"));
    std::fs::write(&cert, builder.build().to_pem().unwrap()).unwrap();
    std::fs::write(&private, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    (cert, private)
}
