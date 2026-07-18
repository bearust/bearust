use bearust::certificates::{CertificateError, CertificateStore};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    x509::{X509NameBuilder, X509},
};

fn material() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "example.com").unwrap();
    let name = name.build();
    let mut b = X509::builder().unwrap();
    b.set_version(2).unwrap();
    b.set_subject_name(&name).unwrap();
    b.set_issuer_name(&name).unwrap();
    b.set_pubkey(&key).unwrap();
    b.set_not_before(openssl::asn1::Asn1Time::days_from_now(0).unwrap().as_ref())
        .unwrap();
    b.set_not_after(openssl::asn1::Asn1Time::days_from_now(30).unwrap().as_ref())
        .unwrap();
    b.sign(&key, MessageDigest::sha256()).unwrap();
    (
        b.build().to_pem().unwrap(),
        key.private_key_to_pem_pkcs8().unwrap(),
    )
}

#[test]
fn valid_import_activation_and_key_permissions() {
    let root = tempfile::tempdir().unwrap();
    let store = CertificateStore::new(root.path()).unwrap();
    let (cert, key) = material();
    let record = store.import_custom("main", &cert, &key).unwrap();
    assert_eq!(record.covered_hostnames, vec!["example.com"]);
    store.activate("main").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(record.key_path)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}

#[test]
fn mismatched_key_is_rejected() {
    let root = tempfile::tempdir().unwrap();
    let store = CertificateStore::new(root.path()).unwrap();
    let (cert, _) = material();
    let (_, other) = material();
    assert!(matches!(
        store.import_custom("bad", &cert, &other),
        Err(CertificateError::KeyMismatch)
    ));
}

#[test]
fn malformed_material_is_rejected_without_secret_in_error() {
    let root = tempfile::tempdir().unwrap();
    let store = CertificateStore::new(root.path()).unwrap();
    let secret = "private-secret-value";
    let err = store
        .import_custom("broken", b"not a certificate", secret.as_bytes())
        .unwrap_err();
    assert!(matches!(err, CertificateError::Malformed));
    assert!(!err.to_string().contains(secret));
    assert!(store.active().is_none());
}

#[test]
fn names_cannot_escape_storage_root() {
    let root = tempfile::tempdir().unwrap();
    let store = CertificateStore::new(root.path()).unwrap();
    let err = store.import_custom("../outside", b"", b"").unwrap_err();
    assert!(matches!(err, CertificateError::InvalidName));
}

#[test]
fn activating_unknown_certificate_does_not_create_active_state() {
    let root = tempfile::tempdir().unwrap();
    let store = CertificateStore::new(root.path()).unwrap();
    assert!(matches!(
        store.activate("missing"),
        Err(CertificateError::NotFound { .. })
    ));
    assert!(store.active().is_none());
}
