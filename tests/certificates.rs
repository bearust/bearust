use bearust::certificates::{CertificateError, CertificateStore};

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
