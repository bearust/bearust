use async_trait::async_trait;
use bearust::acme::{
    lookup_http01, AcmeError, AcmeManager, AcmeOrder, AcmeTransport, CertificateRequest,
    Http01Store, IssuedCertificate,
};
use bearust::certificates::{CertificateSource, CertificateStore};
use openssl::{
    hash::MessageDigest,
    pkey::PKey,
    rsa::Rsa,
    x509::{X509NameBuilder, X509},
};
use std::sync::Arc;
use std::time::Duration;

#[test]
fn http01_store_returns_only_exact_token_and_expires() {
    let store = Http01Store::new(Duration::from_millis(20));
    store
        .put(
            "abc-123",
            "abc-123.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        )
        .unwrap();
    assert_eq!(
        store.get("abc-123").as_deref(),
        Some("abc-123.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    );
    assert!(store.get("abc-123/../x").is_none());
    std::thread::sleep(Duration::from_millis(30));
    assert!(store.get("abc-123").is_none());
}

struct Harness {
    fail: bool,
    material: Option<(Vec<u8>, Vec<u8>)>,
}
#[async_trait]
impl AcmeTransport for Harness {
    async fn new_order(&self, _request: &CertificateRequest) -> Result<AcmeOrder, AcmeError> {
        Ok(AcmeOrder {
            id: "order-1".into(),
            token: "token-1".into(),
            key_authorization: "token-1.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
        })
    }
    async fn poll_order(&self, _order: &AcmeOrder, _store: &Http01Store) -> Result<(), AcmeError> {
        if self.fail {
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        Ok(())
    }
    async fn finalize(
        &self,
        _order: &AcmeOrder,
        _request: &CertificateRequest,
    ) -> Result<IssuedCertificate, AcmeError> {
        self.material
            .clone()
            .map(|(certificate_pem, private_key_pem)| IssuedCertificate {
                certificate_pem,
                private_key_pem,
            })
            .ok_or_else(|| AcmeError::Transport("test harness has no certificate".into()))
    }
}

#[tokio::test]
async fn timeout_preserves_active_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let store = CertificateStore::new(dir.path()).unwrap();
    let (old_cert, old_key) = material();
    let old = store.import_custom("old", &old_cert, &old_key).unwrap();
    store.activate(&old.name).unwrap();
    let manager = AcmeManager::with_transport(
        store.clone(),
        Arc::new(Harness {
            fail: true,
            material: None,
        }),
    )
    .with_timeout(Duration::from_millis(10));
    let request = CertificateRequest::new("site", vec!["example.com".into()]);
    let result = manager.request_http01(request).await;
    assert!(matches!(result, Err(AcmeError::Timeout)));
    assert_eq!(store.active().unwrap().record.name, "old");
    assert!(manager
        .challenge_store()
        .get_for_order("order-1", "example.com", "token-1")
        .is_none());
}

#[tokio::test]
async fn successful_order_finalization_returns_issued_record() {
    let dir = tempfile::tempdir().unwrap();
    let store = CertificateStore::new(dir.path()).unwrap();
    let manager = AcmeManager::with_transport(
        store.clone(),
        Arc::new(Harness {
            fail: false,
            material: Some(material()),
        }),
    );
    let result = manager
        .request_http01(CertificateRequest::new("site", vec!["example.com".into()]))
        .await;
    assert_eq!(result.unwrap().source, CertificateSource::LetsEncrypt);
    assert!(store.active().is_some());
}

#[test]
fn source_enum_includes_letsencrypt() {
    assert_eq!(
        CertificateSource::LetsEncrypt,
        CertificateSource::LetsEncrypt
    );
}

#[test]
fn challenge_entries_are_isolated_by_order_and_hostname() {
    let store = Http01Store::default();
    let value = "token.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    store
        .put_for_order("one", "a.example", "token", value)
        .unwrap();
    assert_eq!(
        store.get_for_order("one", "a.example", "token").as_deref(),
        Some(value)
    );
    assert!(store.get_for_order("two", "a.example", "token").is_none());
    assert!(store.get_for_order("one", "b.example", "token").is_none());
}

#[test]
fn key_authorization_requires_token_and_base64url_digest() {
    let store = Http01Store::default();
    assert!(store
        .put("token", "wrong.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .is_err());
    assert!(store.put("token", "token.not valid").is_err());
    assert!(store
        .put("token", "token.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .is_ok());
}

#[test]
fn challenge_lookup_handles_only_dedicated_path() {
    let store = Http01Store::default();
    store
        .put("token", "token.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
        .unwrap();
    assert!(lookup_http01("/.well-known/acme-challenge/token", &store).is_some());
    assert!(lookup_http01("/proxy/.well-known/acme-challenge/token", &store).is_none());
    assert!(lookup_http01("/.well-known/acme-challenge/token/extra", &store).is_none());
}

fn material() -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap();
    let key = PKey::from_rsa(rsa).unwrap();
    let mut name = X509NameBuilder::new().unwrap();
    name.append_entry_by_text("CN", "example.com").unwrap();
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
