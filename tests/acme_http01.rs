use async_trait::async_trait;
use bearust::acme::{
    AcmeError, AcmeManager, AcmeOrder, AcmeTransport, CertificateRequest, Http01Store,
    IssuedCertificate,
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
    store.put("abc-123", "abc-123.auth").unwrap();
    assert_eq!(store.get("abc-123").as_deref(), Some("abc-123.auth"));
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
            key_authorization: "key-auth".into(),
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
    assert!(store.active().is_none());
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
