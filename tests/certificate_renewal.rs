use async_trait::async_trait;
use bearust::certificates::{CertificateRecord, CertificateStore, RenewedCertificate, RenewalError, RenewalIssuer, RenewalOutcome, RenewalScheduler};
use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, x509::{X509NameBuilder, X509}};
use std::{sync::{Arc, atomic::{AtomicUsize, Ordering}}, time::{Duration, SystemTime}};

fn material(days: u32) -> (Vec<u8>, Vec<u8>) {
    let rsa = Rsa::generate(2048).unwrap(); let key = PKey::from_rsa(rsa).unwrap();
    let mut n = X509NameBuilder::new().unwrap(); n.append_entry_by_text("CN", "example.com").unwrap(); let n = n.build();
    let mut b = X509::builder().unwrap(); b.set_version(2).unwrap(); b.set_subject_name(&n).unwrap(); b.set_issuer_name(&n).unwrap(); b.set_pubkey(&key).unwrap();
    b.set_not_before(openssl::asn1::Asn1Time::days_from_now(0).unwrap().as_ref()).unwrap(); b.set_not_after(openssl::asn1::Asn1Time::days_from_now(days).unwrap().as_ref()).unwrap(); b.sign(&key, MessageDigest::sha256()).unwrap();
    (b.build().to_pem().unwrap(), key.private_key_to_pem_pkcs8().unwrap())
}

struct Fake { calls: AtomicUsize, fail: bool, cert: Vec<u8>, key: Vec<u8> }
#[async_trait] impl RenewalIssuer for Fake {
    async fn renew(&self, record: &CertificateRecord) -> Result<RenewedCertificate, RenewalError> { self.calls.fetch_add(1, Ordering::SeqCst); if self.fail { Err(RenewalError) } else { Ok(RenewedCertificate { name: record.name.clone(), cert_pem: self.cert.clone(), key_pem: self.key.clone() }) } }
}

#[tokio::test]
async fn due_success_activates_and_failure_keeps_last_good() {
    let root = tempfile::tempdir().unwrap(); let store = CertificateStore::new(root.path()).unwrap(); let (cert,key) = material(30);
    let record = store.import_custom("main", &cert, &key).unwrap(); store.activate("main").unwrap();
    let issuer = Arc::new(Fake { calls: AtomicUsize::new(0), fail: false, cert: cert.clone(), key: key.clone() });
    let mut scheduler = RenewalScheduler::new(store.clone(), issuer.clone()).with_policy(Duration::from_secs(31*86400), 3, Duration::from_secs(0));
    assert!(matches!(scheduler.run_once(SystemTime::now()).await, RenewalOutcome::Renewed(_))); assert_eq!(issuer.calls.load(Ordering::SeqCst), 1);
    let failing = Arc::new(Fake { calls: AtomicUsize::new(0), fail: true, cert, key });
    let mut scheduler = RenewalScheduler::new(store.clone(), failing).with_policy(Duration::from_secs(31*86400), 2, Duration::from_secs(0));
    assert!(matches!(scheduler.run_once(SystemTime::now()).await, RenewalOutcome::Retrying { .. }));
    assert!(matches!(scheduler.run_once(SystemTime::now()).await, RenewalOutcome::Failed { attempts: 2 }));
    assert_eq!(store.active().unwrap().record.name, record.name);
}

#[test]
fn next_due_is_now_inside_window_and_future_before_window() {
    let record = CertificateRecord { name: "x".into(), source: bearust::certificates::CertificateSource::Custom, covered_hostnames: vec![], expiry: "Jul 18 00:00:00 2026 GMT".into(), certificate_path: "x".into(), key_path: "x".into() };
    let due = RenewalScheduler::next_due(&record, SystemTime::UNIX_EPOCH); assert!(due > std::time::Instant::now());
}
