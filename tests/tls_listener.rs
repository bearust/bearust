use bearust::{config::TlsConfig, tls};
use openssl::{
    asn1::Asn1Time, hash::MessageDigest, pkey::PKey, rsa::Rsa, x509::X509NameBuilder, x509::X509,
};
use std::fs;
use tempfile::tempdir;

#[test]
fn generated_certificate_builds_native_tls_settings() {
    let dir = tempdir().unwrap();
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
    let cert = dir.path().join("cert.pem");
    let private = dir.path().join("key.pem");
    fs::write(&cert, builder.build().to_pem().unwrap()).unwrap();
    fs::write(&private, key.private_key_to_pem_pkcs8().unwrap()).unwrap();
    let config = TlsConfig {
        cert_path: cert,
        key_path: private,
    };
    assert!(tls::settings(&config).is_ok());
}
