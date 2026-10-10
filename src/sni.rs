//! Per-hostname certificate selection for the HTTPS listener.
//!
//! The resolver runs inside the OpenSSL certificate callback, so lookups only
//! touch an immutable snapshot. Snapshots are rebuilt from the control-plane
//! database whenever proxy hosts or certificates change, which means a new or
//! renewed certificate is served without restarting the listener.

use crate::control_plane::repository::{self, DbPool};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use openssl::{
    asn1::Asn1Time,
    bn::BigNum,
    ec::{EcGroup, EcKey},
    hash::MessageDigest,
    nid::Nid,
    pkey::{PKey, Private},
    x509::{X509Builder, X509NameBuilder, X509},
};
use pingora_core::listeners::TlsAccept;
use pingora_core::protocols::tls::TlsRef;
use pingora_core::tls::ext;
use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
    time::Duration,
};

/// A parsed certificate chain (leaf first) and its private key.
pub struct CertMaterial {
    chain: Vec<X509>,
    key: PKey<Private>,
}

impl CertMaterial {
    pub fn from_pem(cert_pem: &[u8], key_pem: &[u8]) -> Result<Self, String> {
        let chain = X509::stack_from_pem(cert_pem).map_err(|_| "invalid certificate PEM")?;
        if chain.is_empty() {
            return Err("certificate PEM contains no certificate".into());
        }
        let key = PKey::private_key_from_pem(key_pem).map_err(|_| "invalid private key PEM")?;
        let cert_pub = chain[0]
            .public_key()
            .and_then(|key| key.public_key_to_der())
            .map_err(|_| "invalid certificate public key")?;
        if key.public_key_to_der().ok() != Some(cert_pub) {
            return Err("certificate and private key do not match".into());
        }
        Ok(Self { chain, key })
    }

    pub fn from_files(cert_path: &Path, key_path: &Path) -> Result<Self, String> {
        let cert = std::fs::read(cert_path).map_err(|_| "certificate file is not readable")?;
        let key = std::fs::read(key_path).map_err(|_| "private key file is not readable")?;
        Self::from_pem(&cert, &key)
    }

    /// Self-signed placeholder served for unknown hostnames, like the default
    /// certificate of other proxy managers. Browsers will warn, which is the
    /// intended signal that the hostname has no certificate assigned.
    pub fn self_signed() -> Result<Self, openssl::error::ErrorStack> {
        let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1)?;
        let key = PKey::from_ec_key(EcKey::generate(&group)?)?;
        let mut name = X509NameBuilder::new()?;
        name.append_entry_by_nid(Nid::COMMONNAME, "bearust-default")?;
        let name = name.build();
        let mut builder = X509Builder::new()?;
        builder.set_version(2)?;
        let serial = BigNum::from_u32(rand::random::<u32>() | 1)?.to_asn1_integer()?;
        builder.set_serial_number(&serial)?;
        builder.set_subject_name(&name)?;
        builder.set_issuer_name(&name)?;
        builder.set_pubkey(&key)?;
        builder.set_not_before(Asn1Time::days_from_now(0)?.as_ref())?;
        builder.set_not_after(Asn1Time::days_from_now(3650)?.as_ref())?;
        builder.sign(&key, MessageDigest::sha256())?;
        Ok(Self {
            chain: vec![builder.build()],
            key,
        })
    }

    fn hostnames(&self) -> Vec<String> {
        crate::certificates::hostnames(&self.chain[0])
    }

    fn expired(&self) -> bool {
        Asn1Time::days_from_now(0)
            .ok()
            .and_then(|now| self.chain[0].not_after().compare(&now).ok())
            .is_some_and(|ordering| ordering.is_lt())
    }
}

#[derive(Default)]
pub struct SniSnapshot {
    exact: HashMap<String, Arc<CertMaterial>>,
    /// `*.example.com` certificates keyed by `example.com`.
    wildcard: HashMap<String, Arc<CertMaterial>>,
    /// Enabled HTTPS proxy hosts that have a matching certificate; plain HTTP
    /// requests for these hosts are redirected to HTTPS.
    https_hosts: HashSet<String>,
}

impl SniSnapshot {
    fn insert(&mut self, hostname: &str, material: &Arc<CertMaterial>) {
        let hostname = hostname.trim().trim_end_matches('.').to_ascii_lowercase();
        if let Some(parent) = hostname.strip_prefix("*.") {
            self.wildcard
                .insert(parent.to_owned(), Arc::clone(material));
        } else if !hostname.is_empty() {
            self.exact.insert(hostname, Arc::clone(material));
        }
    }

    fn lookup(&self, hostname: &str) -> Option<&Arc<CertMaterial>> {
        let hostname = hostname.trim_end_matches('.').to_ascii_lowercase();
        self.exact.get(&hostname).or_else(|| {
            hostname
                .split_once('.')
                .and_then(|(_, parent)| self.wildcard.get(parent))
        })
    }
}

/// Host facts the snapshot builder needs, decoupled from the DB row type.
pub struct HttpsHost {
    pub domain: String,
    pub enabled: bool,
    pub tls_enabled: bool,
    pub certificate_id: Option<i64>,
}

/// Builds a snapshot. Every stored certificate is indexed by the names it
/// covers (expired ones are skipped); a host's explicitly assigned
/// certificate then overrides that index for its own domain.
pub fn build_snapshot(certificates: Vec<(i64, CertMaterial)>, hosts: &[HttpsHost]) -> SniSnapshot {
    let mut snapshot = SniSnapshot::default();
    let mut by_id = HashMap::new();
    for (id, material) in certificates {
        let material = Arc::new(material);
        if !material.expired() {
            for hostname in material.hostnames() {
                snapshot.insert(&hostname, &material);
            }
        }
        by_id.insert(id, material);
    }
    for host in hosts.iter().filter(|host| host.enabled && host.tls_enabled) {
        if let Some(material) = host.certificate_id.and_then(|id| by_id.get(&id)) {
            snapshot.insert(&host.domain, material);
        }
    }
    for host in hosts.iter().filter(|host| host.enabled && host.tls_enabled) {
        let domain = host.domain.trim().to_ascii_lowercase();
        if snapshot.lookup(&domain).is_some() {
            snapshot.https_hosts.insert(domain);
        }
    }
    snapshot
}

pub struct SniResolver {
    current: ArcSwap<SniSnapshot>,
    fallback: Arc<CertMaterial>,
}

impl SniResolver {
    pub fn new(fallback: CertMaterial) -> Self {
        Self {
            current: ArcSwap::from_pointee(SniSnapshot::default()),
            fallback: Arc::new(fallback),
        }
    }

    pub fn store(&self, snapshot: SniSnapshot) {
        self.current.store(Arc::new(snapshot));
    }

    /// Certificate for a TLS ClientHello server name (fallback when unknown).
    pub fn resolve(&self, server_name: Option<&str>) -> Arc<CertMaterial> {
        server_name
            .and_then(|name| self.current.load().lookup(name).cloned())
            .unwrap_or_else(|| Arc::clone(&self.fallback))
    }

    /// Whether plain-HTTP requests for `host` should be redirected to HTTPS.
    pub fn redirects_to_https(&self, host: &str) -> bool {
        self.current
            .load()
            .https_hosts
            .contains(&host.trim_end_matches('.').to_ascii_lowercase())
    }

    pub async fn refresh(&self, db: &DbPool) -> Result<(), String> {
        let hosts = repository::list_hosts(db)
            .await
            .map_err(|_| "unable to load proxy hosts")?
            .into_iter()
            .map(|host| HttpsHost {
                domain: host.domain,
                enabled: host.enabled,
                tls_enabled: host.tls_mode != "disabled",
                certificate_id: host.certificate_id,
            })
            .collect::<Vec<_>>();
        let mut certificates = Vec::new();
        for certificate in repository::list_certificates(db)
            .await
            .map_err(|_| "unable to load certificates")?
        {
            let Ok(Some((_, cert_path, key_path))) =
                repository::certificate_paths(db, certificate.id).await
            else {
                continue;
            };
            match CertMaterial::from_files(Path::new(&cert_path), Path::new(&key_path)) {
                Ok(material) => certificates.push((certificate.id, material)),
                Err(error) => tracing::warn!(
                    event = "sni_certificate_skipped",
                    certificate_id = certificate.id,
                    error = %error
                ),
            }
        }
        self.store(build_snapshot(certificates, &hosts));
        Ok(())
    }

    /// Keeps the snapshot current: rebuilds immediately when proxy hosts or
    /// certificates change, and every 30 seconds to pick up ACME renewals.
    pub fn spawn_refresh_loop(
        self: &Arc<Self>,
        db: DbPool,
        realtime: Arc<crate::control_plane::realtime::RealtimeHub>,
    ) -> tokio::task::JoinHandle<()> {
        let resolver = Arc::clone(self);
        let mut events = realtime.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                tokio::select! {
                    _ = interval.tick() => {}
                    event = events.recv() => match event {
                        Ok(event)
                            if event.kind == "proxy_hosts.changed"
                                || event.kind == "certificates.changed" => {}
                        Ok(_) => continue,
                        Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                        Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                            events = realtime.subscribe();
                            continue;
                        }
                    },
                }
                if let Err(error) = resolver.refresh(&db).await {
                    tracing::warn!(event = "sni_refresh_failed", error = %error);
                }
            }
        })
    }
}

/// Adapter handed to Pingora; holds the shared resolver.
pub struct SniCallbacks(pub Arc<SniResolver>);

#[async_trait]
impl TlsAccept for SniCallbacks {
    async fn certificate_callback(&self, ssl: &mut TlsRef) {
        let material = self
            .0
            .resolve(ssl.servername(openssl::ssl::NameType::HOST_NAME));
        let mut chain = material.chain.iter();
        if let Some(leaf) = chain.next() {
            if ext::ssl_use_certificate(ssl, leaf).is_err() {
                tracing::warn!(event = "sni_certificate_install_failed");
                return;
            }
        }
        for intermediate in chain {
            let _ = ext::ssl_add_chain_cert(ssl, intermediate);
        }
        if ext::ssl_use_private_key(ssl, &material.key).is_err() {
            tracing::warn!(event = "sni_private_key_install_failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cert_for(names: &[&str]) -> CertMaterial {
        use openssl::x509::extension::SubjectAlternativeName;
        let key = PKey::from_ec_key(
            EcKey::generate(&EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).unwrap()).unwrap(),
        )
        .unwrap();
        let mut name = X509NameBuilder::new().unwrap();
        name.append_entry_by_nid(Nid::COMMONNAME, names[0]).unwrap();
        let name = name.build();
        let mut builder = X509Builder::new().unwrap();
        builder.set_version(2).unwrap();
        builder.set_subject_name(&name).unwrap();
        builder.set_issuer_name(&name).unwrap();
        builder.set_pubkey(&key).unwrap();
        builder
            .set_not_before(Asn1Time::days_from_now(0).unwrap().as_ref())
            .unwrap();
        builder
            .set_not_after(Asn1Time::days_from_now(30).unwrap().as_ref())
            .unwrap();
        let mut san = SubjectAlternativeName::new();
        for name in names {
            san.dns(name);
        }
        let san = san.build(&builder.x509v3_context(None, None)).unwrap();
        builder.append_extension(san).unwrap();
        builder.sign(&key, MessageDigest::sha256()).unwrap();
        CertMaterial {
            chain: vec![builder.build()],
            key,
        }
    }

    fn host(domain: &str, tls: bool, certificate_id: Option<i64>) -> HttpsHost {
        HttpsHost {
            domain: domain.into(),
            enabled: true,
            tls_enabled: tls,
            certificate_id,
        }
    }

    fn leaf_cn(material: &CertMaterial) -> String {
        material.chain[0]
            .subject_name()
            .entries_by_nid(Nid::COMMONNAME)
            .next()
            .unwrap()
            .data()
            .to_string()
            .unwrap()
    }

    #[test]
    fn resolves_exact_wildcard_and_fallback() {
        let resolver = SniResolver::new(CertMaterial::self_signed().unwrap());
        resolver.store(build_snapshot(
            vec![
                (1, cert_for(&["app.example.com"])),
                (2, cert_for(&["*.example.org"])),
            ],
            &[],
        ));
        assert_eq!(
            leaf_cn(&resolver.resolve(Some("APP.example.com"))),
            "app.example.com"
        );
        assert_eq!(
            leaf_cn(&resolver.resolve(Some("api.example.org"))),
            "*.example.org"
        );
        assert_eq!(
            leaf_cn(&resolver.resolve(Some("a.b.example.org"))),
            "bearust-default"
        );
        assert_eq!(leaf_cn(&resolver.resolve(None)), "bearust-default");
    }

    #[test]
    fn assigned_certificate_overrides_index_and_enables_redirect() {
        let resolver = SniResolver::new(CertMaterial::self_signed().unwrap());
        resolver.store(build_snapshot(
            vec![
                (1, cert_for(&["shop.example.com"])),
                (2, cert_for(&["www.shop.example.com", "shop.example.com"])),
            ],
            &[
                host("shop.example.com", true, Some(1)),
                host("plain.example.com", false, None),
                host("pending.example.com", true, None),
            ],
        ));
        assert_eq!(
            leaf_cn(&resolver.resolve(Some("shop.example.com"))),
            "shop.example.com"
        );
        assert!(resolver.redirects_to_https("shop.example.com"));
        assert!(!resolver.redirects_to_https("plain.example.com"));
        // HTTPS requested but no certificate yet: keep serving HTTP.
        assert!(!resolver.redirects_to_https("pending.example.com"));
    }

    #[test]
    fn mismatched_key_is_rejected() {
        let a = cert_for(&["a.example.com"]);
        let b = cert_for(&["b.example.com"]);
        let cert_pem = a.chain[0].to_pem().unwrap();
        let key_pem = b.key.private_key_to_pem_pkcs8().unwrap();
        assert!(CertMaterial::from_pem(&cert_pem, &key_pem).is_err());
    }
}
