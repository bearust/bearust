//! ACME issuance orchestration with an injectable transport.
mod cloudflare;
mod dns;
mod http01;
use crate::certificates::{CertificateError, CertificateRecord, CertificateStore};
use async_trait::async_trait;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
pub use cloudflare::CloudflareProvider;
pub use dns::{DnsError, DnsProvider, TxtRecord};
pub use http01::lookup_http01;
pub use http01::lookup_http01_for_host;
pub use http01::{Http01Error, Http01Store};
use std::{sync::Arc, time::Duration};
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertificateRequest {
    pub name: String,
    pub hostnames: Vec<String>,
}
impl CertificateRequest {
    pub fn new(name: impl Into<String>, hostnames: Vec<String>) -> Self {
        Self {
            name: name.into(),
            hostnames,
        }
    }
}
#[derive(Clone, Debug)]
pub struct AcmeOrder {
    pub id: String,
    pub token: String,
    pub key_authorization: String,
}
#[derive(Clone, Debug)]
pub struct IssuedCertificate {
    pub certificate_pem: Vec<u8>,
    pub private_key_pem: Vec<u8>,
}
#[derive(Debug, Error)]
pub enum AcmeError {
    #[error("ACME operation timed out")]
    Timeout,
    #[error("ACME transport failed")]
    Transport(String),
    #[error("ACME certificate could not be stored")]
    Certificate(#[from] CertificateError),
    #[error("invalid ACME request")]
    InvalidRequest,
}
#[async_trait]
pub trait AcmeTransport: Send + Sync {
    async fn new_order(&self, request: &CertificateRequest) -> Result<AcmeOrder, AcmeError>;
    async fn poll_order(
        &self,
        order: &AcmeOrder,
        challenges: &Http01Store,
    ) -> Result<(), AcmeError>;
    async fn finalize(
        &self,
        order: &AcmeOrder,
        request: &CertificateRequest,
    ) -> Result<IssuedCertificate, AcmeError>;

    async fn poll_order_dns01(
        &self,
        _order: &AcmeOrder,
        _records: &[TxtRecord],
    ) -> Result<(), AcmeError> {
        Err(AcmeError::InvalidRequest)
    }
}
pub struct AcmeManager {
    certificates: CertificateStore,
    transport: Arc<dyn AcmeTransport>,
    challenges: Http01Store,
    timeout: Duration,
}
impl AcmeManager {
    pub fn with_transport(
        certificates: CertificateStore,
        transport: Arc<dyn AcmeTransport>,
    ) -> Self {
        Self {
            certificates,
            transport,
            challenges: Http01Store::default(),
            timeout: Duration::from_secs(60),
        }
    }
    pub fn with_challenge_store(mut self, challenges: Http01Store) -> Self {
        self.challenges = challenges;
        self
    }
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    pub fn challenge_store(&self) -> Http01Store {
        self.challenges.clone()
    }
    pub async fn request_http01(
        &self,
        request: CertificateRequest,
    ) -> Result<CertificateRecord, AcmeError> {
        if request.name.trim().is_empty() || request.hostnames.is_empty() {
            return Err(AcmeError::InvalidRequest);
        }
        tracing::info!(event = "acme_request_start", certificate = %request.name, hostname_count = request.hostnames.len());
        match tokio::time::timeout(self.timeout, self.issue(request.clone())).await {
            Ok(Ok(record)) => {
                tracing::info!(event = "acme_request_success", certificate = %record.name);
                Ok(record)
            }
            Ok(Err(error)) => {
                tracing::warn!(event = "acme_request_failure", certificate = %request.name, reason = acme_reason(&error));
                Err(error)
            }
            Err(_) => {
                tracing::warn!(event = "acme_request_failure", certificate = %request.name, reason = "timeout");
                Err(AcmeError::Timeout)
            }
        }
    }

    /// Issue a certificate using DNS-01 challenges. Wildcard names are
    /// normalized to the same `_acme-challenge.<base>` TXT record as ACME.
    pub async fn request_dns01(
        &self,
        request: CertificateRequest,
        provider: Arc<dyn DnsProvider>,
    ) -> Result<CertificateRecord, AcmeError> {
        if request.name.trim().is_empty()
            || request.hostnames.len() != 1
            || request
                .hostnames
                .iter()
                .any(|host| !valid_dns_hostname(host))
        {
            return Err(AcmeError::InvalidRequest);
        }
        let deadline = tokio::time::Instant::now() + self.timeout;
        let order = tokio::time::timeout_at(deadline, self.transport.new_order(&request))
            .await
            .map_err(|_| AcmeError::Timeout)??;
        let records: Vec<_> = request
            .hostnames
            .iter()
            .map(|hostname| {
                let digest = URL_SAFE_NO_PAD
                    .encode(openssl::sha::sha256(order.key_authorization.as_bytes()));
                TxtRecord::new(dns01_record_name(hostname), digest)
            })
            .collect();
        // Track every candidate before the provider call so partial failure or
        // cancellation still leads to cleanup attempts for all records.
        let result = tokio::time::timeout_at(deadline, async {
            for record in &records {
                provider
                    .present(record.clone())
                    .await
                    .map_err(|_| AcmeError::Transport("DNS provider failed".into()))?;
            }
            for record in &records {
                provider
                    .wait_for_propagation(record.clone())
                    .await
                    .map_err(|_| AcmeError::Transport("DNS propagation failed".into()))?;
            }
            self.transport.poll_order_dns01(&order, &records).await?;
            let issued = self.transport.finalize(&order, &request).await?;
            let record = self.certificates.import_letsencrypt(
                &request.name,
                &issued.certificate_pem,
                &issued.private_key_pem,
            )?;
            self.certificates.activate(&record.name)?;
            Ok(record)
        })
        .await
        .map_err(|_| AcmeError::Timeout)
        .and_then(|result| result);
        for record in records {
            if let Err(error) = provider.cleanup(record).await {
                tracing::warn!(
                    event = "dns_challenge_cleanup_failed",
                    reason = dns_reason(&error)
                );
            }
        }
        result
    }
    async fn issue(&self, request: CertificateRequest) -> Result<CertificateRecord, AcmeError> {
        let order = self.transport.new_order(&request).await?;
        let mut entries = Vec::new();
        for hostname in &request.hostnames {
            self.challenges
                .put_for_order(&order.id, hostname, &order.token, &order.key_authorization)
                .map_err(|_| AcmeError::InvalidRequest)?;
            entries.push((order.id.clone(), hostname.clone(), order.token.clone()));
        }
        let _guard = http01::ChallengeGuard::new(self.challenges.clone(), entries);
        async {
            self.transport.poll_order(&order, &self.challenges).await?;
            let issued = self.transport.finalize(&order, &request).await?;
            let record = self.certificates.import_letsencrypt(
                &request.name,
                &issued.certificate_pem,
                &issued.private_key_pem,
            )?;
            self.certificates.activate(&record.name)?;
            Ok(record)
        }
        .await
    }
}

pub fn dns01_record_name(hostname: &str) -> String {
    format!(
        "_acme-challenge.{}",
        hostname
            .trim()
            .trim_start_matches("*.")
            .trim_end_matches('.')
    )
}

/// DNS-01 currently supports one authorization per order. Multi-SAN support
/// requires transporting one challenge value per ACME authorization; reject
/// it at the manager boundary rather than publishing an incorrect shared TXT.
fn valid_dns_hostname(hostname: &str) -> bool {
    let mut value = hostname.trim();
    if let Some(stripped) = value.strip_prefix("*.") {
        value = stripped;
    }
    value = value.trim_end_matches('.');
    if value.is_empty() || value.len() > 253 || !value.contains('.') {
        return false;
    }
    value.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

fn acme_reason(error: &AcmeError) -> &'static str {
    match error {
        AcmeError::Timeout => "timeout",
        AcmeError::Transport(_) => "transport",
        AcmeError::Certificate(_) => "certificate",
        AcmeError::InvalidRequest => "invalid_request",
    }
}

fn dns_reason(error: &DnsError) -> &'static str {
    match error {
        DnsError::Timeout => "timeout",
        DnsError::Transport => "transport",
        DnsError::Api => "api",
        DnsError::NotFound => "not_found",
        DnsError::PropagationTimeout => "propagation_timeout",
        DnsError::InvalidRecord => "invalid_record",
    }
}
