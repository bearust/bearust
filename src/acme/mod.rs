//! ACME issuance orchestration with an injectable transport.
mod http01;
use crate::certificates::{CertificateError, CertificateRecord, CertificateStore};
use async_trait::async_trait;
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

fn acme_reason(error: &AcmeError) -> &'static str {
    match error {
        AcmeError::Timeout => "timeout",
        AcmeError::Transport(_) => "transport",
        AcmeError::Certificate(_) => "certificate",
        AcmeError::InvalidRequest => "invalid_request",
    }
}
