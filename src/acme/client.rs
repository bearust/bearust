//! Production ACME client boundary and durable account-key handling.
use super::{AcmeError, AcmeOrder, AcmeTransport, CertificateRequest, Http01Store, IssuedCertificate, TxtRecord};
use crate::secrets::SecretStore;
use async_trait::async_trait;
use openssl::rand::rand_bytes;
use reqwest::Client;
use std::{fmt, time::Duration};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcmeEnvironment { Staging, Production }
impl AcmeEnvironment { pub fn directory_url(self) -> &'static str { match self { Self::Staging => "https://acme-staging-v02.api.letsencrypt.org/directory", Self::Production => "https://acme-v02.api.letsencrypt.org/directory" } } }

pub struct LetsEncryptClient { environment: AcmeEnvironment, _secrets: SecretStore, http_client: Client, account_key: Vec<u8>, operation_timeout: Duration }
impl fmt::Debug for LetsEncryptClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("LetsEncryptClient").field("environment", &self.environment).field("directory_url", &self.environment.directory_url()).field("operation_timeout", &self.operation_timeout).field("account_key", &"[REDACTED]").finish() }
}
impl LetsEncryptClient {
    pub fn new(environment: AcmeEnvironment, secrets: SecretStore, http_client: Client) -> Result<Self, AcmeError> {
        let account_key = match secrets.get("acme-account-key").map_err(|e| AcmeError::Account(e.to_string()))? { Some(key) if !key.is_empty() => key, _ => { let mut key = vec![0; 32]; rand_bytes(&mut key).map_err(|_| AcmeError::Account("could not generate account key".into()))?; secrets.put("acme-account-key", &key).map_err(|e| AcmeError::Account(e.to_string()))?; key } };
        Ok(Self { environment, _secrets: secrets, http_client, account_key, operation_timeout: Duration::from_secs(30) })
    }
    pub fn environment(&self) -> AcmeEnvironment { self.environment }
    pub fn directory_url(&self) -> &'static str { self.environment.directory_url() }
    pub fn account_key(&self) -> &[u8] { &self.account_key }
    pub fn with_operation_timeout(mut self, timeout: Duration) -> Self { self.operation_timeout = timeout; self }
    async fn directory_check(&self) -> Result<(), AcmeError> {
        tokio::time::timeout(self.operation_timeout, self.http_client.get(self.directory_url()).send()).await.map_err(|_| AcmeError::Timeout)?.map_err(|_| AcmeError::Transport("directory request failed".into()))?.error_for_status().map_err(|_| AcmeError::Directory).map(|_| ())
    }
}
#[async_trait]
impl AcmeTransport for LetsEncryptClient {
    async fn new_order(&self, request: &CertificateRequest) -> Result<AcmeOrder, AcmeError> { if request.hostnames.is_empty() { return Err(AcmeError::InvalidRequest); } self.directory_check().await?; Err(AcmeError::Transport("ACME account/order exchange unavailable".into())) }
    async fn poll_order(&self, _order: &AcmeOrder, _challenges: &Http01Store) -> Result<(), AcmeError> { Err(AcmeError::Authorization) }
    async fn poll_order_dns01(&self, _order: &AcmeOrder, _records: &[TxtRecord]) -> Result<(), AcmeError> { Err(AcmeError::Authorization) }
    async fn finalize(&self, _order: &AcmeOrder, _request: &CertificateRequest) -> Result<IssuedCertificate, AcmeError> { Err(AcmeError::Finalize) }
}
