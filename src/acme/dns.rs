use async_trait::async_trait;
use thiserror::Error;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TxtRecord {
    pub name: String,
    pub value: String,
}

impl TxtRecord {
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

#[derive(Debug, Error)]
pub enum DnsError {
    #[error("DNS provider request timed out")]
    Timeout,
    #[error("DNS provider transport failed")]
    Transport,
    #[error("DNS provider returned an unsuccessful response")]
    Api,
    #[error("DNS record was not found")]
    NotFound,
    #[error("DNS record propagation timed out")]
    PropagationTimeout,
    #[error("DNS record is invalid")]
    InvalidRecord,
}

#[async_trait]
pub trait DnsProvider: Send + Sync {
    async fn present(&self, record: TxtRecord) -> Result<(), DnsError>;
    async fn cleanup(&self, record: TxtRecord) -> Result<(), DnsError>;
    async fn wait_for_propagation(&self, record: TxtRecord) -> Result<(), DnsError>;
}
