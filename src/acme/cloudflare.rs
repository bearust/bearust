use super::dns::{DnsError, DnsProvider, TxtRecord};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;
use std::{collections::HashMap, sync::{Arc, Mutex}, time::Duration};

#[derive(Clone)]
pub struct CloudflareProvider {
    client: Client,
    base_url: String,
    token: String,
    propagation_timeout: Duration,
    poll_interval: Duration,
    created_records: Arc<Mutex<HashMap<(String, String), String>>>,
}

#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    success: bool,
    result: Option<T>,
}

#[derive(Debug, Deserialize)]
struct Zone {
    id: String,
}

#[derive(Debug, Deserialize)]
struct Record {
    id: String,
    #[serde(default)]
    name: String,
    #[serde(default)]
    content: String,
}

impl CloudflareProvider {
    pub fn new(token: impl Into<String>) -> Result<Self, DnsError> {
        Self::with_endpoint(
            token,
            "https://api.cloudflare.com/client/v4",
            Duration::from_secs(10),
            Duration::from_secs(120),
            Duration::from_secs(2),
        )
    }

    pub fn with_endpoint(
        token: impl Into<String>,
        endpoint: impl Into<String>,
        timeout: Duration,
        propagation_timeout: Duration,
        poll_interval: Duration,
    ) -> Result<Self, DnsError> {
        let token = token.into();
        if token.trim().is_empty() {
            return Err(DnsError::InvalidRecord);
        }
        let client = Client::builder()
            .timeout(timeout)
            .build()
            .map_err(|_| DnsError::Transport)?;
        Ok(Self {
            client,
            base_url: endpoint.into().trim_end_matches('/').to_string(),
            token,
            propagation_timeout,
            poll_interval,
            created_records: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    async fn send<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T, DnsError> {
        let response = request
            .header("Authorization", format!("Bearer {}", self.token))
            .send()
            .await
            .map_err(|e| {
                if e.is_timeout() {
                    DnsError::Timeout
                } else {
                    DnsError::Transport
                }
            })?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Err(DnsError::NotFound);
        }
        if !response.status().is_success() {
            return Err(DnsError::Api);
        }
        let body: ApiResponse<T> = response.json().await.map_err(|_| DnsError::Api)?;
        if !body.success {
            return Err(DnsError::Api);
        }
        body.result.ok_or(DnsError::Api)
    }

    async fn zone(&self, name: &str) -> Result<Zone, DnsError> {
        let normalized = name.trim_start_matches("*.").trim_end_matches('.');
        let labels: Vec<&str> = normalized.split('.').filter(|s| !s.is_empty()).collect();
        if labels.len() < 2 {
            return Err(DnsError::InvalidRecord);
        }
        for start in 0..labels.len() - 1 {
            let candidate = labels[start..].join(".");
            let url = format!("{}/zones", self.base_url);
            let result: Vec<Zone> = self
                .send(self.client.get(url).query(&[
                    ("name", candidate.as_str()),
                    ("status", "active"),
                    ("per_page", "1"),
                ]))
                .await?;
            if let Some(zone) = result.into_iter().next() {
                return Ok(zone);
            }
        }
        Err(DnsError::Api)
    }

    async fn record_id(&self, record: &TxtRecord) -> Result<(Zone, Option<String>), DnsError> {
        let zone = self.zone(&record.name).await?;
        let url = format!("{}/zones/{}/dns_records", self.base_url, zone.id);
        let records: Vec<Record> = self
            .send(self.client.get(url).query(&[
                ("type", "TXT"),
                ("name", record.name.as_str()),
                ("per_page", "100"),
            ]))
            .await?;
        Ok((
            zone,
            records
                .into_iter()
                .find(|candidate| {
                    candidate.name == record.name && candidate.content == record.value
                })
                .map(|r| r.id),
        ))
    }
}

#[async_trait]
impl DnsProvider for CloudflareProvider {
    async fn present(&self, record: TxtRecord) -> Result<(), DnsError> {
        if !valid_dns_name(&record.name) || record.value.is_empty() {
            return Err(DnsError::InvalidRecord);
        }
        let zone = self.zone(&record.name).await?;
        let url = format!("{}/zones/{}/dns_records", self.base_url, zone.id);
        let created: Record = self.send(self.client.post(url).json(&serde_json::json!({"type":"TXT", "name":record.name, "content":record.value, "ttl":120, "proxied":false}))).await?;
        if let Ok(mut records) = self.created_records.lock() {
            records.insert((record.name, record.value), created.id);
        }
        Ok(())
    }

    async fn cleanup(&self, record: TxtRecord) -> Result<(), DnsError> {
        let id = self.created_records.lock().ok().and_then(|mut records| records.remove(&(record.name.clone(), record.value.clone())));
        if let Some(id) = id {
            let zone = self.zone(&record.name).await?;
            let url = format!("{}/zones/{}/dns_records/{}", self.base_url, zone.id, id);
            let request = self.client.delete(url);
            match self.send::<serde_json::Value>(request).await {
                Ok(_) | Err(DnsError::NotFound) => Ok(()),
                Err(e) => Err(e),
            }
        } else {
            Ok(())
        }
    }

    async fn wait_for_propagation(&self, record: TxtRecord) -> Result<(), DnsError> {
        let deadline = tokio::time::Instant::now() + self.propagation_timeout;
        loop {
            let (_, id) = self.record_id(&record).await?;
            if id.is_some() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                return Err(DnsError::PropagationTimeout);
            }
            tokio::time::sleep(self.poll_interval).await;
        }
    }
}

fn valid_dns_name(value: &str) -> bool {
    let value = value.trim().trim_end_matches('.');
    !value.is_empty() && value.split('.').all(|label| {
        !label.is_empty() && label.len() <= 63 && !label.starts_with('-') && !label.ends_with('-')
            && label.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    })
}
