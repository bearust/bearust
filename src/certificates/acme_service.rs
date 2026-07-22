//! Certificate lifecycle orchestration.
//!
//! This module is deliberately the single owner of ACME state transitions.  A
//! job lock prevents two requests from issuing the same certificate at once;
//! repository state is updated only after certificate material has been
//! validated and activated.

use crate::control_plane::repository::DbPool;
use crate::{
    acme::{AcmeError, AcmeManager, CertificateRequest, CloudflareProvider},
    certificates::{CertificateError, CertificateStore},
    control_plane::ConfigReloader,
    control_plane::{
        audit,
        models::{AcmeChallenge, AcmeRequest, AcmeStatus},
        realtime::RealtimeHub,
        repository,
    },
    secrets::SecretStore,
};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sha2::{Digest, Sha256};
use std::{
    collections::HashSet,
    sync::{Arc, RwLock},
};
use thiserror::Error;
use tokio::sync::Mutex;

#[derive(Debug, Error)]
pub enum AcmeServiceError {
    #[error("ACME operation already running")]
    Busy,
    #[error("invalid ACME request: {0}")]
    Invalid(String),
    #[error("certificate was not found")]
    NotFound,
    #[error("ACME operation failed: {0}")]
    Acme(#[from] AcmeError),
    #[error("certificate operation failed: {0}")]
    Certificate(#[from] CertificateError),
    #[error("database operation failed: {0}")]
    Database(#[from] sqlx::Error),
    #[error("configuration reload failed: {0}")]
    Reload(String),
}

#[derive(Clone)]
pub struct AcmeService {
    db: DbPool,
    certificates: Arc<CertificateStore>,
    manager: Arc<AcmeManager>,
    reloader: Arc<dyn ConfigReloader>,
    jobs: Arc<Mutex<HashSet<String>>>,
    secrets: SecretStore,
    realtime: Arc<RwLock<Option<Arc<RealtimeHub>>>>,
}

impl AcmeService {
    pub fn new(
        db: DbPool,
        certificates: Arc<CertificateStore>,
        manager: Arc<AcmeManager>,
        reloader: Arc<dyn ConfigReloader>,
        secrets: SecretStore,
    ) -> Self {
        Self {
            db,
            certificates,
            manager,
            reloader,
            jobs: Arc::new(Mutex::new(HashSet::new())),
            secrets,
            realtime: Arc::new(RwLock::new(None)),
        }
    }

    /// Attach the process-local event hub after the service is constructed.
    /// This keeps the certificate service usable by embedded callers that do
    /// not run a control plane while allowing background renewals to notify
    /// connected dashboards.
    pub fn attach_realtime(&self, hub: Arc<RealtimeHub>) {
        if let Ok(mut slot) = self.realtime.write() {
            *slot = Some(hub);
        }
    }

    /// Issue and activate a certificate.  The request is normalized before a
    /// lock is acquired so equivalent host lists share one in-flight job.
    pub async fn issue(
        &self,
        actor_id: i64,
        request: AcmeRequest,
        cloudflare_token: Option<Vec<u8>>,
    ) -> Result<AcmeStatus, AcmeServiceError> {
        let request = request.normalized().map_err(AcmeServiceError::Invalid)?;
        let key = operation_key(&request);
        let _guard = JobGuard::acquire(self.jobs.clone(), key).await?;
        let name = certificate_name(&request);
        let issued = self
            .issue_material(&request, &name, cloudflare_token.clone())
            .await?;
        let hosts =
            serde_json::to_string(&issued.covered_hostnames).unwrap_or_else(|_| "[]".into());
        let id = repository::insert_certificate(
            &self.db,
            &issued.name,
            "letsencrypt",
            &hosts,
            &issued.expiry,
            &issued.certificate_path.to_string_lossy(),
            &issued.key_path.to_string_lossy(),
        )
        .await?;
        let status = repository::insert_acme_certificate(&self.db, id, &request).await?;
        if let (AcmeChallenge::CloudflareDns01, Some(token)) =
            (&request.challenge, cloudflare_token)
        {
            let secret_ref = format!("cloudflare-{id}");
            self.secrets
                .put(&secret_ref, &token)
                .map_err(|e| AcmeServiceError::Invalid(e.to_string()))?;
            repository::set_acme_secret_ref(&self.db, id, &secret_ref).await?;
        }
        let next = renewal_at(&issued.expiry);
        repository::update_acme_status(
            &self.db,
            id,
            "active",
            next.as_deref(),
            Some(&Utc::now().to_rfc3339()),
            None,
        )
        .await?;
        audit::record(
            &self.db,
            Some(actor_id),
            "acme_issued",
            &format!("certificate_id={id}"),
        )
        .await;
        self.reload(id).await?;
        Ok(repository::get_acme_status(&self.db, id)
            .await?
            .unwrap_or(status))
    }

    pub async fn renew(
        &self,
        actor_id: Option<i64>,
        certificate_id: i64,
    ) -> Result<AcmeStatus, AcmeServiceError> {
        let status = repository::get_acme_status(&self.db, certificate_id)
            .await?
            .ok_or(AcmeServiceError::NotFound)?;
        let _guard = JobGuard::acquire(self.jobs.clone(), format!("id:{certificate_id}")).await?;
        let name = repository::certificate_name(&self.db, certificate_id)
            .await?
            .ok_or(AcmeServiceError::NotFound)?;
        let request = AcmeRequest {
            environment: status.environment.clone(),
            challenge: status.challenge.clone(),
            hostnames: status.hostnames.clone(),
        }
        .normalized()
        .map_err(AcmeServiceError::Invalid)?;
        let token = if matches!(request.challenge, AcmeChallenge::CloudflareDns01) {
            let secret_ref = repository::acme_secret_ref(&self.db, certificate_id)
                .await?
                .ok_or_else(|| {
                    AcmeServiceError::Invalid("Cloudflare credentials are unavailable".into())
                })?;
            Some(
                self.secrets
                    .get(&secret_ref)
                    .map_err(|e| AcmeServiceError::Invalid(e.to_string()))?
                    .ok_or_else(|| {
                        AcmeServiceError::Invalid("Cloudflare credentials are unavailable".into())
                    })?,
            )
        } else {
            None
        };
        let issued = self.issue_material(&request, &name, token).await?;
        // import_letsencrypt validates before replacing the existing material;
        // activation is the final state transition and can therefore be
        // retried without changing the previous active pointer on failure.
        let cert = std::fs::read(&issued.certificate_path)
            .map_err(|e| AcmeServiceError::Certificate(CertificateError::Io(e)))?;
        let key = std::fs::read(&issued.key_path)
            .map_err(|e| AcmeServiceError::Certificate(CertificateError::Io(e)))?;
        let record = self.certificates.import_letsencrypt(&name, &cert, &key)?;
        self.certificates.activate(&record.name)?;
        let next = renewal_at(&record.expiry);
        repository::update_acme_status(
            &self.db,
            certificate_id,
            "active",
            next.as_deref(),
            Some(&Utc::now().to_rfc3339()),
            None,
        )
        .await?;
        audit::record(
            &self.db,
            actor_id,
            "acme_renewed",
            &format!("certificate_id={certificate_id}"),
        )
        .await;
        self.reload(certificate_id).await?;
        self.publish_realtime("certificates.changed");
        repository::get_acme_status(&self.db, certificate_id)
            .await?
            .ok_or(AcmeServiceError::NotFound)
    }

    pub async fn status(&self, certificate_id: i64) -> Result<AcmeStatus, AcmeServiceError> {
        repository::get_acme_status(&self.db, certificate_id)
            .await?
            .ok_or(AcmeServiceError::NotFound)
    }

    pub async fn run_due_renewals(&self) -> Result<(), AcmeServiceError> {
        let now = Utc::now();
        let due = repository::list_due_acme_certificates(&self.db, &now.to_rfc3339()).await?;
        for item in due {
            if let Err(error) = self.renew(None, item.certificate_id).await {
                let code = error_code(&error);
                let _ = repository::update_acme_status(
                    &self.db,
                    item.certificate_id,
                    "retrying",
                    Some(&(now + ChronoDuration::hours(1)).to_rfc3339()),
                    Some(&now.to_rfc3339()),
                    Some(code),
                )
                .await;
            }
        }
        Ok(())
    }

    async fn issue_material(
        &self,
        request: &AcmeRequest,
        name: &str,
        cloudflare_token: Option<Vec<u8>>,
    ) -> Result<crate::certificates::CertificateRecord, AcmeServiceError> {
        let req = CertificateRequest::new(name, request.hostnames.clone());
        match request.challenge {
            AcmeChallenge::Http01 => Ok(self.manager.request_http01(req).await?),
            AcmeChallenge::CloudflareDns01 => {
                let token = cloudflare_token.ok_or_else(|| {
                    AcmeServiceError::Invalid("Cloudflare token is required".into())
                })?;
                let secret_name = format!("cloudflare-{}", uuid::Uuid::new_v4());
                self.secrets
                    .put(&secret_name, &token)
                    .map_err(|e| AcmeServiceError::Invalid(e.to_string()))?;
                let provider = CloudflareProvider::with_secret_store(
                    &secret_name,
                    self.secrets.clone(),
                    "https://api.cloudflare.com/client/v4",
                    std::time::Duration::from_secs(10),
                    std::time::Duration::from_secs(120),
                    std::time::Duration::from_secs(2),
                )
                .map_err(|e| AcmeServiceError::Invalid(e.to_string()))?;
                let result = self.manager.request_dns01(req, Arc::new(provider)).await;
                let _ = self.secrets.delete(&secret_name);
                Ok(result?)
            }
        }
    }
    async fn reload(&self, certificate_id: i64) -> Result<(), AcmeServiceError> {
        self.reloader
            .apply_certificate_change(certificate_id)
            .await
            .map_err(|e| AcmeServiceError::Reload(e.to_string()))
    }

    fn publish_realtime(&self, kind: &'static str) {
        if let Ok(slot) = self.realtime.read() {
            if let Some(hub) = slot.as_ref() {
                hub.publish(kind);
            }
        }
    }
}

struct JobGuard {
    jobs: Arc<Mutex<HashSet<String>>>,
    key: String,
}
impl JobGuard {
    async fn acquire(
        jobs: Arc<Mutex<HashSet<String>>>,
        key: String,
    ) -> Result<Self, AcmeServiceError> {
        let mut lock = jobs.lock().await;
        if !lock.insert(key.clone()) {
            return Err(AcmeServiceError::Busy);
        }
        drop(lock);
        Ok(Self { jobs, key })
    }
}
impl Drop for JobGuard {
    fn drop(&mut self) {
        let jobs = self.jobs.clone();
        let key = self.key.clone();
        tokio::spawn(async move {
            jobs.lock().await.remove(&key);
        });
    }
}

fn operation_key(request: &AcmeRequest) -> String {
    format!(
        "{}:{:?}:{:?}",
        certificate_name(request),
        request.environment,
        request.challenge
    )
}
fn certificate_name(request: &AcmeRequest) -> String {
    let mut h = Sha256::new();
    h.update(request.hostnames.join("\n"));
    format!("acme-{}", &hex::encode(h.finalize())[..24])
}
fn renewal_at(expiry: &str) -> Option<String> {
    DateTime::parse_from_str(expiry, "%b %e %H:%M:%S %Y GMT")
        .ok()
        .map(|d| (d.with_timezone(&Utc) - ChronoDuration::days(30)).to_rfc3339())
}
fn error_code(error: &AcmeServiceError) -> &'static str {
    match error {
        AcmeServiceError::Busy => "busy",
        AcmeServiceError::Invalid(_) => "invalid_request",
        AcmeServiceError::NotFound => "not_found",
        AcmeServiceError::Acme(AcmeError::Timeout) => "timeout",
        _ => "failed",
    }
}
