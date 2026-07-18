//! Production ACME client backed by `instant-acme`.
use super::{AcmeError, AcmeOrder, AcmeTransport, CertificateRequest, Http01Store, IssuedCertificate, TxtRecord};
use crate::secrets::SecretStore;
use async_trait::async_trait;
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use instant_acme::{Account, AccountCredentials, ChallengeType, HttpClient, NewAccount, NewOrder, Identifier, OrderStatus};
use openssl::{hash::MessageDigest, nid::Nid, pkey::PKey, rsa::Rsa, stack::Stack, x509::{X509Extension, X509NameBuilder, X509ReqBuilder}};
use reqwest::Client;
use std::{collections::HashMap, fmt, future::Future, pin::Pin, time::Duration};
use tokio::sync::Mutex;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcmeEnvironment { Staging, Production }
impl AcmeEnvironment { pub fn directory_url(self) -> &'static str { match self { Self::Staging => "https://acme-staging-v02.api.letsencrypt.org/directory", Self::Production => "https://acme-v02.api.letsencrypt.org/directory" } } }

struct ReqwestHttp(Client);
impl HttpClient for ReqwestHttp {
    fn request(&self, req: Request<Full<Bytes>>) -> Pin<Box<dyn Future<Output = Result<instant_acme::BytesResponse, instant_acme::Error>> + Send>> {
        let client = self.0.clone();
        Box::pin(async move {
            let (parts, body) = req.into_parts();
            let bytes = body.collect().await.map_err(|e| instant_acme::Error::Other(Box::new(e)))?.to_bytes();
            let mut rb = client.request(parts.method, parts.uri.to_string()).body(bytes);
            for (name, value) in &parts.headers { rb = rb.header(name, value); }
            let response = rb.send().await.map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
            let status = response.status();
            let headers = response.headers().clone();
            let body = response.bytes().await.map_err(|e| instant_acme::Error::Other(Box::new(e)))?;
            let mut builder = Response::builder().status(status);
            *builder.headers_mut().expect("response builder") = headers;
            Ok(builder.body(Full::new(body)).map_err(instant_acme::Error::from)?.into())
        })
    }
}

pub struct LetsEncryptClient {
    environment: AcmeEnvironment,
    secrets: SecretStore,
    http_client: Client,
    account_key: Vec<u8>,
    credentials: Mutex<Option<AccountCredentials>>,
    orders: Mutex<HashMap<String, instant_acme::Order>>,
    order_challenges: Mutex<HashMap<String, ChallengeType>>,
    operation_timeout: Duration,
}
impl fmt::Debug for LetsEncryptClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.debug_struct("LetsEncryptClient").field("environment", &self.environment).field("directory_url", &self.environment.directory_url()).field("operation_timeout", &self.operation_timeout).field("account_key", &"[REDACTED]").finish() }
}
impl LetsEncryptClient {
    pub fn new(environment: AcmeEnvironment, secrets: SecretStore, http_client: Client) -> Result<Self, AcmeError> {
        let raw = secrets.get("acme-account-key").map_err(|_| AcmeError::Account("secret unavailable".into()))?.unwrap_or_default();
        let credentials = serde_json::from_slice(&raw).ok();
        Ok(Self { environment, secrets, http_client, account_key: raw, credentials: Mutex::new(credentials), orders: Mutex::new(HashMap::new()), order_challenges: Mutex::new(HashMap::new()), operation_timeout: Duration::from_secs(60) })
    }
    pub fn environment(&self) -> AcmeEnvironment { self.environment }
    pub fn directory_url(&self) -> &'static str { self.environment.directory_url() }
    /// Returns an opaque persisted account-key blob for diagnostics/tests; never logs it.
    pub fn account_key(&self) -> &[u8] { &self.account_key }
    pub fn with_operation_timeout(mut self, timeout: Duration) -> Self { self.operation_timeout = timeout; self }
    async fn account(&self) -> Result<Account, AcmeError> {
        let mut guard = self.credentials.lock().await;
        if let Some(credentials) = guard.as_ref() { return Account::from_credentials_and_http(serde_json::from_slice(&serde_json::to_vec(credentials).map_err(|_| AcmeError::Account("account serialization failed".into()))?).map_err(|_| AcmeError::Account("account credentials invalid".into()))?, Box::new(ReqwestHttp(self.http_client.clone()))).await.map_err(|_| AcmeError::Account("account restore failed".into())); }
        let new = NewAccount { contact: &[], terms_of_service_agreed: true, only_return_existing: false };
        let (account, credentials) = Account::create_with_http(&new, self.directory_url(), None, Box::new(ReqwestHttp(self.http_client.clone()))).await.map_err(|_| AcmeError::Account("account creation failed".into()))?;
        let encoded = serde_json::to_vec(&credentials).map_err(|_| AcmeError::Account("account serialization failed".into()))?;
        self.secrets.put("acme-account-key", &encoded).map_err(|_| AcmeError::Account("account persistence failed".into()))?;
        *guard = Some(credentials);
        Ok(account)
    }
    fn map_error(err: instant_acme::Error, phase: &'static str) -> AcmeError { let _ = err; match phase { "directory" => AcmeError::Directory, "account" => AcmeError::Account("account operation failed".into()), "authorization" => AcmeError::Authorization, "finalize" => AcmeError::Finalize, _ => AcmeError::Transport("ACME transport failed".into()) } }
    async fn wait_order(&self, order: &mut instant_acme::Order) -> Result<(), AcmeError> {
        let deadline = tokio::time::Instant::now() + self.operation_timeout;
        for _ in 0..60 {
            let state = tokio::time::timeout_at(deadline, order.refresh()).await.map_err(|_| AcmeError::Timeout)?.map_err(|e| Self::map_error(e, "authorization"))?;
            match state.status { OrderStatus::Ready | OrderStatus::Valid => return Ok(()), OrderStatus::Invalid => return Err(AcmeError::Authorization), _ => tokio::time::sleep(Duration::from_secs(1)).await }
        }
        Err(AcmeError::Timeout)
    }
    async fn poll_order_with_type(&self, order_ref: &AcmeOrder, challenge_type: ChallengeType) -> Result<(), AcmeError> {
        let deadline = tokio::time::Instant::now() + self.operation_timeout;
        if let Some(expected) = self.order_challenges.lock().await.get(&order_ref.id).cloned() {
            if expected != challenge_type {
                return Err(AcmeError::InvalidRequest);
            }
        }
        let mut order = self.orders.lock().await.remove(&order_ref.id).ok_or(AcmeError::Authorization)?;
        let auths = tokio::time::timeout_at(deadline, order.authorizations()).await.map_err(|_| AcmeError::Timeout)?.map_err(|e| Self::map_error(e, "authorization"))?;
        for auth in auths {
            if let Some(ch) = auth.challenges.iter().find(|c| c.r#type == challenge_type) {
                tokio::time::timeout_at(deadline, order.set_challenge_ready(&ch.url)).await.map_err(|_| AcmeError::Timeout)?.map_err(|e| Self::map_error(e, "authorization"))?;
            }
        }
        self.wait_order(&mut order).await?;
        self.orders.lock().await.insert(order.url().to_owned(), order);
        self.order_challenges.lock().await.remove(&order_ref.id);
        Ok(())
    }
}
#[async_trait]
impl AcmeTransport for LetsEncryptClient {
    async fn new_order(&self, request: &CertificateRequest) -> Result<AcmeOrder, AcmeError> {
        if request.hostnames.is_empty() { return Err(AcmeError::InvalidRequest); }
        let fut = async {
            let account = self.account().await?;
            let ids: Vec<_> = request.hostnames.iter().map(|h| Identifier::Dns(h.clone())).collect();
            let mut order = account.new_order(&NewOrder { identifiers: &ids }).await.map_err(|e| Self::map_error(e, "directory"))?;
            let auths = order.authorizations().await.map_err(|e| Self::map_error(e, "authorization"))?;
            // Wildcard identifiers require DNS-01; otherwise prefer HTTP-01 deterministically.
            let preferred = if request.hostnames.iter().any(|h| h.trim_start().starts_with("*.")) { ChallengeType::Dns01 } else { ChallengeType::Http01 };
            let challenge = auths.iter().flat_map(|a| a.challenges.iter()).find(|c| c.r#type == preferred).or_else(|| auths.iter().flat_map(|a| a.challenges.iter()).find(|c| c.r#type == ChallengeType::Http01 || c.r#type == ChallengeType::Dns01)).ok_or(AcmeError::Authorization)?;
            let key = order.key_authorization(challenge).as_str().to_owned();
            let result = AcmeOrder { id: order.url().to_owned(), token: challenge.token.clone(), key_authorization: key };
            self.order_challenges.lock().await.insert(result.id.clone(), challenge.r#type.clone());
            self.orders.lock().await.insert(result.id.clone(), order);
            Ok(result)
        };
        tokio::time::timeout(self.operation_timeout, fut).await.map_err(|_| AcmeError::Timeout)?
    }
    async fn poll_order(&self, order: &AcmeOrder, _challenges: &Http01Store) -> Result<(), AcmeError> { self.poll_order_with_type(order, ChallengeType::Http01).await }
    async fn poll_order_dns01(&self, order: &AcmeOrder, _records: &[TxtRecord]) -> Result<(), AcmeError> { self.poll_order_with_type(order, ChallengeType::Dns01).await }
    #[allow(deprecated)]
    async fn finalize(&self, order: &AcmeOrder, request: &CertificateRequest) -> Result<IssuedCertificate, AcmeError> { let deadline = tokio::time::Instant::now() + self.operation_timeout; let mut order = self.orders.lock().await.remove(&order.id).ok_or(AcmeError::Finalize)?; let rsa = Rsa::generate(2048).map_err(|_| AcmeError::Finalize)?; let key = PKey::from_rsa(rsa).map_err(|_| AcmeError::Finalize)?; let mut name = X509NameBuilder::new().map_err(|_| AcmeError::Finalize)?; name.append_entry_by_text("CN", &request.hostnames[0]).map_err(|_| AcmeError::Finalize)?; let name = name.build(); let mut csr = X509ReqBuilder::new().map_err(|_| AcmeError::Finalize)?; csr.set_subject_name(&name).map_err(|_| AcmeError::Finalize)?; csr.set_pubkey(&key).map_err(|_| AcmeError::Finalize)?; let mut extensions = Stack::new().map_err(|_| AcmeError::Finalize)?; let san = request.hostnames.iter().map(|h| format!("DNS:{}", h.trim())).collect::<Vec<_>>().join(","); extensions.push(X509Extension::new_nid(None, None, Nid::SUBJECT_ALT_NAME, &san).map_err(|_| AcmeError::Finalize)?).map_err(|_| AcmeError::Finalize)?; csr.add_extensions(&extensions).map_err(|_| AcmeError::Finalize)?; csr.sign(&key, MessageDigest::sha256()).map_err(|_| AcmeError::Finalize)?; tokio::time::timeout_at(deadline, order.finalize(&csr.build().to_der().map_err(|_| AcmeError::Finalize)?)).await.map_err(|_| AcmeError::Timeout)?.map_err(|e| Self::map_error(e, "finalize"))?; let cert = loop { if let Some(cert) = tokio::time::timeout_at(deadline, order.certificate()).await.map_err(|_| AcmeError::Timeout)?.map_err(|e| Self::map_error(e, "finalize"))? { break cert.into_bytes(); } tokio::time::sleep(Duration::from_secs(1)).await; }; let private_key_pem = key.private_key_to_pem_pkcs8().map_err(|_| AcmeError::Finalize)?; Ok(IssuedCertificate { certificate_pem: cert, private_key_pem }) }
}
