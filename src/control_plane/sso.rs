//! Single sign-on through external identity providers.
//!
//! OIDC uses the authorization-code flow with PKCE (S256), a single-use
//! `state` bound to a browser cookie, and a `nonce` echoed in the ID token.
//! ID tokens are verified against the provider's JWKS with asymmetric
//! algorithms only. SAML (feature `saml`) lives in [`super::sso_saml`].
//!
//! A provider subject is linked to a local user through `sso_identities`.
//! An unlinked subject is linked to an existing account by email only when
//! the provider asserts the email as verified and `link_by_email` is set,
//! and a new account is created only when `auto_provision` is set. Accounts
//! created this way have no usable password.

use crate::control_plane::models::{ErrorEnvelope, User};
use crate::control_plane::rbac::{authorize, Permission, ResourceContext};
use crate::control_plane::{audit, auth, repository, AppState};
use axum::{
    extract::{Path, RawQuery, State},
    http::{header, HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Redirect, Response},
    Json,
};
use jsonwebtoken::{jwk::JwkSet, Algorithm, DecodingKey, Validation};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use sqlx::Row;
use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Login attempts must complete within this window.
const STATE_TTL_SECONDS: i64 = 600;
/// Discovery documents and JWKS are refreshed after this long.
const METADATA_TTL: Duration = Duration::from_secs(3600);
const STATE_COOKIE: &str = "bearust_sso";
/// Password hash marker for SSO-only accounts; never parses as a hash.
pub const SSO_ONLY_PASSWORD: &str = "!sso-only";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProviderKind {
    Oidc,
    Saml,
}

impl ProviderKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Oidc => "oidc",
            Self::Saml => "saml",
        }
    }
    fn parse(value: &str) -> Option<Self> {
        match value {
            "oidc" => Some(Self::Oidc),
            "saml" => Some(Self::Saml),
            _ => None,
        }
    }
}

/// Settings shared by every provider kind.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct AccountPolicy {
    /// Role given to auto-provisioned accounts.
    pub default_role: String,
    #[serde(default)]
    pub auto_provision: bool,
    #[serde(default)]
    pub link_by_email: bool,
    /// When non-empty, only emails in these domains may sign in.
    #[serde(default)]
    pub allowed_domains: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    /// Public base URL of this dashboard, e.g. `https://bearust.example.com`;
    /// the callback is `<base>/api/auth/sso/<slug>/callback`.
    pub redirect_base_url: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    #[serde(flatten)]
    pub account: AccountPolicy,
}

fn default_scopes() -> Vec<String> {
    vec!["openid".into(), "email".into(), "profile".into()]
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SsoProvider {
    pub id: i64,
    pub slug: String,
    pub kind: ProviderKind,
    pub name: String,
    pub enabled: bool,
    pub config: serde_json::Value,
    /// Whether a client secret is stored (OIDC). The secret itself is never
    /// returned.
    pub has_secret: bool,
}

impl SsoProvider {
    pub fn account_policy(&self) -> Option<AccountPolicy> {
        match self.kind {
            ProviderKind::Oidc => serde_json::from_value::<OidcConfig>(self.config.clone())
                .ok()
                .map(|c| c.account),
            #[cfg(feature = "saml")]
            ProviderKind::Saml => {
                serde_json::from_value::<super::sso_saml::SamlConfig>(self.config.clone())
                    .ok()
                    .map(|c| c.account)
            }
            #[cfg(not(feature = "saml"))]
            ProviderKind::Saml => None,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProviderInput {
    pub slug: String,
    pub kind: ProviderKind,
    pub name: String,
    #[serde(default = "enabled_default")]
    pub enabled: bool,
    pub config: serde_json::Value,
    /// OIDC client secret. Omit on update to keep the stored secret.
    #[serde(default)]
    pub client_secret: Option<String>,
}

fn enabled_default() -> bool {
    true
}

/// Public listing for the login page.
#[derive(Debug, Serialize)]
pub struct PublicProvider {
    pub slug: String,
    pub name: String,
    pub kind: ProviderKind,
}

// ---------------------------------------------------------------------------
// Storage
// ---------------------------------------------------------------------------

fn secret_name(slug: &str) -> String {
    format!("sso-{slug}-client-secret")
}

fn provider_from_row(state: &AppState, row: &sqlx::any::AnyRow) -> Option<SsoProvider> {
    let slug: String = row.get("slug");
    Some(SsoProvider {
        id: row.get("id"),
        kind: ProviderKind::parse(&row.get::<String, _>("kind"))?,
        name: row.get("name"),
        enabled: row.get::<i64, _>("enabled") != 0,
        config: serde_json::from_str(&row.get::<String, _>("config")).ok()?,
        has_secret: state
            .secrets
            .get(&secret_name(&slug))
            .ok()
            .flatten()
            .is_some(),
        slug,
    })
}

pub async fn list_providers(state: &AppState) -> Result<Vec<SsoProvider>, sqlx::Error> {
    let rows =
        sqlx::query("SELECT id,slug,kind,name,enabled,config FROM sso_providers ORDER BY name")
            .fetch_all(&state.db)
            .await?;
    Ok(rows
        .iter()
        .filter_map(|row| provider_from_row(state, row))
        .collect())
}

pub async fn provider_by_slug(
    state: &AppState,
    slug: &str,
) -> Result<Option<SsoProvider>, sqlx::Error> {
    let row =
        sqlx::query("SELECT id,slug,kind,name,enabled,config FROM sso_providers WHERE slug=?")
            .bind(slug)
            .fetch_optional(&state.db)
            .await?;
    Ok(row.as_ref().and_then(|row| provider_from_row(state, row)))
}

fn state_hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

pub(crate) async fn store_login_state(
    state: &AppState,
    provider_id: i64,
    key: &str,
    nonce: &str,
    code_verifier: &str,
) -> Result<(), sqlx::Error> {
    let now = chrono::Utc::now();
    sqlx::query("DELETE FROM sso_login_states WHERE expires_at < ?")
        .bind(now.to_rfc3339())
        .execute(&state.db)
        .await?;
    sqlx::query(
        "INSERT INTO sso_login_states(state_hash,provider_id,nonce,code_verifier,expires_at)
         VALUES(?,?,?,?,?)",
    )
    .bind(state_hash(key))
    .bind(provider_id)
    .bind(nonce)
    .bind(code_verifier)
    .bind((now + chrono::Duration::seconds(STATE_TTL_SECONDS)).to_rfc3339())
    .execute(&state.db)
    .await?;
    Ok(())
}

/// Consume a login state exactly once; returns `(nonce, code_verifier)`.
pub(crate) async fn take_login_state(
    state: &AppState,
    provider_id: i64,
    key: &str,
) -> Result<Option<(String, String)>, sqlx::Error> {
    let hash = state_hash(key);
    let row = sqlx::query(
        "SELECT nonce,code_verifier,expires_at FROM sso_login_states
         WHERE state_hash=? AND provider_id=?",
    )
    .bind(&hash)
    .bind(provider_id)
    .fetch_optional(&state.db)
    .await?;
    let Some(row) = row else { return Ok(None) };
    // Deleting first and requiring the delete to succeed makes the state
    // single-use even under concurrent callbacks.
    let deleted = sqlx::query("DELETE FROM sso_login_states WHERE state_hash=?")
        .bind(&hash)
        .execute(&state.db)
        .await?
        .rows_affected();
    let expires = row.get::<String, _>("expires_at");
    let live =
        chrono::DateTime::parse_from_rfc3339(&expires).is_ok_and(|exp| exp > chrono::Utc::now());
    Ok((deleted == 1 && live).then(|| (row.get("nonce"), row.get("code_verifier"))))
}

/// Verified identity asserted by a provider.
#[derive(Debug, Clone)]
pub struct AssertedIdentity {
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ResolveError {
    DomainNotAllowed,
    NotLinked,
    Disabled,
    Database,
}

/// Map an asserted identity to a local user, linking or provisioning as the
/// provider's account policy allows.
pub async fn resolve_user(
    state: &AppState,
    provider: &SsoProvider,
    policy: &AccountPolicy,
    identity: &AssertedIdentity,
) -> Result<User, ResolveError> {
    let email = identity
        .email
        .as_deref()
        .map(|e| e.trim().to_ascii_lowercase())
        .filter(|e| e.contains('@'));
    if !policy.allowed_domains.is_empty() {
        let domain_ok = identity.email_verified
            && email.as_deref().is_some_and(|email| {
                let domain = email.rsplit('@').next().unwrap_or_default();
                policy
                    .allowed_domains
                    .iter()
                    .any(|allowed| allowed.trim().eq_ignore_ascii_case(domain))
            });
        if !domain_ok {
            return Err(ResolveError::DomainNotAllowed);
        }
    }
    let linked =
        sqlx::query("SELECT user_id FROM sso_identities WHERE provider_id=? AND subject=?")
            .bind(provider.id)
            .bind(&identity.subject)
            .fetch_optional(&state.db)
            .await
            .map_err(|_| ResolveError::Database)?
            .map(|row| row.get::<i64, _>("user_id"));
    let users = repository::list_users(&state.db)
        .await
        .map_err(|_| ResolveError::Database)?;
    let user = if let Some(user_id) = linked {
        users.into_iter().find(|u| u.id == user_id)
    } else {
        let verified_email = email.filter(|_| identity.email_verified);
        let existing = verified_email
            .as_deref()
            .filter(|_| policy.link_by_email)
            .and_then(|email| users.iter().find(|u| u.email == email).cloned());
        let user = match (existing, verified_email) {
            (Some(user), _) => user,
            (None, Some(email)) if policy.auto_provision => {
                if users.iter().any(|u| u.email == email) {
                    // The email belongs to an account we may not link to.
                    return Err(ResolveError::NotLinked);
                }
                let user = repository::insert_user(
                    &state.db,
                    &email,
                    SSO_ONLY_PASSWORD,
                    &policy.default_role,
                )
                .await
                .map_err(|_| ResolveError::Database)?;
                audit::record_state(
                    state,
                    Some(user.id),
                    "sso_user_provisioned",
                    &serde_json::json!({ "provider": provider.slug, "user_id": user.id })
                        .to_string(),
                )
                .await;
                state.realtime.publish("users.changed");
                user
            }
            _ => return Err(ResolveError::NotLinked),
        };
        sqlx::query(
            "INSERT INTO sso_identities(provider_id,subject,user_id,created_at) VALUES(?,?,?,?)",
        )
        .bind(provider.id)
        .bind(&identity.subject)
        .bind(user.id)
        .bind(chrono::Utc::now().to_rfc3339())
        .execute(&state.db)
        .await
        .map_err(|_| ResolveError::Database)?;
        audit::record_state(
            state,
            Some(user.id),
            "sso_identity_linked",
            &serde_json::json!({ "provider": provider.slug, "user_id": user.id }).to_string(),
        )
        .await;
        Some(user)
    };
    match user {
        Some(user) if !user.disabled => Ok(user),
        Some(_) => Err(ResolveError::Disabled),
        None => Err(ResolveError::NotLinked),
    }
}

// ---------------------------------------------------------------------------
// OIDC
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

struct CachedMetadata {
    discovery: Discovery,
    jwks: JwkSet,
    fetched: Instant,
}

/// Process-wide cache of discovery documents and JWKS per issuer.
#[derive(Default)]
pub struct OidcCache {
    entries: Mutex<HashMap<String, std::sync::Arc<CachedMetadata>>>,
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap_or_default()
}

async fn fetch_metadata(issuer: &str) -> Result<CachedMetadata, String> {
    let client = http_client();
    let url = format!(
        "{}/.well-known/openid-configuration",
        issuer.trim_end_matches('/')
    );
    let discovery: Discovery = client
        .get(&url)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|_| "discovery_unavailable")?
        .json()
        .await
        .map_err(|_| "discovery_invalid")?;
    // The issuer in the document must be exactly the configured issuer.
    if discovery.issuer.trim_end_matches('/') != issuer.trim_end_matches('/') {
        return Err("issuer_mismatch".into());
    }
    let jwks: JwkSet = client
        .get(&discovery.jwks_uri)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|_| "jwks_unavailable")?
        .json()
        .await
        .map_err(|_| "jwks_invalid")?;
    Ok(CachedMetadata {
        discovery,
        jwks,
        fetched: Instant::now(),
    })
}

impl OidcCache {
    async fn get(
        &self,
        issuer: &str,
        refresh: bool,
    ) -> Result<std::sync::Arc<CachedMetadata>, String> {
        if !refresh {
            if let Some(entry) = self
                .entries
                .lock()
                .ok()
                .and_then(|map| map.get(issuer).cloned())
                .filter(|entry| entry.fetched.elapsed() < METADATA_TTL)
            {
                return Ok(entry);
            }
        }
        let entry = std::sync::Arc::new(fetch_metadata(issuer).await?);
        if let Ok(mut map) = self.entries.lock() {
            map.insert(issuer.to_owned(), entry.clone());
        }
        Ok(entry)
    }
}

fn random_token() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64url(&bytes)
}

fn base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = match chunk.len() {
            3 => u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8 | u32::from(chunk[2]),
            2 => u32::from(chunk[0]) << 16 | u32::from(chunk[1]) << 8,
            _ => u32::from(chunk[0]) << 16,
        };
        let symbols = chunk.len() + 1;
        for i in 0..symbols {
            out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
        }
    }
    out
}

fn callback_url(base: &str, slug: &str) -> String {
    format!(
        "{}/api/auth/sso/{slug}/callback",
        base.trim_end_matches('/')
    )
}

/// Asymmetric algorithms accepted for ID tokens. Symmetric (HS*) and `none`
/// are rejected so a token cannot be forged with public information.
const ID_TOKEN_ALGORITHMS: [Algorithm; 9] = [
    Algorithm::RS256,
    Algorithm::RS384,
    Algorithm::RS512,
    Algorithm::PS256,
    Algorithm::PS384,
    Algorithm::PS512,
    Algorithm::ES256,
    Algorithm::ES384,
    Algorithm::EdDSA,
];

#[derive(Debug, Deserialize)]
struct IdTokenClaims {
    sub: String,
    nonce: Option<String>,
    azp: Option<String>,
    /// Already validated against the client id; only its arity matters here.
    #[serde(default)]
    aud: serde_json::Value,
    email: Option<String>,
    #[serde(default)]
    email_verified: EmailVerified,
}

/// Some providers send `email_verified` as the string `"true"`.
#[derive(Debug, Default, Deserialize)]
#[serde(untagged)]
enum EmailVerified {
    Bool(bool),
    Text(String),
    #[default]
    Missing,
}

impl EmailVerified {
    fn is_true(&self) -> bool {
        match self {
            Self::Bool(value) => *value,
            Self::Text(value) => value.eq_ignore_ascii_case("true"),
            Self::Missing => false,
        }
    }
}

fn verify_id_token(
    token: &str,
    jwks: &JwkSet,
    issuer: &str,
    client_id: &str,
    nonce: &str,
) -> Result<AssertedIdentity, &'static str> {
    let header = jsonwebtoken::decode_header(token).map_err(|_| "id_token_malformed")?;
    if !ID_TOKEN_ALGORITHMS.contains(&header.alg) {
        return Err("id_token_algorithm");
    }
    let jwk = match header.kid.as_deref() {
        Some(kid) => jwks.find(kid),
        None if jwks.keys.len() == 1 => jwks.keys.first(),
        None => None,
    }
    .ok_or("id_token_unknown_key")?;
    let key = DecodingKey::from_jwk(jwk).map_err(|_| "id_token_key")?;
    let mut validation = Validation::new(header.alg);
    validation.set_issuer(&[issuer, issuer.trim_end_matches('/')]);
    validation.set_audience(&[client_id]);
    validation.set_required_spec_claims(&["exp", "iat", "iss", "aud", "sub"]);
    validation.leeway = 60;
    let claims = jsonwebtoken::decode::<IdTokenClaims>(token, &key, &validation)
        .map_err(|_| "id_token_invalid")?
        .claims;
    if claims.nonce.as_deref() != Some(nonce) {
        return Err("id_token_nonce");
    }
    let audiences = claims.aud.as_array().map_or(1, Vec::len);
    if audiences > 1 && claims.azp.as_deref() != Some(client_id) {
        return Err("id_token_azp");
    }
    Ok(AssertedIdentity {
        subject: claims.sub,
        email: claims.email,
        email_verified: claims.email_verified.is_true(),
    })
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

// ---------------------------------------------------------------------------
// HTTP handlers
// ---------------------------------------------------------------------------

fn error(status: StatusCode, code: &str, message: &str) -> Response {
    (
        status,
        Json(ErrorEnvelope {
            code: code.into(),
            message: message.into(),
        }),
    )
        .into_response()
}

/// Redirect back to the login page with a stable, non-sensitive reason.
pub(crate) fn login_failure(reason: &str) -> Response {
    let mut response = Redirect::to(&format!("/login?sso_error={reason}")).into_response();
    clear_state_cookie(response.headers_mut());
    response
}

fn clear_state_cookie(headers: &mut HeaderMap) {
    if let Ok(value) = HeaderValue::from_str(&format!(
        "{STATE_COOKIE}=; HttpOnly; Secure; SameSite=Lax; Path=/api/auth/sso; Max-Age=0"
    )) {
        headers.append(header::SET_COOKIE, value);
    }
}

pub(crate) fn state_cookie(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|v| v.trim().strip_prefix(&format!("{STATE_COOKIE}=")))
}

pub(crate) fn with_state_cookie(mut response: Response, key: &str, same_site: &str) -> Response {
    if let Ok(value) = HeaderValue::from_str(&format!(
        "{STATE_COOKIE}={key}; HttpOnly; Secure; SameSite={same_site}; Path=/api/auth/sso; Max-Age={STATE_TTL_SECONDS}"
    )) {
        response.headers_mut().append(header::SET_COOKIE, value);
    }
    response
}

/// Finish a login: resolve the user, issue a session, and go to the app.
pub(crate) async fn complete_login(
    state: &AppState,
    provider: &SsoProvider,
    policy: &AccountPolicy,
    identity: AssertedIdentity,
) -> Response {
    let user = match resolve_user(state, provider, policy, &identity).await {
        Ok(user) => user,
        Err(error) => {
            let reason = match error {
                ResolveError::DomainNotAllowed => "domain_not_allowed",
                ResolveError::NotLinked => "account_not_linked",
                ResolveError::Disabled => "account_disabled",
                ResolveError::Database => "unavailable",
            };
            audit::record_state(
                state,
                None,
                "sso_login_denied",
                &serde_json::json!({ "provider": provider.slug, "reason": reason }).to_string(),
            )
            .await;
            return login_failure(reason);
        }
    };
    let detail = serde_json::json!({ "method": "sso", "provider": provider.slug }).to_string();
    let Some(mut headers) = auth::issue_session(state, &user, &detail).await else {
        return login_failure("unavailable");
    };
    clear_state_cookie(&mut headers);
    (headers, Redirect::to("/")).into_response()
}

pub async fn public_providers(State(state): State<AppState>) -> Response {
    match list_providers(&state).await {
        Ok(providers) => Json(
            providers
                .into_iter()
                .filter(|p| p.enabled && p.account_policy().is_some())
                .map(|p| PublicProvider {
                    slug: p.slug,
                    name: p.name,
                    kind: p.kind,
                })
                .collect::<Vec<_>>(),
        )
        .into_response(),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

async fn enabled_provider(state: &AppState, slug: &str) -> Result<SsoProvider, Response> {
    match provider_by_slug(state, slug).await {
        Ok(Some(provider)) if provider.enabled => Ok(provider),
        Ok(_) => Err(login_failure("unknown_provider")),
        Err(_) => Err(login_failure("unavailable")),
    }
}

/// `GET /api/auth/sso/{slug}/start`: redirect the browser to the provider.
pub async fn start(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Response {
    let key = headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown");
    // A separate budget from password logins: starting SSO must not lock a
    // user out of password login, nor the reverse.
    if !crate::control_plane::allow_auth_attempt(&state, &format!("sso:{key}")).await {
        return login_failure("rate_limited");
    }
    let provider = match enabled_provider(&state, &slug).await {
        Ok(provider) => provider,
        Err(response) => return response,
    };
    match provider.kind {
        ProviderKind::Oidc => oidc_start(&state, &provider).await,
        #[cfg(feature = "saml")]
        ProviderKind::Saml => super::sso_saml::start(&state, &provider).await,
        #[cfg(not(feature = "saml"))]
        ProviderKind::Saml => login_failure("saml_unavailable"),
    }
}

async fn oidc_start(state: &AppState, provider: &SsoProvider) -> Response {
    let Ok(config) = serde_json::from_value::<OidcConfig>(provider.config.clone()) else {
        return login_failure("provider_misconfigured");
    };
    let metadata = match state.oidc.get(&config.issuer, false).await {
        Ok(metadata) => metadata,
        Err(reason) => {
            tracing::warn!(event = "sso_discovery_failed", provider = %provider.slug, reason = %reason);
            return login_failure("provider_unavailable");
        }
    };
    let key = random_token();
    let nonce = random_token();
    let verifier = random_token();
    if store_login_state(state, provider.id, &key, &nonce, &verifier)
        .await
        .is_err()
    {
        return login_failure("unavailable");
    }
    let challenge = base64url(&Sha256::digest(verifier.as_bytes()));
    let query = serde_urlencoded::to_string([
        ("response_type", "code"),
        ("client_id", config.client_id.as_str()),
        (
            "redirect_uri",
            &callback_url(&config.redirect_base_url, &provider.slug),
        ),
        ("scope", &config.scopes.join(" ")),
        ("state", key.as_str()),
        ("nonce", nonce.as_str()),
        ("code_challenge", challenge.as_str()),
        ("code_challenge_method", "S256"),
    ])
    .unwrap_or_default();
    let separator = if metadata.discovery.authorization_endpoint.contains('?') {
        '&'
    } else {
        '?'
    };
    with_state_cookie(
        Redirect::to(&format!(
            "{}{separator}{query}",
            metadata.discovery.authorization_endpoint
        ))
        .into_response(),
        &key,
        "Lax",
    )
}

/// `GET /api/auth/sso/{slug}/callback`: OIDC redirect target.
pub async fn oidc_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    RawQuery(raw): RawQuery,
) -> Response {
    let provider = match enabled_provider(&state, &slug).await {
        Ok(provider) if provider.kind == ProviderKind::Oidc => provider,
        Ok(_) => return login_failure("unknown_provider"),
        Err(response) => return response,
    };
    let params: HashMap<String, String> = raw
        .as_deref()
        .and_then(|raw| serde_urlencoded::from_str(raw).ok())
        .unwrap_or_default();
    if params.contains_key("error") {
        return login_failure("provider_denied");
    }
    let (Some(code), Some(key)) = (params.get("code"), params.get("state")) else {
        return login_failure("invalid_callback");
    };
    // The state must come back to the same browser that started the login.
    let cookie_ok = state_cookie(&headers)
        .is_some_and(|cookie| crate::cluster::constant_time_eq(cookie.as_bytes(), key.as_bytes()));
    if !cookie_ok {
        return login_failure("state_mismatch");
    }
    let Ok(Some((nonce, verifier))) = take_login_state(&state, provider.id, key).await else {
        return login_failure("state_expired");
    };
    let Ok(config) = serde_json::from_value::<OidcConfig>(provider.config.clone()) else {
        return login_failure("provider_misconfigured");
    };
    let identity = match oidc_exchange(&state, &provider, &config, code, &verifier, &nonce).await {
        Ok(identity) => identity,
        Err(reason) => {
            audit::record_state(
                &state,
                None,
                "sso_login_denied",
                &serde_json::json!({ "provider": provider.slug, "reason": reason }).to_string(),
            )
            .await;
            return login_failure("token_rejected");
        }
    };
    complete_login(&state, &provider, &config.account, identity).await
}

async fn oidc_exchange(
    state: &AppState,
    provider: &SsoProvider,
    config: &OidcConfig,
    code: &str,
    verifier: &str,
    nonce: &str,
) -> Result<AssertedIdentity, &'static str> {
    let metadata = state
        .oidc
        .get(&config.issuer, false)
        .await
        .map_err(|_| "provider_unavailable")?;
    let secret = state
        .secrets
        .get(&secret_name(&provider.slug))
        .ok()
        .flatten()
        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned());
    let redirect_uri = callback_url(&config.redirect_base_url, &provider.slug);
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", redirect_uri.as_str()),
        ("code_verifier", verifier),
        ("client_id", config.client_id.as_str()),
    ];
    if let Some(secret) = secret.as_deref() {
        form.push(("client_secret", secret));
    }
    let response: TokenResponse = http_client()
        .post(&metadata.discovery.token_endpoint)
        .header(header::ACCEPT, "application/json")
        .form(&form)
        .send()
        .await
        .and_then(reqwest::Response::error_for_status)
        .map_err(|_| "token_exchange_failed")?
        .json()
        .await
        .map_err(|_| "token_response_invalid")?;
    match verify_id_token(
        &response.id_token,
        &metadata.jwks,
        &config.issuer,
        &config.client_id,
        nonce,
    ) {
        // Keys may have rotated since the JWKS was cached; retry once.
        Err("id_token_unknown_key") => {
            let refreshed = state
                .oidc
                .get(&config.issuer, true)
                .await
                .map_err(|_| "provider_unavailable")?;
            verify_id_token(
                &response.id_token,
                &refreshed.jwks,
                &config.issuer,
                &config.client_id,
                nonce,
            )
        }
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Administration
// ---------------------------------------------------------------------------

async fn require_settings_admin(state: &AppState, headers: &HeaderMap) -> Result<User, Response> {
    let user = crate::control_plane::current_user(state, headers)
        .await
        .map_err(|status| error(status, "unauthorized", "Authentication required"))?;
    if !authorize(
        &state.db,
        &user,
        Permission::SystemSettingsManage,
        ResourceContext::GLOBAL,
    )
    .await
    .unwrap_or(false)
    {
        return Err(error(
            StatusCode::FORBIDDEN,
            "forbidden",
            "Administrator access required",
        ));
    }
    Ok(user)
}

fn valid_slug(slug: &str) -> bool {
    !slug.is_empty()
        && slug.len() <= 64
        && slug
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

async fn validate_input(state: &AppState, input: &ProviderInput) -> Result<(), &'static str> {
    if !valid_slug(&input.slug) || input.name.trim().is_empty() || input.name.len() > 128 {
        return Err("Invalid slug or name");
    }
    let account = match input.kind {
        ProviderKind::Oidc => {
            let config = serde_json::from_value::<OidcConfig>(input.config.clone())
                .map_err(|_| "Invalid OIDC configuration")?;
            let https = |url: &str| {
                url.starts_with("https://")
                    || url.starts_with("http://localhost")
                    || url.starts_with("http://127.0.0.1")
            };
            if !https(&config.issuer)
                || !https(&config.redirect_base_url)
                || config.client_id.trim().is_empty()
                || !config.scopes.iter().any(|s| s == "openid")
            {
                return Err(
                    "OIDC issuer and redirect base must be HTTPS and scopes must include openid",
                );
            }
            config.account
        }
        #[cfg(feature = "saml")]
        ProviderKind::Saml => super::sso_saml::validate_config(&input.config)?,
        #[cfg(not(feature = "saml"))]
        ProviderKind::Saml => return Err("SAML support is not compiled into this build"),
    };
    if account.auto_provision
        && repository::role_by_slug(&state.db, &account.default_role)
            .await
            .ok()
            .flatten()
            .is_none()
    {
        return Err("Default role does not exist");
    }
    Ok(())
}

pub async fn admin_list(State(state): State<AppState>, headers: HeaderMap) -> Response {
    if let Err(response) = require_settings_admin(&state, &headers).await {
        return response;
    }
    match list_providers(&state).await {
        Ok(providers) => Json(providers).into_response(),
        Err(_) => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

/// `PUT /api/sso/providers/{slug}`: create or replace a provider.
pub async fn admin_upsert(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    input: Result<Json<ProviderInput>, axum::extract::rejection::JsonRejection>,
) -> Response {
    let actor = match require_settings_admin(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(Json(input)) = input else {
        return error(StatusCode::BAD_REQUEST, "invalid_input", "Invalid provider");
    };
    if input.slug != slug {
        return error(StatusCode::BAD_REQUEST, "invalid_input", "Slug mismatch");
    }
    if let Err(message) = validate_input(&state, &input).await {
        return error(StatusCode::BAD_REQUEST, "invalid_input", message);
    }
    if let Some(secret) = input.client_secret.as_deref() {
        if state
            .secrets
            .put(&secret_name(&slug), secret.as_bytes())
            .is_err()
        {
            return error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "secret_store_error",
                "Unable to store client secret",
            );
        }
    }
    let now = chrono::Utc::now().to_rfc3339();
    let config = input.config.to_string();
    let enabled = i64::from(input.enabled);
    let updated = sqlx::query(
        "UPDATE sso_providers SET kind=?,name=?,enabled=?,config=?,updated_at=? WHERE slug=?",
    )
    .bind(input.kind.as_str())
    .bind(input.name.trim())
    .bind(enabled)
    .bind(&config)
    .bind(&now)
    .bind(&slug)
    .execute(&state.db)
    .await;
    let result = match updated {
        Ok(done) if done.rows_affected() > 0 => Ok(()),
        Ok(_) => sqlx::query(
            "INSERT INTO sso_providers(id,slug,kind,name,enabled,config,created_at,updated_at)
             VALUES(?,?,?,?,?,?,?,?)",
        )
        .bind(repository::generated_id())
        .bind(&slug)
        .bind(input.kind.as_str())
        .bind(input.name.trim())
        .bind(enabled)
        .bind(&config)
        .bind(&now)
        .bind(&now)
        .execute(&state.db)
        .await
        .map(|_| ()),
        Err(error) => Err(error),
    };
    if result.is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        );
    }
    audit::record_state(
        &state,
        Some(actor.id),
        "sso_provider_saved",
        &serde_json::json!({ "provider": slug, "kind": input.kind.as_str(), "enabled": input.enabled })
            .to_string(),
    )
    .await;
    match provider_by_slug(&state, &slug).await {
        Ok(Some(provider)) => Json(provider).into_response(),
        _ => error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        ),
    }
}

pub async fn admin_delete(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
) -> Response {
    let actor = match require_settings_admin(&state, &headers).await {
        Ok(user) => user,
        Err(response) => return response,
    };
    let Ok(Some(provider)) = provider_by_slug(&state, &slug).await else {
        return error(StatusCode::NOT_FOUND, "not_found", "Provider not found");
    };
    let deleted = async {
        sqlx::query("DELETE FROM sso_identities WHERE provider_id=?")
            .bind(provider.id)
            .execute(&state.db)
            .await?;
        sqlx::query("DELETE FROM sso_login_states WHERE provider_id=?")
            .bind(provider.id)
            .execute(&state.db)
            .await?;
        sqlx::query("DELETE FROM sso_providers WHERE id=?")
            .bind(provider.id)
            .execute(&state.db)
            .await
    }
    .await;
    if deleted.is_err() {
        return error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "database_error",
            "Database unavailable",
        );
    }
    let _ = state.secrets.delete(&secret_name(&slug));
    audit::record_state(
        &state,
        Some(actor.id),
        "sso_provider_deleted",
        &serde_json::json!({ "provider": slug }).to_string(),
    )
    .await;
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64url_matches_rfc4648_vectors() {
        for (input, expected) in [
            ("", ""),
            ("f", "Zg"),
            ("fo", "Zm8"),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg"),
            ("fooba", "Zm9vYmE"),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64url(input.as_bytes()), expected);
        }
        // S256 challenge, cross-checked with Python's urlsafe_b64encode.
        assert_eq!(
            base64url(&Sha256::digest(
                b"dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWEOEjXk"
            )),
            "TP3DZQl9rJnri9eRuZaFS6Q7czCrth7sEZC00LreApo"
        );
    }
}
