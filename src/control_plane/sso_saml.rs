//! SAML 2.0 service provider (SP-initiated, HTTP-Redirect request,
//! HTTP-POST response). Signature verification uses libxmlsec1 through
//! `samael`; a provider is only accepted when its IdP metadata carries a
//! signing certificate, because without one `samael` skips verification.
//!
//! The AuthnRequest id is a fresh 256-bit token stored as a single-use login
//! state and in a `SameSite=None` cookie (the IdP returns by cross-site
//! POST). The response must be `InResponseTo` that id, so a response cannot
//! be replayed or injected into another browser's login.

use super::sso::{
    complete_login, login_failure, state_cookie, store_login_state, take_login_state,
    with_state_cookie, AccountPolicy, AssertedIdentity, ProviderKind, SsoProvider,
};
use crate::control_plane::{audit, AppState};
use axum::{
    extract::{Form, Path, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Redirect, Response},
};
use samael::crypto::AllowedSignatureAlgorithm;
use samael::metadata::{EntityDescriptor, HTTP_REDIRECT_BINDING};
use samael::service_provider::{ServiceProvider, ServiceProviderBuilder};
use samael::traits::ToXml;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const EMAIL_NAME_ID_FORMAT: &str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SamlConfig {
    /// The IdP's metadata XML (EntityDescriptor) including its signing
    /// certificate and SSO endpoint.
    pub idp_metadata_xml: String,
    /// Public base URL of this dashboard; the ACS is
    /// `<base>/api/auth/sso/<slug>/acs`.
    pub redirect_base_url: String,
    /// SP entity id; defaults to `<base>/api/auth/sso/<slug>/metadata`.
    #[serde(default)]
    pub sp_entity_id: Option<String>,
    /// Attribute carrying the email; when unset an emailAddress-format
    /// NameID is used.
    #[serde(default)]
    pub email_attribute: Option<String>,
    /// SAML has no `email_verified`; set when the IdP only asserts emails it
    /// has verified, to allow email linking and provisioning.
    #[serde(default)]
    pub trust_email: bool,
    #[serde(flatten)]
    pub account: AccountPolicy,
}

fn base(config: &SamlConfig) -> &str {
    config.redirect_base_url.trim_end_matches('/')
}

fn acs_url(config: &SamlConfig, slug: &str) -> String {
    format!("{}/api/auth/sso/{slug}/acs", base(config))
}

fn entity_id(config: &SamlConfig, slug: &str) -> String {
    config
        .sp_entity_id
        .clone()
        .unwrap_or_else(|| format!("{}/api/auth/sso/{slug}/metadata", base(config)))
}

/// Algorithms accepted on IdP signatures; SHA-1 and DSA are excluded.
fn allowed_algorithms() -> Vec<AllowedSignatureAlgorithm> {
    vec![
        AllowedSignatureAlgorithm::RsaSha256,
        AllowedSignatureAlgorithm::RsaSha384,
        AllowedSignatureAlgorithm::RsaSha512,
        AllowedSignatureAlgorithm::EcdsaSha256,
        AllowedSignatureAlgorithm::EcdsaSha384,
        AllowedSignatureAlgorithm::EcdsaSha512,
    ]
}

fn service_provider(config: &SamlConfig, slug: &str) -> Result<ServiceProvider, &'static str> {
    let idp: EntityDescriptor = config
        .idp_metadata_xml
        .parse()
        .map_err(|_| "Invalid IdP metadata XML")?;
    let sp = ServiceProviderBuilder::default()
        .entity_id(entity_id(config, slug))
        .acs_url(acs_url(config, slug))
        .metadata_url(format!("{}/api/auth/sso/{slug}/metadata", base(config)))
        .idp_metadata(idp)
        .allowed_signature_algorithms(allowed_algorithms())
        .allow_idp_initiated(false)
        .build()
        .map_err(|_| "Invalid SAML configuration")?;
    // Without a signing certificate samael would accept unsigned responses.
    match sp.idp_signing_certs() {
        Ok(Some(certs)) if !certs.is_empty() => {}
        _ => return Err("IdP metadata must include a signing certificate"),
    }
    if sp.sso_binding_location(HTTP_REDIRECT_BINDING).is_none() {
        return Err("IdP metadata must include an HTTP-Redirect SSO endpoint");
    }
    Ok(sp)
}

/// Validate an admin-supplied SAML configuration and return its account
/// policy.
pub fn validate_config(value: &serde_json::Value) -> Result<AccountPolicy, &'static str> {
    let config: SamlConfig =
        serde_json::from_value(value.clone()).map_err(|_| "Invalid SAML configuration")?;
    let https = |url: &str| {
        url.starts_with("https://")
            || url.starts_with("http://localhost")
            || url.starts_with("http://127.0.0.1")
    };
    if !https(&config.redirect_base_url) {
        return Err("SAML redirect base must be HTTPS");
    }
    service_provider(&config, "validation")?;
    Ok(config.account)
}

fn config_of(provider: &SsoProvider) -> Option<SamlConfig> {
    (provider.kind == ProviderKind::Saml)
        .then(|| serde_json::from_value(provider.config.clone()).ok())
        .flatten()
}

fn request_id() -> String {
    use rand::RngCore;
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    // XML IDs must not start with a digit.
    format!("_{}", hex::encode(bytes))
}

/// Begin an SP-initiated login by redirecting to the IdP.
pub async fn start(state: &AppState, provider: &SsoProvider) -> Response {
    let Some(config) = config_of(provider) else {
        return login_failure("provider_misconfigured");
    };
    let Ok(sp) = service_provider(&config, &provider.slug) else {
        return login_failure("provider_misconfigured");
    };
    let Some(destination) = sp.sso_binding_location(HTTP_REDIRECT_BINDING) else {
        return login_failure("provider_misconfigured");
    };
    let Ok(mut request) = sp.make_authentication_request(&destination) else {
        return login_failure("provider_misconfigured");
    };
    let id = request_id();
    request.id = id.clone();
    let Ok(Some(url)) = request.redirect("") else {
        return login_failure("provider_misconfigured");
    };
    if store_login_state(state, provider.id, &id, "", "")
        .await
        .is_err()
    {
        return login_failure("unavailable");
    }
    // The IdP returns with a cross-site POST, which only carries
    // SameSite=None cookies.
    with_state_cookie(Redirect::to(url.as_str()).into_response(), &id, "None")
}

/// `POST /api/auth/sso/{slug}/acs`: assertion consumer service.
pub async fn acs(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(slug): Path<String>,
    Form(form): Form<HashMap<String, String>>,
) -> Response {
    let provider = match super::sso::provider_by_slug(&state, &slug).await {
        Ok(Some(provider)) if provider.enabled && provider.kind == ProviderKind::Saml => provider,
        Ok(_) => return login_failure("unknown_provider"),
        Err(_) => return login_failure("unavailable"),
    };
    let Some(config) = config_of(&provider) else {
        return login_failure("provider_misconfigured");
    };
    let Some(encoded) = form.get("SAMLResponse") else {
        return login_failure("invalid_callback");
    };
    let Some(request_id) = state_cookie(&headers).map(str::to_owned) else {
        return login_failure("state_mismatch");
    };
    let Ok(Some(_)) = take_login_state(&state, provider.id, &request_id).await else {
        return login_failure("state_expired");
    };
    // samael's XML types are not Send, so verification runs synchronously and
    // only the extracted identity crosses the next await.
    let identity = match verify_response(&config, &provider.slug, encoded, &request_id) {
        Ok(identity) => identity,
        Err(reason) => {
            tracing::info!(event = "saml_response_rejected", provider = %provider.slug, reason = %reason);
            audit::record_state(
                &state,
                None,
                "sso_login_denied",
                &serde_json::json!({ "provider": provider.slug, "reason": "assertion_rejected" })
                    .to_string(),
            )
            .await;
            return login_failure("token_rejected");
        }
    };
    complete_login(&state, &provider, &config.account, identity).await
}

/// Verify a base64 SAMLResponse issued for `request_id` and extract the
/// asserted identity.
pub fn verify_response(
    config: &SamlConfig,
    slug: &str,
    encoded: &str,
    request_id: &str,
) -> Result<AssertedIdentity, String> {
    let sp = service_provider(config, slug).map_err(str::to_owned)?;
    let assertion = sp
        .parse_base64_response(encoded, Some(&[request_id]))
        .map_err(|error| error.to_string())?;
    let name_id = assertion
        .subject
        .as_ref()
        .and_then(|s| s.name_id.as_ref())
        .ok_or("missing NameID")?;
    let email = match config.email_attribute.as_deref() {
        Some(wanted) => assertion
            .attribute_statements
            .iter()
            .flatten()
            .flat_map(|statement| &statement.attributes)
            .find(|attribute| {
                attribute.name.as_deref() == Some(wanted)
                    || attribute.friendly_name.as_deref() == Some(wanted)
            })
            .and_then(|attribute| attribute.values.first())
            .and_then(|value| value.value.clone()),
        None => {
            (name_id.format.as_deref() == Some(EMAIL_NAME_ID_FORMAT)).then(|| name_id.value.clone())
        }
    };
    Ok(AssertedIdentity {
        subject: name_id.value.clone(),
        email,
        email_verified: config.trust_email,
    })
}

/// `GET /api/auth/sso/{slug}/metadata`: SP metadata for IdP registration.
pub async fn metadata(State(state): State<AppState>, Path(slug): Path<String>) -> Response {
    let provider = match super::sso::provider_by_slug(&state, &slug).await {
        Ok(Some(provider)) if provider.kind == ProviderKind::Saml => provider,
        _ => return StatusCode::NOT_FOUND.into_response(),
    };
    let Some(config) = config_of(&provider) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let xml = service_provider(&config, &slug)
        .ok()
        .and_then(|sp| sp.metadata().ok())
        .and_then(|descriptor| descriptor.to_string().ok());
    match xml {
        Some(xml) => (
            [(header::CONTENT_TYPE, "application/samlmetadata+xml")],
            xml,
        )
            .into_response(),
        None => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
