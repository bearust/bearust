//! SAML single sign-on with responses signed by an in-test identity provider.
#![cfg(feature = "saml")]

use axum::{
    body::{to_bytes, Body},
    http::{Request, StatusCode},
    Router,
};
use bearust::control_plane::sso_saml::{validate_config, verify_response, SamlConfig};
use bearust::control_plane::{build_state, router};
use samael::crypto::{Crypto, CryptoProvider};
use samael::idp::response_builder::{build_response_template, ResponseAttribute};
use samael::idp::sp_extractor::RequiredAttribute;
use samael::idp::{CertificateParams, IdentityProvider, KeyType, Rsa};
use samael::signature::DigestAlgorithm;
use samael::traits::ToXml;
use serde_json::{json, Value};
use std::collections::HashMap;
use tower::util::ServiceExt;

const IDP_ENTITY: &str = "https://idp.example.test";
const BASE: &str = "https://bearust.example.com";

fn base64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let mut n = 0u32;
        for (i, b) in chunk.iter().enumerate() {
            n |= u32::from(*b) << (16 - 8 * i);
        }
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(A[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

struct TestIdp {
    idp: IdentityProvider,
    cert: samael::crypto::CertificateDer,
}

impl TestIdp {
    fn new() -> Self {
        let idp = IdentityProvider::generate_new(KeyType::Rsa(Rsa::Rsa2048)).unwrap();
        let cert = idp
            .create_certificate(&CertificateParams {
                common_name: "idp.example.test",
                issuer_name: "idp.example.test",
                days_until_expiration: 30,
            })
            .unwrap();
        Self { idp, cert }
    }

    fn metadata(&self, with_cert: bool) -> String {
        let key = if with_cert {
            format!(
                r#"<md:KeyDescriptor use="signing"><ds:KeyInfo xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:X509Data><ds:X509Certificate>{}</ds:X509Certificate></ds:X509Data></ds:KeyInfo></md:KeyDescriptor>"#,
                base64(self.cert.der_data())
            )
        } else {
            String::new()
        };
        format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{IDP_ENTITY}"><md:IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">{key}<md:SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="{IDP_ENTITY}/sso"/></md:IDPSSODescriptor></md:EntityDescriptor>"#
        )
    }

    /// Signed response XML for `request_id`. samael's own IdP signer uses a
    /// SHA-1 digest, which Bearust rejects, so the template is re-signed
    /// with SHA-256.
    fn response_xml(&self, slug: &str, request_id: &str, name_id: &str, email: &str) -> String {
        let attribute = ResponseAttribute {
            required_attribute: RequiredAttribute {
                name: "email".into(),
                format: Some("urn:oasis:names:tc:SAML:2.0:attrname-format:basic".into()),
            },
            value: email,
        };
        let mut response = build_response_template(
            &self.cert,
            name_id,
            &format!("{BASE}/api/auth/sso/{slug}/metadata"),
            IDP_ENTITY,
            &format!("{BASE}/api/auth/sso/{slug}/acs"),
            request_id,
            &[attribute],
        );
        // Bearer confirmations must carry an expiry.
        let assertion = response.assertion.as_mut().unwrap();
        for confirmation in assertion
            .subject
            .as_mut()
            .unwrap()
            .subject_confirmations
            .as_mut()
            .unwrap()
        {
            confirmation
                .subject_confirmation_data
                .as_mut()
                .unwrap()
                .not_on_or_after = Some(chrono::Utc::now() + chrono::Duration::minutes(5));
        }
        for reference in &mut response.signature.as_mut().unwrap().signed_info.reference {
            reference.digest_method.algorithm = DigestAlgorithm::Sha256;
        }
        Crypto::sign_xml(
            response.to_string().unwrap(),
            &self.idp.export_private_key_der().unwrap(),
        )
        .unwrap()
    }

    /// A signed, base64-encoded SAMLResponse for `request_id`.
    fn response(&self, slug: &str, request_id: &str, name_id: &str, email: &str) -> String {
        base64(
            self.response_xml(slug, request_id, name_id, email)
                .as_bytes(),
        )
    }
}

fn config(idp: &TestIdp) -> Value {
    json!({
        "idp_metadata_xml": idp.metadata(true),
        "redirect_base_url": BASE,
        "email_attribute": "email",
        "trust_email": true,
        "default_role": "viewer",
        "auto_provision": true
    })
}

#[test]
fn verify_response_accepts_only_signed_responses_for_the_request() {
    let idp = TestIdp::new();
    let config: SamlConfig = serde_json::from_value(config(&idp)).unwrap();
    let ok = idp.response("corp", "_req1", "alice-id", "alice@example.com");
    let identity = verify_response(&config, "corp", &ok, "_req1").unwrap();
    assert_eq!(identity.subject, "alice-id");
    assert_eq!(identity.email.as_deref(), Some("alice@example.com"));
    assert!(identity.email_verified);

    // Issued for another request.
    assert!(verify_response(&config, "corp", &ok, "_other").is_err());
    // Issued for another SP (audience/recipient).
    let other_sp = idp.response("other", "_req1", "alice-id", "alice@example.com");
    assert!(verify_response(&config, "corp", &other_sp, "_req1").is_err());
    // Signed by a key the metadata does not trust.
    let rogue = TestIdp::new().response("corp", "_req1", "alice-id", "alice@example.com");
    assert!(verify_response(&config, "corp", &rogue, "_req1").is_err());
    // Altered after signing.
    let altered = idp
        .response_xml("corp", "_req1", "alice-id", "alice@example.com")
        .replace("alice-id", "admin-id");
    assert!(verify_response(&config, "corp", &base64(altered.as_bytes()), "_req1").is_err());
    // samael's stock signer (SHA-1 digest) is refused by the algorithm policy.
    let sha1 = idp
        .idp
        .sign_authn_response(
            &idp.cert,
            "alice-id",
            &format!("{BASE}/api/auth/sso/corp/metadata"),
            &format!("{BASE}/api/auth/sso/corp/acs"),
            IDP_ENTITY,
            "_req1",
            &[],
        )
        .unwrap()
        .to_string()
        .unwrap();
    assert!(verify_response(&config, "corp", &base64(sha1.as_bytes()), "_req1").is_err());

    // Metadata without a signing certificate is refused outright.
    let mut unsigned = config.clone();
    unsigned.idp_metadata_xml = idp.metadata(false);
    assert!(validate_config(&serde_json::to_value(unsigned).unwrap()).is_err());
}

async fn call(
    app: &Router,
    method: &str,
    uri: &str,
    cookie: Option<&str>,
    body: Body,
    content_type: &str,
) -> (StatusCode, HashMap<String, Vec<String>>, String) {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .header("content-type", content_type);
    if let Some(cookie) = cookie {
        req = req.header("cookie", cookie);
    }
    let response = app.clone().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = response.status();
    let mut headers: HashMap<String, Vec<String>> = HashMap::new();
    for (name, value) in response.headers() {
        headers
            .entry(name.as_str().to_owned())
            .or_default()
            .push(value.to_str().unwrap().to_owned());
    }
    let body = to_bytes(response.into_body(), 1 << 20).await.unwrap();
    (status, headers, String::from_utf8_lossy(&body).into_owned())
}

fn cookie_value(headers: &HashMap<String, Vec<String>>, name: &str) -> Option<String> {
    headers.get("set-cookie")?.iter().find_map(|c| {
        c.split(';')
            .next()?
            .strip_prefix(&format!("{name}="))
            .filter(|v| !v.is_empty())
            .map(str::to_owned)
    })
}

#[tokio::test]
async fn saml_login_round_trip_issues_a_session_once() {
    let idp = TestIdp::new();
    let dir = tempfile::tempdir().unwrap();
    let app = router(
        build_state("sqlite::memory:", dir.path(), "setup-token")
            .await
            .unwrap(),
    );
    let json_body = |v: Value| Body::from(v.to_string());
    call(&app, "POST", "/api/setup/initialize", None, json_body(json!({
        "email": "admin@example.com", "password": "correct horse battery", "setup_token": "setup-token"
    })), "application/json").await;
    let (_, headers, _) = call(
        &app,
        "POST",
        "/api/auth/login",
        None,
        json_body(json!({
            "email": "admin@example.com", "password": "correct horse battery"
        })),
        "application/json",
    )
    .await;
    let admin = format!(
        "bearust_session={}",
        cookie_value(&headers, "bearust_session").unwrap()
    );
    let (status, _, body) = call(
        &app,
        "PUT",
        "/api/sso/providers/corp",
        Some(&admin),
        json_body(json!({
            "slug": "corp", "kind": "saml", "name": "Corp SAML", "config": config(&idp)
        })),
        "application/json",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, _, metadata) = call(
        &app,
        "GET",
        "/api/auth/sso/corp/metadata",
        None,
        Body::empty(),
        "text/plain",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(metadata.contains(&format!("{BASE}/api/auth/sso/corp/acs")));

    let (status, headers, _) = call(
        &app,
        "GET",
        "/api/auth/sso/corp/start",
        None,
        Body::empty(),
        "text/plain",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(headers["location"][0].starts_with(&format!("{IDP_ENTITY}/sso?SAMLRequest=")));
    let set_cookie = headers["set-cookie"].join("\n");
    assert!(set_cookie.contains("SameSite=None") && set_cookie.contains("Secure"));
    let request_id = cookie_value(&headers, "bearust_sso").unwrap();
    let cookie = format!("bearust_sso={request_id}");

    let saml = idp.response("corp", &request_id, "alice-id", "alice@example.com");
    let form = serde_urlencoded::to_string([("SAMLResponse", saml.as_str())]).unwrap();
    let (status, headers, _) = call(
        &app,
        "POST",
        "/api/auth/sso/corp/acs",
        Some(&cookie),
        Body::from(form.clone()),
        "application/x-www-form-urlencoded",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(headers["location"][0], "/");
    let session = format!(
        "bearust_session={}",
        cookie_value(&headers, "bearust_session").unwrap()
    );
    let (_, _, me) = call(
        &app,
        "GET",
        "/api/auth/me",
        Some(&session),
        Body::empty(),
        "text/plain",
    )
    .await;
    assert!(
        me.contains("alice@example.com") && me.contains("viewer"),
        "{me}"
    );

    // Replay of the same response is refused.
    let (_, headers, _) = call(
        &app,
        "POST",
        "/api/auth/sso/corp/acs",
        Some(&cookie),
        Body::from(form),
        "application/x-www-form-urlencoded",
    )
    .await;
    assert_eq!(headers["location"][0], "/login?sso_error=state_expired");
}
