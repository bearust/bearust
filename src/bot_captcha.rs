//! Third-party CAPTCHA providers for the bot challenge page: Cloudflare
//! Turnstile, hCaptcha, and Google reCAPTCHA (v2/invisible). When one is
//! configured with a secret, it replaces proof-of-work as the challenge
//! proof; the signed, fingerprint-bound challenge token still applies.

use serde::{Deserialize, Serialize};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptchaProvider {
    #[default]
    None,
    Turnstile,
    Hcaptcha,
    Recaptcha,
}

impl CaptchaProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Turnstile => "turnstile",
            Self::Hcaptcha => "hcaptcha",
            Self::Recaptcha => "recaptcha",
        }
    }

    pub fn parse(value: &str) -> Self {
        match value {
            "turnstile" => Self::Turnstile,
            "hcaptcha" => Self::Hcaptcha,
            "recaptcha" => Self::Recaptcha,
            _ => Self::None,
        }
    }

    pub fn verify_url(self) -> Option<&'static str> {
        match self {
            Self::None => None,
            Self::Turnstile => Some("https://challenges.cloudflare.com/turnstile/v0/siteverify"),
            Self::Hcaptcha => Some("https://api.hcaptcha.com/siteverify"),
            Self::Recaptcha => Some("https://www.google.com/recaptcha/api/siteverify"),
        }
    }
}

/// Replicated CAPTCHA settings. The secret is node-local (secret store).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptchaConfig {
    pub provider: CaptchaProvider,
    pub site_key: String,
    #[serde(default)]
    pub updated_at: String,
}

pub const SECRET_NAME: &str = "bot-captcha-secret";
pub const MAX_KEY_BYTES: usize = 256;
pub const MAX_RESPONSE_TOKEN_BYTES: usize = 4096;

impl CaptchaConfig {
    pub fn validate(&self) -> Result<(), &'static str> {
        let key_ok = self.site_key.len() <= MAX_KEY_BYTES
            && self
                .site_key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !key_ok || (self.provider != CaptchaProvider::None && self.site_key.is_empty()) {
            return Err("invalid CAPTCHA settings");
        }
        Ok(())
    }
}

#[derive(Deserialize)]
struct SiteVerify {
    success: bool,
}

/// Ask the provider whether `response` is a valid solution. `endpoint`
/// overrides the provider URL (tests). Any transport error is a failure.
pub async fn verify(
    provider: CaptchaProvider,
    secret: &str,
    site_key: &str,
    response: &str,
    remote_ip: Option<&str>,
    endpoint: Option<&str>,
) -> bool {
    let Some(url) = endpoint.or(provider.verify_url()) else {
        return false;
    };
    if response.is_empty() || response.len() > MAX_RESPONSE_TOKEN_BYTES {
        return false;
    }
    let mut form = vec![("secret", secret), ("response", response)];
    if let Some(ip) = remote_ip {
        form.push(("remoteip", ip));
    }
    if provider == CaptchaProvider::Hcaptcha {
        form.push(("sitekey", site_key));
    }
    let Ok(client) = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
    else {
        return false;
    };
    match client.post(url).form(&form).send().await {
        Ok(reply) if reply.status().is_success() => reply
            .json::<SiteVerify>()
            .await
            .is_ok_and(|body| body.success),
        _ => false,
    }
}
