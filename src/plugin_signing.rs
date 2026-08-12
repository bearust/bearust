//! Ed25519 signature construction and verification for plugin manifests.
//!
//! A plugin's signature covers both its manifest's security-relevant
//! fields and its compiled wasm bytes (see `signing_message`), so
//! tampering with either invalidates the signature. This module has no
//! knowledge of trust pinning (see `plugin_trust`) — it only answers "is
//! this a cryptographically valid signature for this exact manifest and
//! wasm pair", nothing about whether the signing key should be trusted.

use crate::plugin_runtime::{PluginLimits, PluginManifest};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};

/// The subset of a manifest's fields that are security-relevant and
/// therefore covered by a plugin's signature. `display_name` (cosmetic)
/// and `module` (a local filename, not the wasm content itself — the wasm
/// bytes are separately hashed by content) are deliberately excluded.
#[derive(Debug, Serialize)]
struct SignedManifestFields {
    id: String,
    abi_version: u32,
    capabilities: Vec<String>,
    limits: PluginLimits,
}

/// Builds the 64-byte message a plugin's signature covers: the manifest's
/// security-relevant fields' digest, concatenated with the wasm bytes'
/// digest. `capabilities` is sorted before serialization so declaration
/// order in `plugin.toml` never changes the signed message.
pub fn signing_message(manifest: &PluginManifest, wasm_bytes: &[u8]) -> [u8; 64] {
    let mut capabilities = manifest.capabilities.clone();
    capabilities.sort();
    let fields = SignedManifestFields {
        id: manifest.id.clone(),
        abi_version: manifest.abi_version,
        capabilities,
        limits: manifest.limits.clone(),
    };
    let manifest_json =
        serde_json::to_vec(&fields).expect("SignedManifestFields always serializes");
    let manifest_digest = Sha256::digest(&manifest_json);
    let wasm_digest = Sha256::digest(wasm_bytes);
    let mut message = [0u8; 64];
    message[..32].copy_from_slice(&manifest_digest);
    message[32..].copy_from_slice(&wasm_digest);
    message
}

/// The on-disk (`plugin.sig`, TOML) shape of a plugin's signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginSignature {
    pub algorithm: String,
    pub public_key: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureError {
    /// The signature file's shape, encoding, or algorithm is invalid --
    /// covers everything short of "the crypto check itself failed":
    /// unsupported algorithm, bad base64, or wrong-length decoded bytes.
    MalformedSignature,
    /// Well-formed, but the signature does not verify against the
    /// reconstructed signing message.
    InvalidSignature,
}

impl SignatureError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MalformedSignature => "malformed_signature",
            Self::InvalidSignature => "invalid_signature",
        }
    }
}

/// Verifies `sig` against `manifest`/`wasm_bytes` and returns the
/// signature's public key on success. A valid return here means only
/// "this signature is cryptographically genuine for this exact
/// manifest+wasm pair" -- the caller is still responsible for deciding
/// whether that key should be trusted (see `plugin_trust::TrustStore`).
pub fn verify(
    manifest: &PluginManifest,
    wasm_bytes: &[u8],
    sig: &PluginSignature,
) -> Result<VerifyingKey, SignatureError> {
    if sig.algorithm != "ed25519" {
        return Err(SignatureError::MalformedSignature);
    }
    let key_bytes = BASE64
        .decode(sig.public_key.as_bytes())
        .map_err(|_| SignatureError::MalformedSignature)?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| SignatureError::MalformedSignature)?;
    let verifying_key =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| SignatureError::MalformedSignature)?;
    let sig_bytes = BASE64
        .decode(sig.signature.as_bytes())
        .map_err(|_| SignatureError::MalformedSignature)?;
    let sig_bytes: [u8; 64] = sig_bytes
        .try_into()
        .map_err(|_| SignatureError::MalformedSignature)?;
    let signature = Signature::from_bytes(&sig_bytes);
    let message = signing_message(manifest, wasm_bytes);
    verifying_key
        .verify(&message, &signature)
        .map_err(|_| SignatureError::InvalidSignature)?;
    Ok(verifying_key)
}

/// Signs `manifest`/`wasm_bytes` with `signing_key`, producing the
/// `plugin.sig` content. Used by the `bearust plugin sign` CLI command.
pub fn sign(
    manifest: &PluginManifest,
    wasm_bytes: &[u8],
    signing_key: &SigningKey,
) -> PluginSignature {
    let message = signing_message(manifest, wasm_bytes);
    let signature = signing_key.sign(&message);
    PluginSignature {
        algorithm: "ed25519".to_string(),
        public_key: BASE64.encode(signing_key.verifying_key().to_bytes()),
        signature: BASE64.encode(signature.to_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin_runtime::{PluginLimits, PluginManifest};
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    fn sample_manifest() -> PluginManifest {
        PluginManifest {
            id: "demo-plugin".to_string(),
            display_name: "Demo".to_string(),
            abi_version: 2,
            module: "demo.wasm".to_string(),
            capabilities: vec!["health_check".to_string()],
            limits: PluginLimits {
                memory_pages: 4,
                fuel: 1000,
                invocation_timeout_ms: 100,
                max_output_bytes: 1024,
            },
        }
    }

    #[test]
    fn sign_then_verify_round_trips() {
        let manifest = sample_manifest();
        let wasm_bytes = b"pretend-wasm-bytes";
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = sign(&manifest, wasm_bytes, &signing_key);
        assert_eq!(signature.algorithm, "ed25519");
        let verified = verify(&manifest, wasm_bytes, &signature).unwrap();
        assert_eq!(verified.to_bytes(), signing_key.verifying_key().to_bytes());
    }

    #[test]
    fn tampering_with_a_manifest_field_invalidates_the_signature() {
        let manifest = sample_manifest();
        let wasm_bytes = b"pretend-wasm-bytes";
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = sign(&manifest, wasm_bytes, &signing_key);
        let mut tampered = manifest;
        tampered.capabilities.push("waf.detect".to_string());
        assert_eq!(
            verify(&tampered, wasm_bytes, &signature),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn tampering_with_wasm_bytes_invalidates_the_signature() {
        let manifest = sample_manifest();
        let wasm_bytes = b"pretend-wasm-bytes";
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = sign(&manifest, wasm_bytes, &signing_key);
        assert_eq!(
            verify(&manifest, b"different-wasm-bytes", &signature),
            Err(SignatureError::InvalidSignature)
        );
    }

    #[test]
    fn capability_declaration_order_does_not_affect_the_signature() {
        let mut manifest_a = sample_manifest();
        manifest_a.capabilities = vec!["health_check".to_string(), "waf.detect".to_string()];
        let mut manifest_b = sample_manifest();
        manifest_b.capabilities = vec!["waf.detect".to_string(), "health_check".to_string()];
        let wasm_bytes = b"pretend-wasm-bytes";
        assert_eq!(
            signing_message(&manifest_a, wasm_bytes),
            signing_message(&manifest_b, wasm_bytes)
        );
    }

    #[test]
    fn malformed_base64_public_key_is_rejected_without_panicking() {
        let manifest = sample_manifest();
        let signature = PluginSignature {
            algorithm: "ed25519".to_string(),
            public_key: "not-valid-base64!!!".to_string(),
            signature: "AAAA".to_string(),
        };
        assert_eq!(
            verify(&manifest, b"wasm", &signature),
            Err(SignatureError::MalformedSignature)
        );
    }

    #[test]
    fn wrong_length_public_key_is_rejected_without_panicking() {
        let manifest = sample_manifest();
        let signature = PluginSignature {
            algorithm: "ed25519".to_string(),
            public_key: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                b"too-short",
            ),
            signature: base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                [0u8; 64],
            ),
        };
        assert_eq!(
            verify(&manifest, b"wasm", &signature),
            Err(SignatureError::MalformedSignature)
        );
    }

    #[test]
    fn unsupported_algorithm_is_rejected() {
        let manifest = sample_manifest();
        let wasm_bytes = b"pretend-wasm-bytes";
        let signing_key = SigningKey::generate(&mut OsRng);
        let mut signature = sign(&manifest, wasm_bytes, &signing_key);
        signature.algorithm = "rsa".to_string();
        assert_eq!(
            verify(&manifest, wasm_bytes, &signature),
            Err(SignatureError::MalformedSignature)
        );
    }
}
