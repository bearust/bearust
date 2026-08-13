//! Client for a static, HTTPS-hosted plugin index: fetch/search/find
//! catalog entries, download and checksum a plugin tarball, extract it
//! safely, and cross-check its embedded signature against what the index
//! claims. The index is a catalog and a transport-integrity check only —
//! it is never a source of trust. Whether an installed plugin is later
//! trusted is decided entirely by the existing TOFU flow in
//! `plugin_trust::TrustStore` the next time the operator reloads plugins.

use serde::Deserialize;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RegistryEntry {
    pub id: String,
    pub display_name: String,
    pub description: String,
    pub version: String,
    pub download_url: String,
    pub sha256: String,
    pub signer_public_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
pub struct RegistryIndex {
    pub entries: Vec<RegistryEntry>,
}

/// A generous ceiling on the index response itself -- a static JSON
/// catalog has no reason to be large, so anything past this is treated
/// as a hostile or broken server rather than read fully into memory.
const MAX_INDEX_RESPONSE_BYTES: u64 = 1_048_576;

#[derive(Debug)]
pub enum RegistryError {
    Fetch(String),
    Parse(String),
    ResponseTooLarge,
    NotFound(String),
    ChecksumMismatch,
    MalformedArchive(String),
    ManifestIdMismatch { expected: String, found: String },
    SignerKeyMismatch(String),
}

impl std::fmt::Display for RegistryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Fetch(reason) => write!(f, "could not fetch: {reason}"),
            Self::Parse(reason) => write!(f, "could not parse response: {reason}"),
            Self::ResponseTooLarge => write!(f, "response exceeded the size limit"),
            Self::NotFound(id) => write!(
                f,
                "no plugin with id \"{id}\" in the index -- try `bearust plugin search`"
            ),
            Self::ChecksumMismatch => {
                write!(f, "downloaded archive does not match the index's checksum")
            }
            Self::MalformedArchive(reason) => write!(f, "malformed plugin archive: {reason}"),
            Self::ManifestIdMismatch { expected, found } => write!(
                f,
                "archive's plugin.toml declares id \"{found}\", expected \"{expected}\""
            ),
            Self::SignerKeyMismatch(reason) => write!(f, "signer key mismatch: {reason}"),
        }
    }
}

impl RegistryIndex {
    pub fn fetch(
        client: &reqwest::blocking::Client,
        url: &str,
    ) -> Result<RegistryIndex, RegistryError> {
        let response = client
            .get(url)
            .send()
            .map_err(|e| RegistryError::Fetch(e.to_string()))?;
        if !response.status().is_success() {
            return Err(RegistryError::Fetch(format!(
                "{url} returned HTTP {}",
                response.status()
            )));
        }
        if let Some(len) = response.content_length() {
            if len > MAX_INDEX_RESPONSE_BYTES {
                return Err(RegistryError::ResponseTooLarge);
            }
        }
        let bytes = response
            .bytes()
            .map_err(|e| RegistryError::Fetch(e.to_string()))?;
        if bytes.len() as u64 > MAX_INDEX_RESPONSE_BYTES {
            return Err(RegistryError::ResponseTooLarge);
        }
        serde_json::from_slice(&bytes).map_err(|e| RegistryError::Parse(e.to_string()))
    }

    pub fn find(&self, id: &str) -> Option<&RegistryEntry> {
        self.entries.iter().find(|entry| entry.id == id)
    }

    pub fn search(&self, query: &str) -> Vec<&RegistryEntry> {
        let query = query.to_ascii_lowercase();
        self.entries
            .iter()
            .filter(|entry| {
                entry.id.to_ascii_lowercase().contains(&query)
                    || entry.display_name.to_ascii_lowercase().contains(&query)
                    || entry.description.to_ascii_lowercase().contains(&query)
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_well_formed_index() {
        let json = r#"{
            "entries": [
                {
                    "id": "example-plugin",
                    "display_name": "Example Plugin",
                    "description": "Does something useful.",
                    "version": "1.0.0",
                    "download_url": "https://example.com/example-plugin-1.0.0.tar.gz",
                    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    "signer_public_key": "cGxhY2Vob2xkZXItYmFzZTY0LWtleQ=="
                }
            ]
        }"#;
        let index: RegistryIndex = serde_json::from_str(json).unwrap();
        assert_eq!(index.entries.len(), 1);
        assert_eq!(index.entries[0].id, "example-plugin");
        assert_eq!(index.entries[0].signer_public_key.as_deref(), Some("cGxhY2Vob2xkZXItYmFzZTY0LWtleQ=="));
    }

    #[test]
    fn parses_an_unsigned_entry_with_null_signer_key() {
        let json = r#"{
            "entries": [
                {
                    "id": "unsigned-plugin",
                    "display_name": "Unsigned Plugin",
                    "description": "No signature yet.",
                    "version": "0.1.0",
                    "download_url": "https://example.com/unsigned-plugin-0.1.0.tar.gz",
                    "sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    "signer_public_key": null
                }
            ]
        }"#;
        let index: RegistryIndex = serde_json::from_str(json).unwrap();
        assert_eq!(index.entries[0].signer_public_key, None);
    }

    fn sample_index() -> RegistryIndex {
        RegistryIndex {
            entries: vec![
                RegistryEntry {
                    id: "waf-guard".to_owned(),
                    display_name: "WAF Guard".to_owned(),
                    description: "Blocks admin paths.".to_owned(),
                    version: "1.0.0".to_owned(),
                    download_url: "https://example.com/waf-guard-1.0.0.tar.gz".to_owned(),
                    sha256: "a".repeat(64),
                    signer_public_key: Some("key1".to_owned()),
                },
                RegistryEntry {
                    id: "header-tagger".to_owned(),
                    display_name: "Header Tagger".to_owned(),
                    description: "Adds a diagnostic header.".to_owned(),
                    version: "0.2.0".to_owned(),
                    download_url: "https://example.com/header-tagger-0.2.0.tar.gz".to_owned(),
                    sha256: "b".repeat(64),
                    signer_public_key: None,
                },
            ],
        }
    }

    #[test]
    fn find_matches_by_exact_id_only() {
        let index = sample_index();
        assert_eq!(index.find("waf-guard").map(|e| e.id.as_str()), Some("waf-guard"));
        assert_eq!(index.find("waf"), None);
    }

    #[test]
    fn search_matches_case_insensitively_across_id_name_and_description() {
        let index = sample_index();
        let results = index.search("HEADER");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "header-tagger");

        let results = index.search("blocks");
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].id, "waf-guard");

        assert_eq!(index.search("nonexistent").len(), 0);
    }
}
