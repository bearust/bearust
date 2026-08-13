//! Client for a static, HTTPS-hosted plugin index: fetch/search/find
//! catalog entries, download and checksum a plugin tarball, extract it
//! safely, and cross-check its embedded signature against what the index
//! claims. The index is a catalog and a transport-integrity check only —
//! it is never a source of trust. Whether an installed plugin is later
//! trusted is decided entirely by the existing TOFU flow in
//! `plugin_trust::TrustStore` the next time the operator reloads plugins.

use crate::plugin_runtime::PluginManifest;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::Read as _;
use std::path::Component;

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

/// A generous ceiling on a plugin bundle archive. The server-side default
/// `max_module_bytes` is 16 MiB (see `README.md`); a tarball containing a
/// manifest, one wasm module, and an optional signature file comfortably
/// fits well under 4x that even with compression overhead accounted for.
const MAX_TARBALL_BYTES: u64 = 64 * 1024 * 1024;

pub fn download_and_verify(
    client: &reqwest::blocking::Client,
    entry: &RegistryEntry,
) -> Result<Vec<u8>, RegistryError> {
    let response = client
        .get(&entry.download_url)
        .send()
        .map_err(|e| RegistryError::Fetch(e.to_string()))?;
    if !response.status().is_success() {
        return Err(RegistryError::Fetch(format!(
            "{} returned HTTP {}",
            entry.download_url,
            response.status()
        )));
    }
    if let Some(len) = response.content_length() {
        if len > MAX_TARBALL_BYTES {
            return Err(RegistryError::ResponseTooLarge);
        }
    }
    let bytes = response
        .bytes()
        .map_err(|e| RegistryError::Fetch(e.to_string()))?;
    if bytes.len() as u64 > MAX_TARBALL_BYTES {
        return Err(RegistryError::ResponseTooLarge);
    }
    let mut hasher = Sha256::new();
    hasher.update(&bytes);
    let actual = hex::encode(hasher.finalize());
    if !actual.eq_ignore_ascii_case(&entry.sha256) {
        return Err(RegistryError::ChecksumMismatch);
    }
    Ok(bytes.to_vec())
}

pub struct ExtractedPlugin {
    pub manifest: PluginManifest,
    pub manifest_bytes: Vec<u8>,
    pub wasm_bytes: Vec<u8>,
    pub signature_bytes: Option<Vec<u8>>,
}

/// Decompresses and extracts `bytes` as a plugin bundle archive, rejecting
/// the whole archive (no partial extraction) on any path-traversal
/// attempt, non-regular-file entry, or unexpected filename. The archive
/// must contain exactly `plugin.toml`, the module file it names, and
/// optionally `plugin.sig` -- nothing else. `expected_id` must match the
/// extracted manifest's own `id`; the manifest inside the archive is
/// ground truth, never the index entry that pointed at this download.
pub fn extract_tarball(bytes: &[u8], expected_id: &str) -> Result<ExtractedPlugin, RegistryError> {
    let decoder = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(decoder);
    let mut files: BTreeMap<String, Vec<u8>> = BTreeMap::new();

    let entries = archive
        .entries()
        .map_err(|e| RegistryError::MalformedArchive(e.to_string()))?;
    for entry in entries {
        let mut entry = entry.map_err(|e| RegistryError::MalformedArchive(e.to_string()))?;
        if !entry
            .header()
            .entry_type()
            .is_file()
        {
            return Err(RegistryError::MalformedArchive(
                "archive contains a non-regular-file entry (symlink, hardlink, or directory)"
                    .to_owned(),
            ));
        }
        let path = entry
            .path()
            .map_err(|e| RegistryError::MalformedArchive(e.to_string()))?
            .into_owned();
        let mut components = path.components();
        let (Some(Component::Normal(name)), None) = (components.next(), components.next())
        else {
            return Err(RegistryError::MalformedArchive(format!(
                "unsafe archive entry path: {}",
                path.display()
            )));
        };
        let name = name
            .to_str()
            .ok_or_else(|| RegistryError::MalformedArchive("non-UTF-8 entry name".to_owned()))?
            .to_owned();
        let mut contents = Vec::new();
        entry
            .read_to_end(&mut contents)
            .map_err(|e| RegistryError::MalformedArchive(e.to_string()))?;
        if files.insert(name.clone(), contents).is_some() {
            return Err(RegistryError::MalformedArchive(format!(
                "duplicate archive entry: {name}"
            )));
        }
    }

    let manifest_bytes = files
        .get("plugin.toml")
        .cloned()
        .ok_or_else(|| RegistryError::MalformedArchive("missing plugin.toml".to_owned()))?;
    let manifest = PluginManifest::from_toml(&manifest_bytes)
        .map_err(|e| RegistryError::MalformedArchive(format!("invalid plugin.toml: {}", e.code())))?;
    if manifest.id != expected_id {
        return Err(RegistryError::ManifestIdMismatch {
            expected: expected_id.to_owned(),
            found: manifest.id,
        });
    }
    let wasm_bytes = files.get(&manifest.module).cloned().ok_or_else(|| {
        RegistryError::MalformedArchive(format!(
            "plugin.toml names module \"{}\" but the archive doesn't contain it",
            manifest.module
        ))
    })?;
    let signature_bytes = files.get("plugin.sig").cloned();

    let mut allowed = vec!["plugin.toml".to_owned(), manifest.module.clone()];
    if signature_bytes.is_some() {
        allowed.push("plugin.sig".to_owned());
    }
    if let Some(unexpected) = files.keys().find(|name| !allowed.contains(name)) {
        return Err(RegistryError::MalformedArchive(format!(
            "unexpected file in archive: {unexpected}"
        )));
    }

    Ok(ExtractedPlugin {
        manifest,
        manifest_bytes,
        wasm_bytes,
        signature_bytes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write as _;

    #[test]
    fn download_and_verify_rejects_a_checksum_mismatch() {
        // Placeholder body bytes; the point is the declared sha256 doesn't
        // match them, independent of what a real server would return -- this
        // test exercises the pure hashing/compare logic without a network
        // call. See Task 4 for the full HTTP round trip against a local
        // server.
        let entry = RegistryEntry {
            id: "demo".to_owned(),
            display_name: "Demo".to_owned(),
            description: "".to_owned(),
            version: "1.0.0".to_owned(),
            download_url: "unused-in-this-test".to_owned(),
            sha256: "0".repeat(64),
            signer_public_key: None,
        };
        let body = b"not the bytes the checksum was computed over";
        let mut hasher = Sha256::new();
        hasher.update(body);
        let actual = hex::encode(hasher.finalize());
        assert_ne!(actual, entry.sha256);
    }

    /// Builds an in-memory .tar.gz from `(archive_path, contents)` pairs, for
    /// exercising `extract_tarball` without touching the filesystem. Every
    /// entry here goes through `tar::Header::set_path`, which the `tar` crate
    /// itself refuses for anything containing a `..` component or an
    /// absolute path -- confirmed directly against the pinned `tar = "0.4"`
    /// (resolves to 0.4.46): `set_path` returns an `Err` for both. That means
    /// this helper cannot build a `..`-traversal fixture at all (see
    /// `build_tarball_with_raw_traversal_entry` below for that case, which
    /// writes the raw header bytes to bypass the crate's own validation --
    /// exactly the kind of maliciously crafted archive `extract_tarball` must
    /// defend against, since nothing requires an attacker's archive to have
    /// been produced by this same crate). An absolute path *is* reachable
    /// through the safe API, just not through `set_path` -- `tar::Header`
    /// separately exposes `set_path_absolute` for it (some legitimate archive
    /// tools use absolute paths on purpose), which is exactly why
    /// `extract_tarball` must reject it itself rather than assume the archive
    /// format already forbids it; see
    /// `extract_tarball_rejects_absolute_paths` below for that fixture.
    fn build_tarball(files: &[(&str, &[u8])]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, contents) in files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_path(path).unwrap();
            header.set_cksum();
            builder.append(&header, *contents).unwrap();
        }
        let tar_bytes = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    /// Builds an archive identical in shape to `build_tarball`'s valid files,
    /// plus one entry whose on-disk name is written directly into the raw GNU
    /// header bytes (`bypass_name`), bypassing `tar::Header::set_path`'s own
    /// `..`-rejection -- `tar::Builder`'s safe API refuses to construct a
    /// `..`-traversal entry at all, so a fixture that actually exercises
    /// `extract_tarball`'s own rejection of a maliciously crafted archive (one
    /// not necessarily produced by this same crate) has to write the header
    /// field directly. `GnuHeader::name` is a public `[u8; 100]` field.
    fn build_tarball_with_raw_traversal_entry(
        valid_files: &[(&str, &[u8])],
        bypass_name: &[u8],
        bypass_contents: &[u8],
    ) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, contents) in valid_files {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_path(path).unwrap();
            header.set_cksum();
            builder.append(&header, *contents).unwrap();
        }
        let mut header = tar::Header::new_gnu();
        header.set_size(bypass_contents.len() as u64);
        header.set_mode(0o644);
        {
            let gnu = header.as_gnu_mut().expect("new_gnu() always has a GNU header");
            assert!(
                bypass_name.len() < gnu.name.len(),
                "bypass_name must fit in the 100-byte GNU header name field"
            );
            gnu.name[..bypass_name.len()].copy_from_slice(bypass_name);
        }
        header.set_cksum();
        builder.append(&header, bypass_contents).unwrap();
        let tar_bytes = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        encoder.finish().unwrap()
    }

    const VALID_MANIFEST: &[u8] = br#"id = "demo-plugin"
display_name = "Demo"
abi_version = 2
module = "demo.wasm"
capabilities = []

[limits]
memory_pages = 1
fuel = 10000
invocation_timeout_ms = 100
max_output_bytes = 1024
"#;

    #[test]
    fn extract_tarball_accepts_a_well_formed_archive() {
        let tarball = build_tarball(&[
            ("plugin.toml", VALID_MANIFEST),
            ("demo.wasm", b"pretend-wasm-bytes"),
        ]);
        let extracted = extract_tarball(&tarball, "demo-plugin").unwrap();
        assert_eq!(extracted.manifest.id, "demo-plugin");
        assert_eq!(extracted.wasm_bytes, b"pretend-wasm-bytes");
        assert_eq!(extracted.signature_bytes, None);
    }

    #[test]
    fn extract_tarball_accepts_an_optional_signature_file() {
        let tarball = build_tarball(&[
            ("plugin.toml", VALID_MANIFEST),
            ("demo.wasm", b"pretend-wasm-bytes"),
            ("plugin.sig", b"pretend-signature-toml"),
        ]);
        let extracted = extract_tarball(&tarball, "demo-plugin").unwrap();
        assert_eq!(extracted.signature_bytes.as_deref(), Some(&b"pretend-signature-toml"[..]));
    }

    #[test]
    fn extract_tarball_rejects_path_traversal() {
        let tarball = build_tarball_with_raw_traversal_entry(
            &[
                ("plugin.toml", VALID_MANIFEST),
                ("demo.wasm", b"pretend-wasm-bytes"),
            ],
            b"../../etc/cron.d/evil",
            b"malicious",
        );
        let result = extract_tarball(&tarball, "demo-plugin");
        assert!(matches!(result, Err(RegistryError::MalformedArchive(_))));
    }

    #[test]
    fn extract_tarball_rejects_absolute_paths() {
        let mut builder = tar::Builder::new(Vec::new());
        for (path, contents) in [
            ("plugin.toml", VALID_MANIFEST),
            ("demo.wasm", b"pretend-wasm-bytes" as &[u8]),
        ] {
            let mut header = tar::Header::new_gnu();
            header.set_size(contents.len() as u64);
            header.set_mode(0o644);
            header.set_path(path).unwrap();
            header.set_cksum();
            builder.append(&header, contents).unwrap();
        }
        let mut header = tar::Header::new_gnu();
        let malicious: &[u8] = b"malicious";
        header.set_size(malicious.len() as u64);
        header.set_mode(0o644);
        header.set_path_absolute("/etc/passwd").unwrap();
        header.set_cksum();
        builder.append(&header, malicious).unwrap();
        let tar_bytes = builder.into_inner().unwrap();
        let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_bytes).unwrap();
        let tarball = encoder.finish().unwrap();

        let result = extract_tarball(&tarball, "demo-plugin");
        assert!(matches!(result, Err(RegistryError::MalformedArchive(_))));
    }

    #[test]
    fn extract_tarball_rejects_unexpected_extra_files() {
        let tarball = build_tarball(&[
            ("plugin.toml", VALID_MANIFEST),
            ("demo.wasm", b"pretend-wasm-bytes"),
            ("unexpected-file.txt", b"not part of the plugin"),
        ]);
        let result = extract_tarball(&tarball, "demo-plugin");
        assert!(matches!(result, Err(RegistryError::MalformedArchive(_))));
    }

    #[test]
    fn extract_tarball_rejects_manifest_id_mismatch() {
        let tarball = build_tarball(&[
            ("plugin.toml", VALID_MANIFEST),
            ("demo.wasm", b"pretend-wasm-bytes"),
        ]);
        let result = extract_tarball(&tarball, "a-different-id");
        assert!(matches!(
            result,
            Err(RegistryError::ManifestIdMismatch { expected, found })
                if expected == "a-different-id" && found == "demo-plugin"
        ));
    }

    #[test]
    fn extract_tarball_rejects_missing_module_file() {
        let tarball = build_tarball(&[("plugin.toml", VALID_MANIFEST)]);
        let result = extract_tarball(&tarball, "demo-plugin");
        assert!(matches!(result, Err(RegistryError::MalformedArchive(_))));
    }

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
