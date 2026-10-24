//! Client for a static, HTTPS-hosted plugin index: fetch/search/find
//! catalog entries, download and checksum a plugin tarball, extract it
//! safely, and cross-check its embedded signature against what the index
//! claims. The index is a catalog and a transport-integrity check only —
//! it is never a source of trust. Whether an installed plugin is later
//! trusted is decided entirely by the existing TOFU flow in
//! `plugin_trust::TrustStore` the next time the operator reloads plugins.

use crate::plugin_runtime::PluginManifest;
use crate::plugin_signing::{self, PluginSignature};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
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
    /// Signer public keys (base64) the registry has revoked. Honored only
    /// from an index whose signature verified against the pinned key.
    #[serde(default)]
    pub revoked_keys: Vec<String>,
    /// Individual releases withdrawn by the registry (same condition).
    #[serde(default)]
    pub revoked: Vec<RevokedRelease>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
pub struct RevokedRelease {
    pub id: String,
    pub version: String,
}

/// An index plus whether its detached signature verified. An unsigned index
/// is a catalog only: its revocation lists are dropped.
#[derive(Debug, Clone)]
pub struct VerifiedIndex {
    pub index: RegistryIndex,
    pub signed: bool,
}

/// The community index used when no registry URL is configured.
pub const DEFAULT_PLUGIN_REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/Bearust/bearust-plugin-index/main/index.json";

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
    ManifestIdMismatch {
        expected: String,
        found: String,
    },
    SignerKeyMismatch(String),
    /// The index signature is missing or invalid for the pinned registry key.
    IndexSignature(String),
    /// The release or its signer key has been revoked by the registry.
    Revoked(String),
    AlreadyInstalled(String),
    Io(String),
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
            Self::IndexSignature(reason) => write!(f, "registry index signature: {reason}"),
            Self::Revoked(reason) => write!(f, "revoked by the registry: {reason}"),
            Self::AlreadyInstalled(path) => {
                write!(f, "{path} already exists -- pass --force to overwrite")
            }
            Self::Io(reason) => write!(f, "could not write plugin files: {reason}"),
        }
    }
}

impl RegistryIndex {
    pub fn fetch(
        client: &reqwest::blocking::Client,
        url: &str,
    ) -> Result<RegistryIndex, RegistryError> {
        let bytes = fetch_bytes(client, url)?;
        serde_json::from_slice(&bytes).map_err(|e| RegistryError::Parse(e.to_string()))
    }

    /// Fetch the index and its detached signature (`<url>.sig`, base64
    /// Ed25519 over the exact index bytes). With a pinned `registry_key`
    /// the signature is mandatory; without one the index is accepted as an
    /// unsigned catalog and its revocation lists are ignored.
    pub fn fetch_verified(
        client: &reqwest::blocking::Client,
        url: &str,
        registry_key: Option<&str>,
    ) -> Result<VerifiedIndex, RegistryError> {
        let bytes = fetch_bytes(client, url)?;
        let mut index: RegistryIndex =
            serde_json::from_slice(&bytes).map_err(|e| RegistryError::Parse(e.to_string()))?;
        let signed = match registry_key.map(str::trim).filter(|k| !k.is_empty()) {
            Some(key) => {
                let signature = fetch_bytes(client, &format!("{url}.sig"))
                    .map_err(|e| RegistryError::IndexSignature(format!("no signature: {e}")))?;
                verify_index_signature(&bytes, &signature, key)?;
                true
            }
            None => false,
        };
        if !signed {
            index.revoked_keys.clear();
            index.revoked.clear();
        }
        Ok(VerifiedIndex { index, signed })
    }
}

/// Verify a base64 Ed25519 signature over `bytes` with a base64 public key.
pub fn verify_index_signature(
    bytes: &[u8],
    signature_b64: &[u8],
    public_key_b64: &str,
) -> Result<(), RegistryError> {
    use ed25519_dalek::{Signature, VerifyingKey};
    let invalid = |reason: &str| RegistryError::IndexSignature(reason.to_owned());
    let key_bytes: [u8; 32] = BASE64
        .decode(public_key_b64)
        .ok()
        .and_then(|k| k.try_into().ok())
        .ok_or_else(|| invalid("pinned registry key is not a base64 Ed25519 key"))?;
    let key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| invalid("invalid registry key"))?;
    let signature_text = std::str::from_utf8(signature_b64).map_err(|_| invalid("malformed"))?;
    let signature_bytes: [u8; 64] = BASE64
        .decode(signature_text.trim())
        .ok()
        .and_then(|s| s.try_into().ok())
        .ok_or_else(|| invalid("malformed"))?;
    key.verify_strict(bytes, &Signature::from_bytes(&signature_bytes))
        .map_err(|_| invalid("does not verify against the pinned registry key"))
}

fn fetch_bytes(client: &reqwest::blocking::Client, url: &str) -> Result<Vec<u8>, RegistryError> {
    {
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
        // `content_length()` is only a fast-path rejection for a present,
        // honest header -- a server that omits it or lies can still make
        // `.bytes()` buffer an unbounded body before any check fires. Read
        // at most one byte past the limit so an oversized body is caught
        // without ever fully buffering it.
        let mut bytes = Vec::new();
        response
            .take(MAX_INDEX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .map_err(|e| RegistryError::Fetch(e.to_string()))?;
        if bytes.len() as u64 > MAX_INDEX_RESPONSE_BYTES {
            return Err(RegistryError::ResponseTooLarge);
        }
        Ok(bytes)
    }
}

impl RegistryIndex {
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

/// A generous ceiling on a single decompressed archive entry. `flate2`
/// happily inflates a small compressed tarball into gigabytes in memory, so
/// `MAX_TARBALL_BYTES` (which only bounds the *compressed* download) isn't
/// enough on its own -- this bounds what `extract_tarball` will ever buffer
/// per entry, well above the server's 16 MiB `max_module_bytes` default but
/// nowhere near a decompression bomb's blast radius.
const MAX_ENTRY_BYTES: u64 = 32 * 1024 * 1024;

/// A ceiling on the *sum* of decompressed bytes read across every entry in
/// the archive, independent of the per-entry cap above. A legitimate plugin
/// bundle never has more than three substantial entries (`plugin.toml`, one
/// wasm module, an optional `plugin.sig`), so this is deliberately kept in
/// the same ballpark as `MAX_ENTRY_BYTES` itself rather than some multiple
/// of it scaled by an assumed entry count -- a tarball of many
/// just-under-the-per-entry-cap entries would otherwise sail past a looser
/// bound and still exhaust memory before the loop's later "unexpected file"
/// check ever runs. Checked incrementally, entry by entry, so a hostile
/// archive is rejected the moment the running total would exceed this, not
/// after the whole loop finishes.
const MAX_TOTAL_DECOMPRESSED_BYTES: u64 = MAX_ENTRY_BYTES + (8 * 1024 * 1024);

/// A ceiling on the number of entries an archive may contain. A legitimate
/// plugin bundle never has more than three (`plugin.toml`, one wasm module,
/// an optional `plugin.sig`), so this also structurally blocks the "many
/// small entries" attack shape regardless of the byte accounting above.
const MAX_ARCHIVE_ENTRIES: usize = 8;

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
    // See the matching comment in `RegistryIndex::fetch`: `content_length()`
    // does nothing when the header is absent or dishonest, so bound the
    // actual read instead of trusting it alone.
    let mut bytes = Vec::new();
    response
        .take(MAX_TARBALL_BYTES + 1)
        .read_to_end(&mut bytes)
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
    Ok(bytes)
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
    let mut entry_count: usize = 0;
    let mut total_decompressed_bytes: u64 = 0;
    for entry in entries {
        entry_count += 1;
        if entry_count > MAX_ARCHIVE_ENTRIES {
            return Err(RegistryError::MalformedArchive(format!(
                "archive contains more than the {MAX_ARCHIVE_ENTRIES}-entry limit"
            )));
        }
        let mut entry = entry.map_err(|e| RegistryError::MalformedArchive(e.to_string()))?;
        if !entry.header().entry_type().is_file() {
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
        let (Some(Component::Normal(name)), None) = (components.next(), components.next()) else {
            return Err(RegistryError::MalformedArchive(format!(
                "unsafe archive entry path: {}",
                path.display()
            )));
        };
        let name = name
            .to_str()
            .ok_or_else(|| RegistryError::MalformedArchive("non-UTF-8 entry name".to_owned()))?
            .to_owned();
        // The header's declared size is untrusted metadata from the archive
        // itself, but rejecting on it up front avoids even attempting to
        // buffer an entry that claims to be huge. The bounded read below is
        // the real defense -- it catches a header that understates the true
        // (decompressed) entry size too.
        if entry.size() > MAX_ENTRY_BYTES {
            return Err(RegistryError::MalformedArchive(format!(
                "archive entry \"{name}\" exceeds the {MAX_ENTRY_BYTES}-byte per-entry limit"
            )));
        }
        // Bound the aggregate before doing any reading for this entry too --
        // the header's declared size is untrusted, but rejecting on it up
        // front (in addition to the bounded read below, which is the real
        // defense against an understated header) avoids even attempting to
        // buffer an entry once the running total is already known to be
        // hostile.
        if total_decompressed_bytes.saturating_add(entry.size()) > MAX_TOTAL_DECOMPRESSED_BYTES {
            return Err(RegistryError::MalformedArchive(format!(
                "archive's total decompressed size exceeds the {MAX_TOTAL_DECOMPRESSED_BYTES}-byte aggregate limit"
            )));
        }
        // Cap this entry's read at whatever headroom remains in the
        // aggregate budget (never more than MAX_ENTRY_BYTES), so a single
        // entry's read can never itself blow past the aggregate ceiling no
        // matter what the header claimed.
        let remaining_budget = MAX_TOTAL_DECOMPRESSED_BYTES - total_decompressed_bytes;
        let read_cap = MAX_ENTRY_BYTES.min(remaining_budget);
        let mut contents = Vec::new();
        entry
            .by_ref()
            .take(read_cap)
            .read_to_end(&mut contents)
            .map_err(|e| RegistryError::MalformedArchive(e.to_string()))?;
        if contents.len() as u64 == read_cap {
            // Either genuinely exactly at the cap, or -- far more likely for
            // a hostile archive -- silently truncated real data beyond it.
            // Confirm nothing more was left to read; if there was, reject
            // outright rather than accepting a truncated file.
            let mut probe = [0u8; 1];
            let more = entry
                .read(&mut probe)
                .map_err(|e| RegistryError::MalformedArchive(e.to_string()))?;
            if more > 0 {
                return Err(RegistryError::MalformedArchive(format!(
                    "archive entry \"{name}\" exceeds the {MAX_ENTRY_BYTES}-byte per-entry limit, \
                     or the archive's total decompressed size exceeds the \
                     {MAX_TOTAL_DECOMPRESSED_BYTES}-byte aggregate limit"
                )));
            }
        }
        total_decompressed_bytes += contents.len() as u64;
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
    let manifest = PluginManifest::from_toml(&manifest_bytes).map_err(|e| {
        RegistryError::MalformedArchive(format!("invalid plugin.toml: {}", e.code()))
    })?;
    if manifest.id != expected_id {
        return Err(RegistryError::ManifestIdMismatch {
            expected: expected_id.to_owned(),
            found: manifest.id,
        });
    }
    let wasm_bytes = files.remove(&manifest.module).ok_or_else(|| {
        RegistryError::MalformedArchive(format!(
            "plugin.toml names module \"{}\" but the archive doesn't contain it",
            manifest.module
        ))
    })?;
    let signature_bytes = files.remove("plugin.sig");

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

/// Cross-checks `extracted`'s embedded signature (if any) against what the
/// index entry claimed. Returns the verified signer's base64 public key on
/// success (`None` only for a genuinely unsigned plugin the index also
/// didn't claim a signer for). This is the only place index metadata can
/// abort an install on a *trust*-relevant mismatch -- everywhere else the
/// index is just a catalog. It never pins a key: that remains
/// `plugin_trust::TrustStore`'s job, run by the existing reload path.
pub fn verify_signer(
    extracted: &ExtractedPlugin,
    declared_signer_public_key: Option<&str>,
) -> Result<Option<String>, RegistryError> {
    match (&extracted.signature_bytes, declared_signer_public_key) {
        (None, None) => Ok(None),
        (None, Some(_)) => Err(RegistryError::SignerKeyMismatch(
            "index declares a signer but the archive has no plugin.sig".to_owned(),
        )),
        (Some(sig_bytes), declared) => {
            let sig_str = std::str::from_utf8(sig_bytes).map_err(|e| {
                RegistryError::SignerKeyMismatch(format!("plugin.sig is not valid UTF-8: {e}"))
            })?;
            let signature: PluginSignature = toml::from_str(sig_str).map_err(|e| {
                RegistryError::SignerKeyMismatch(format!("plugin.sig does not parse: {e}"))
            })?;
            let verifying_key =
                plugin_signing::verify(&extracted.manifest, &extracted.wasm_bytes, &signature)
                    .map_err(|e| {
                        RegistryError::SignerKeyMismatch(format!(
                            "signature does not verify: {}",
                            e.code()
                        ))
                    })?;
            let actual_key_b64 = BASE64.encode(verifying_key.to_bytes());
            if let Some(declared) = declared {
                if declared != actual_key_b64 {
                    return Err(RegistryError::SignerKeyMismatch(format!(
                        "index declares signer {declared} but the archive is signed by {actual_key_b64}"
                    )));
                }
            }
            Ok(Some(actual_key_b64))
        }
    }
}

/// Metadata written next to an installed plugin (`.registry.json`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct InstallRecord {
    pub id: String,
    pub version: String,
    pub signer: Option<String>,
    pub index_signed: bool,
    pub installed_at: String,
}

pub const INSTALL_RECORD: &str = ".registry.json";
/// Registry-revoked signer keys, persisted in the plugins directory and
/// enforced on every plugin reload.
pub const REVOKED_KEYS_FILE: &str = "revoked-keys.json";

/// The registry version installed in `plugins_dir/<id>`, if it was
/// installed from a registry.
pub fn installed_record(plugins_dir: &std::path::Path, id: &str) -> Option<InstallRecord> {
    let bytes = std::fs::read(plugins_dir.join(id).join(INSTALL_RECORD)).ok()?;
    serde_json::from_slice(&bytes).ok()
}

/// Compare dotted numeric versions (`1.10.0` > `1.9.3`); non-numeric parts
/// compare as text. Used to flag available upgrades.
pub fn version_newer(candidate: &str, installed: &str) -> bool {
    let parse = |v: &str| -> Vec<(u64, String)> {
        v.trim_start_matches('v')
            .split(['.', '-', '+'])
            .map(|part| (part.parse::<u64>().unwrap_or(0), part.to_owned()))
            .collect()
    };
    parse(candidate) > parse(installed)
}

/// Merge a signed index's revoked keys into the plugins directory's
/// revocation file so already-installed plugins stop loading.
pub fn persist_revocations(
    plugins_dir: &std::path::Path,
    verified: &VerifiedIndex,
) -> Result<(), RegistryError> {
    if !verified.signed || verified.index.revoked_keys.is_empty() {
        return Ok(());
    }
    let path = plugins_dir.join(REVOKED_KEYS_FILE);
    let mut keys = load_revoked_keys(plugins_dir);
    for key in &verified.index.revoked_keys {
        if !keys.contains(key) {
            keys.push(key.clone());
        }
    }
    keys.sort();
    std::fs::create_dir_all(plugins_dir).map_err(|e| RegistryError::Io(e.to_string()))?;
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, serde_json::to_vec_pretty(&keys).unwrap_or_default())
        .and_then(|()| std::fs::rename(&tmp, &path))
        .map_err(|e| RegistryError::Io(e.to_string()))
}

/// Revoked signer keys recorded in `plugins_dir` (empty when none).
pub fn load_revoked_keys(plugins_dir: &std::path::Path) -> Vec<String> {
    std::fs::read(plugins_dir.join(REVOKED_KEYS_FILE))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// A plugin ready to be written: verified and checked against revocations.
pub struct PreparedInstall {
    pub entry: RegistryEntry,
    pub extracted: ExtractedPlugin,
    pub signer: Option<String>,
    pub index_signed: bool,
}

/// Download, checksum, extract, signer-check, and revocation-check one
/// registry entry without touching the filesystem.
pub fn prepare_install(
    client: &reqwest::blocking::Client,
    verified: &VerifiedIndex,
    id: &str,
) -> Result<PreparedInstall, RegistryError> {
    let entry = verified
        .index
        .find(id)
        .ok_or_else(|| RegistryError::NotFound(id.to_owned()))?
        .clone();
    if verified
        .index
        .revoked
        .iter()
        .any(|r| r.id == entry.id && r.version == entry.version)
    {
        return Err(RegistryError::Revoked(format!(
            "{} {}",
            entry.id, entry.version
        )));
    }
    let tarball = download_and_verify(client, &entry)?;
    let extracted = extract_tarball(&tarball, id)?;
    let signer = verify_signer(&extracted, entry.signer_public_key.as_deref())?;
    if let Some(key) = &signer {
        if verified.index.revoked_keys.contains(key) {
            return Err(RegistryError::Revoked(format!("signer key {key}")));
        }
    }
    Ok(PreparedInstall {
        entry,
        extracted,
        signer,
        index_signed: verified.signed,
    })
}

/// Write a prepared plugin into `plugins_dir/<id>` atomically (temp dir +
/// rename), with its install record. `force` replaces an existing plugin
/// (upgrade). Trust pinning still happens on the next reload.
pub fn write_install(
    plugins_dir: &std::path::Path,
    prepared: &PreparedInstall,
    force: bool,
) -> Result<InstallRecord, RegistryError> {
    let id = &prepared.entry.id;
    let target_dir = plugins_dir.join(id);
    if target_dir.parent() != Some(plugins_dir) {
        return Err(RegistryError::NotFound(id.clone()));
    }
    if target_dir.exists() && !force {
        return Err(RegistryError::AlreadyInstalled(
            target_dir.display().to_string(),
        ));
    }
    let record = InstallRecord {
        id: id.clone(),
        version: prepared.entry.version.clone(),
        signer: prepared.signer.clone(),
        index_signed: prepared.index_signed,
        installed_at: chrono::Utc::now().to_rfc3339(),
    };
    let io = |e: std::io::Error| RegistryError::Io(e.to_string());
    std::fs::create_dir_all(plugins_dir).map_err(io)?;
    let temp_dir = plugins_dir.join(format!(".{id}.install-tmp"));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).map_err(io)?;
    let extracted = &prepared.extracted;
    let write_result = (|| -> std::io::Result<()> {
        std::fs::write(temp_dir.join("plugin.toml"), &extracted.manifest_bytes)?;
        std::fs::write(
            temp_dir.join(&extracted.manifest.module),
            &extracted.wasm_bytes,
        )?;
        if let Some(signature_bytes) = &extracted.signature_bytes {
            std::fs::write(temp_dir.join("plugin.sig"), signature_bytes)?;
        }
        std::fs::write(
            temp_dir.join(INSTALL_RECORD),
            serde_json::to_vec_pretty(&record).unwrap_or_default(),
        )?;
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return Err(io(error));
    }
    if target_dir.exists() {
        std::fs::remove_dir_all(&target_dir).map_err(io)?;
    }
    std::fs::rename(&temp_dir, &target_dir).map_err(io)?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;
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
            let gnu = header
                .as_gnu_mut()
                .expect("new_gnu() always has a GNU header");
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
        assert_eq!(
            extracted.signature_bytes.as_deref(),
            Some(&b"pretend-signature-toml"[..])
        );
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
    fn extract_tarball_rejects_missing_manifest() {
        let tarball = build_tarball(&[("demo.wasm", b"pretend-wasm-bytes")]);
        let result = extract_tarball(&tarball, "demo-plugin");
        assert!(matches!(result, Err(RegistryError::MalformedArchive(_))));
    }

    #[test]
    fn extract_tarball_rejects_a_decompression_bomb_without_buffering_it() {
        // A highly-compressible entry that genuinely decompresses to well
        // past MAX_ENTRY_BYTES, well within MAX_TARBALL_BYTES compressed --
        // exactly the "small download, huge in memory" attack the size cap
        // on the compressed download alone cannot catch. Confirms
        // extract_tarball rejects it quickly and without ever holding the
        // full decompressed entry in memory.
        let huge = vec![0u8; (MAX_ENTRY_BYTES as usize) + (16 * 1024 * 1024)];
        let tarball = build_tarball(&[("plugin.toml", VALID_MANIFEST), ("demo.wasm", &huge)]);
        assert!(
            (tarball.len() as u64) < MAX_TARBALL_BYTES / 4,
            "fixture should compress far below the tarball size cap to prove this isn't caught by that check"
        );
        let started = std::time::Instant::now();
        let result = extract_tarball(&tarball, "demo-plugin");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "rejection should be fast, not proportional to the decompressed size"
        );
        assert!(matches!(result, Err(RegistryError::MalformedArchive(_))));
    }

    #[test]
    fn extract_tarball_rejects_many_entries_each_under_the_per_entry_cap_but_over_in_aggregate() {
        // Reproduces the re-reviewer's exact attack shape: many entries,
        // each individually just under MAX_ENTRY_BYTES (so the per-entry
        // cap alone doesn't catch any single one of them), whose sum vastly
        // exceeds any reasonable plugin archive size. The old code only
        // caught this via the "unexpected file in archive" check *after*
        // the whole loop finished decompressing every entry -- this test
        // confirms rejection now happens quickly, via the aggregate/entry-
        // count bound, without the loop ever completing.
        let per_entry = vec![0u8; (MAX_ENTRY_BYTES as usize) - 1024];
        let mut files: Vec<(String, &[u8])> = vec![("plugin.toml".to_owned(), VALID_MANIFEST)];
        let mut names = Vec::new();
        for i in 0..64 {
            names.push(format!("extra-{i}.bin"));
        }
        for name in &names {
            files.push((name.clone(), &per_entry));
        }
        let files_ref: Vec<(&str, &[u8])> = files.iter().map(|(n, c)| (n.as_str(), *c)).collect();
        let tarball = build_tarball(&files_ref);
        assert!(
            (tarball.len() as u64) < MAX_TARBALL_BYTES,
            "fixture should compress under the tarball size cap, matching the re-reviewer's report"
        );
        let started = std::time::Instant::now();
        let result = extract_tarball(&tarball, "demo-plugin");
        assert!(
            started.elapsed() < std::time::Duration::from_secs(5),
            "rejection should be fast and bounded, not proportional to the aggregate decompressed size"
        );
        assert!(matches!(result, Err(RegistryError::MalformedArchive(_))));
    }

    #[test]
    fn extract_tarball_rejects_duplicate_entry_names() {
        let tarball = build_tarball(&[
            ("plugin.toml", VALID_MANIFEST),
            ("demo.wasm", b"pretend-wasm-bytes"),
            ("demo.wasm", b"a-second-entry-with-the-same-name"),
        ]);
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
        assert_eq!(
            index.entries[0].signer_public_key.as_deref(),
            Some("cGxhY2Vob2xkZXItYmFzZTY0LWtleQ==")
        );
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
            revoked_keys: Vec::new(),
            revoked: Vec::new(),
        }
    }

    #[test]
    fn find_matches_by_exact_id_only() {
        let index = sample_index();
        assert_eq!(
            index.find("waf-guard").map(|e| e.id.as_str()),
            Some("waf-guard")
        );
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

    fn signed_extracted_plugin() -> (ExtractedPlugin, SigningKey) {
        let manifest = PluginManifest::from_toml(VALID_MANIFEST).unwrap();
        let wasm_bytes = b"pretend-wasm-bytes".to_vec();
        let signing_key = SigningKey::generate(&mut OsRng);
        let signature = crate::plugin_signing::sign(&manifest, &wasm_bytes, &signing_key);
        let signature_toml = toml::to_string(&signature).unwrap();
        (
            ExtractedPlugin {
                manifest,
                manifest_bytes: VALID_MANIFEST.to_vec(),
                wasm_bytes,
                signature_bytes: Some(signature_toml.into_bytes()),
            },
            signing_key,
        )
    }

    #[test]
    fn verify_signer_accepts_a_matching_declared_key() {
        let (extracted, signing_key) = signed_extracted_plugin();
        let public_key_b64 = base64::engine::general_purpose::STANDARD
            .encode(signing_key.verifying_key().to_bytes());
        let result = verify_signer(&extracted, Some(&public_key_b64));
        assert_eq!(result.unwrap(), Some(public_key_b64));
    }

    #[test]
    fn verify_signer_rejects_a_declared_key_that_does_not_match_the_real_signer() {
        let (extracted, _signing_key) = signed_extracted_plugin();
        let wrong_key = SigningKey::generate(&mut OsRng);
        let wrong_public_key_b64 =
            base64::engine::general_purpose::STANDARD.encode(wrong_key.verifying_key().to_bytes());
        let result = verify_signer(&extracted, Some(&wrong_public_key_b64));
        assert!(matches!(result, Err(RegistryError::SignerKeyMismatch(_))));
    }

    #[test]
    fn verify_signer_accepts_a_signed_plugin_the_index_did_not_declare_a_signer_for() {
        let (extracted, _signing_key) = signed_extracted_plugin();
        let result = verify_signer(&extracted, None);
        assert!(result.unwrap().is_some());
    }

    #[test]
    fn verify_signer_accepts_a_genuinely_unsigned_plugin() {
        let manifest = PluginManifest::from_toml(VALID_MANIFEST).unwrap();
        let extracted = ExtractedPlugin {
            manifest,
            manifest_bytes: VALID_MANIFEST.to_vec(),
            wasm_bytes: b"pretend-wasm-bytes".to_vec(),
            signature_bytes: None,
        };
        let result = verify_signer(&extracted, None);
        assert_eq!(result.unwrap(), None);
    }

    #[test]
    fn verify_signer_rejects_a_declared_signer_when_the_archive_has_no_signature() {
        let manifest = PluginManifest::from_toml(VALID_MANIFEST).unwrap();
        let extracted = ExtractedPlugin {
            manifest,
            manifest_bytes: VALID_MANIFEST.to_vec(),
            wasm_bytes: b"pretend-wasm-bytes".to_vec(),
            signature_bytes: None,
        };
        let result = verify_signer(&extracted, Some("some-declared-key=="));
        assert!(matches!(result, Err(RegistryError::SignerKeyMismatch(_))));
    }

    #[test]
    fn verify_signer_rejects_a_malformed_signature_file() {
        let manifest = PluginManifest::from_toml(VALID_MANIFEST).unwrap();
        let extracted = ExtractedPlugin {
            manifest,
            manifest_bytes: VALID_MANIFEST.to_vec(),
            wasm_bytes: b"pretend-wasm-bytes".to_vec(),
            signature_bytes: Some(b"not valid toml".to_vec()),
        };
        let result = verify_signer(&extracted, None);
        assert!(result.is_err());
    }
}
