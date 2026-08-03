//! Secure manifest parsing and path validation for WASM plugins.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
};

pub const SUPPORTED_ABI_VERSION: u32 = 1;
pub const MAX_ID_LEN: usize = 64;
pub const MAX_DISPLAY_NAME_LEN: usize = 128;
pub const MAX_MODULE_NAME_LEN: usize = 128;
pub const MAX_CAPABILITY_LEN: usize = 64;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    pub id: String,
    pub display_name: String,
    pub abi_version: u32,
    pub module: String,
    #[serde(default)]
    pub capabilities: Vec<String>,
    #[serde(default)]
    pub limits: PluginLimits,
}

#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct PluginLimits {
    #[serde(default = "default_memory_pages")]
    pub memory_pages: u32,
    #[serde(default = "default_fuel")]
    pub fuel: u64,
    #[serde(default = "default_timeout_ms")]
    pub invocation_timeout_ms: u64,
    #[serde(default = "default_output_bytes")]
    pub max_output_bytes: usize,
}

fn default_memory_pages() -> u32 {
    256
}
fn default_fuel() -> u64 {
    10_000_000
}
fn default_timeout_ms() -> u64 {
    1_000
}
fn default_output_bytes() -> usize {
    64 * 1024
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginPolicy {
    pub max_memory_pages: u32,
    pub max_fuel: u64,
    pub max_invocation_timeout_ms: u64,
    pub max_output_bytes: usize,
    pub module_root: PathBuf,
}
impl Default for PluginPolicy {
    fn default() -> Self {
        Self {
            max_memory_pages: 256,
            max_fuel: 10_000_000,
            max_invocation_timeout_ms: 1_000,
            max_output_bytes: 64 * 1024,
            module_root: PathBuf::from("."),
        }
    }
}

#[derive(Debug, Clone)]
pub struct ValidatedManifest {
    pub id: String,
    pub display_name: String,
    pub abi_version: u32,
    pub module: PathBuf,
    pub capabilities: Vec<String>,
    pub limits: PluginLimits,
}

#[derive(Debug)]
pub enum PluginError {
    InvalidManifest,
    AbiMismatch,
    Disabled,
    Timeout,
    FuelExhausted,
    MemoryLimit,
    Trap,
    CompileFailed,
}
impl PluginError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidManifest => "invalid_manifest",
            Self::AbiMismatch => "abi_mismatch",
            Self::Disabled => "disabled",
            Self::Timeout => "timeout",
            Self::FuelExhausted => "fuel_exhausted",
            Self::MemoryLimit => "memory_limit",
            Self::Trap => "trap",
            Self::CompileFailed => "compile_failed",
        }
    }
}
impl fmt::Display for PluginError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code())
    }
}
impl std::error::Error for PluginError {}

impl PluginManifest {
    pub fn from_toml(bytes: &[u8]) -> Result<Self, PluginError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(PluginError::InvalidManifest);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| PluginError::InvalidManifest)?;
        toml::from_str(text).map_err(|_| PluginError::InvalidManifest)
    }
    pub fn validate(&self, policy: &PluginPolicy) -> Result<ValidatedManifest, PluginError> {
        if self.id.is_empty() || self.id.len() > MAX_ID_LEN || !valid_id(&self.id) {
            return Err(PluginError::InvalidManifest);
        }
        if self.display_name.is_empty() || self.display_name.len() > MAX_DISPLAY_NAME_LEN {
            return Err(PluginError::InvalidManifest);
        }
        if self.module.is_empty() || self.module.len() > MAX_MODULE_NAME_LEN {
            return Err(PluginError::InvalidManifest);
        }
        if self.abi_version != SUPPORTED_ABI_VERSION {
            return Err(PluginError::AbiMismatch);
        }
        if self
            .capabilities
            .iter()
            .any(|c| c != "health_check" || c.len() > MAX_CAPABILITY_LEN)
        {
            return Err(PluginError::InvalidManifest);
        }
        let mut caps = self.capabilities.clone();
        caps.sort();
        caps.dedup();
        if caps.len() != self.capabilities.len() {
            return Err(PluginError::InvalidManifest);
        }
        if self.limits.memory_pages == 0
            || self.limits.memory_pages > policy.max_memory_pages
            || self.limits.fuel == 0
            || self.limits.fuel > policy.max_fuel
            || self.limits.invocation_timeout_ms == 0
            || self.limits.invocation_timeout_ms > policy.max_invocation_timeout_ms
            || self.limits.max_output_bytes == 0
            || self.limits.max_output_bytes > policy.max_output_bytes
        {
            return Err(PluginError::InvalidManifest);
        }
        let module = resolve_module_path(&policy.module_root, &self.module)?;
        Ok(ValidatedManifest {
            id: self.id.clone(),
            display_name: self.display_name.clone(),
            abi_version: self.abi_version,
            module,
            capabilities: self.capabilities.clone(),
            limits: self.limits.clone(),
        })
    }
}

fn valid_id(id: &str) -> bool {
    id.bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
        && !id.ends_with('-')
        && !id.contains("--")
}

pub fn resolve_module_path(root: &Path, relative: &str) -> Result<PathBuf, PluginError> {
    let rel = Path::new(relative);
    if relative.is_empty()
        || rel.is_absolute()
        || rel.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir
                    | std::path::Component::RootDir
                    | std::path::Component::Prefix(_)
            )
        })
    {
        return Err(PluginError::InvalidManifest);
    }
    let root = fs::canonicalize(root).map_err(|_| PluginError::InvalidManifest)?;
    let candidate = root.join(rel);
    let canonical = fs::canonicalize(&candidate).map_err(|_| PluginError::InvalidManifest)?;
    if !canonical.starts_with(&root) || !canonical.is_file() {
        return Err(PluginError::InvalidManifest);
    }
    Ok(canonical)
}

pub fn module_digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
