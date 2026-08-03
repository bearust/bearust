//! Secure manifest parsing and path validation for WASM plugins.
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fmt, fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    thread,
    time::{Duration, Instant},
};
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

pub const SUPPORTED_ABI_VERSION: u32 = 1;
pub const MAX_ID_LEN: usize = 64;
pub const MAX_DISPLAY_NAME_LEN: usize = 128;
pub const MAX_MODULE_NAME_LEN: usize = 128;
pub const MAX_CAPABILITY_LEN: usize = 64;
pub const MAX_MANIFEST_BYTES: usize = 64 * 1024;
const HEALTH_RESULT_BYTES: usize = std::mem::size_of::<i32>();
const EPOCH_TICK: Duration = Duration::from_millis(1);

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
    pub max_module_bytes: usize,
    pub max_memory_pages: u32,
    pub max_fuel: u64,
    pub max_invocation_timeout_ms: u64,
    pub max_output_bytes: usize,
    pub module_root: PathBuf,
}
impl Default for PluginPolicy {
    fn default() -> Self {
        Self {
            max_module_bytes: 16 * 1024 * 1024,
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

/// The bounded result returned by a plugin health invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthResult {
    pub status: i32,
    pub elapsed: Duration,
}

/// A Wasmtime engine configured for the plugin trust boundary.
///
/// The engine has fuel and epoch interruption enabled. No linker or host
/// imports are ever installed, so modules can only use core Wasm facilities.
pub struct PluginEngine {
    engine: Engine,
    policy: PluginPolicy,
    scheduler: Arc<EpochScheduler>,
}

struct EpochScheduler {
    stop: Arc<AtomicBool>,
    thread: Mutex<Option<thread::JoinHandle<()>>>,
}

impl EpochScheduler {
    fn start(engine: &Engine) -> Result<Arc<Self>, PluginError> {
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = Arc::clone(&stop);
        let thread_engine = engine.clone();
        let handle = thread::Builder::new()
            .name("bearust-plugin-epoch".into())
            .spawn(move || {
                while !thread_stop.load(Ordering::Acquire) {
                    thread::sleep(EPOCH_TICK);
                    if !thread_stop.load(Ordering::Acquire) {
                        thread_engine.increment_epoch();
                    }
                }
            })
            .map_err(|_| PluginError::CompileFailed)?;
        Ok(Arc::new(Self {
            stop,
            thread: Mutex::new(Some(handle)),
        }))
    }
}

impl Drop for EpochScheduler {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Ok(slot) = self.thread.get_mut() {
            if let Some(handle) = slot.take() {
                let _ = handle.join();
            }
        }
    }
}

struct StoreState {
    limits: StoreLimits,
}

/// A compiled, immutable plugin module. Each health check creates a fresh
/// store and instance, keeping invocation state isolated from later calls.
pub struct CompiledPlugin {
    engine: Engine,
    scheduler: Arc<EpochScheduler>,
    module: Module,
    limits: PluginLimits,
    has_health_check: bool,
}

impl PluginEngine {
    pub fn new(policy: PluginPolicy) -> Result<Self, PluginError> {
        if policy.max_module_bytes == 0
            || policy.max_memory_pages == 0
            || policy.max_fuel == 0
            || policy.max_invocation_timeout_ms == 0
            || policy.max_output_bytes == 0
        {
            return Err(PluginError::InvalidManifest);
        }
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config).map_err(|_| PluginError::CompileFailed)?;
        let scheduler = EpochScheduler::start(&engine)?;
        Ok(Self {
            engine,
            policy,
            scheduler,
        })
    }

    pub fn compile(
        &self,
        manifest: ValidatedManifest,
        module_bytes: &[u8],
    ) -> Result<CompiledPlugin, PluginError> {
        if manifest.abi_version != SUPPORTED_ABI_VERSION {
            return Err(PluginError::AbiMismatch);
        }
        if module_bytes.len() > self.policy.max_module_bytes {
            return Err(PluginError::InvalidManifest);
        }
        let module =
            Module::new(&self.engine, module_bytes).map_err(|_| PluginError::CompileFailed)?;

        // Instantiation with an empty import list rejects all host/WASI
        // imports and also catches malformed modules before publication.
        let limits = clamp_limits(&manifest.limits, &self.policy);
        if limits.memory_pages == 0
            || limits.fuel == 0
            || limits.invocation_timeout_ms == 0
            || limits.max_output_bytes < HEALTH_RESULT_BYTES
        {
            return Err(PluginError::InvalidManifest);
        }
        let mut store = new_store(&self.engine, &limits)?;
        store
            .set_fuel(limits.fuel)
            .map_err(|_| PluginError::FuelExhausted)?;
        store.set_epoch_deadline(epoch_ticks(limits.invocation_timeout_ms));
        let instance =
            Instance::new(&mut store, &module, &[]).map_err(|error| map_compile_error(&error))?;

        // get_typed_func enforces the exact () -> i32 ABI signature and maps
        // both missing and malformed exports to the stable ABI error.
        instance
            .get_typed_func::<(), i32>(&mut store, "bearust_abi_version")
            .map_err(|_| PluginError::AbiMismatch)?;
        let has_health_check =
            match instance.get_typed_func::<(), i32>(&mut store, "bearust_health_check") {
                Ok(_) => true,
                Err(_)
                    if instance
                        .get_export(&mut store, "bearust_health_check")
                        .is_none() =>
                {
                    false
                }
                Err(_) => return Err(PluginError::AbiMismatch),
            };

        Ok(CompiledPlugin {
            engine: self.engine.clone(),
            scheduler: Arc::clone(&self.scheduler),
            module,
            limits,
            has_health_check,
        })
    }
}

impl CompiledPlugin {
    pub fn health_check(&self) -> Result<HealthResult, PluginError> {
        let started = Instant::now();
        // Keep the scheduler alive for the duration of this invocation.
        let _scheduler = Arc::clone(&self.scheduler);
        let mut store = new_store(&self.engine, &self.limits)?;
        store
            .set_fuel(self.limits.fuel)
            .map_err(|_| PluginError::FuelExhausted)?;
        store.set_epoch_deadline(epoch_ticks(self.limits.invocation_timeout_ms));

        let result = (|| {
            let instance = Instance::new(&mut store, &self.module, &[])
                .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
            let abi = instance
                .get_typed_func::<(), i32>(&mut store, "bearust_abi_version")
                .map_err(|_| PluginError::AbiMismatch)?;
            let version = abi
                .call(&mut store, ())
                .map_err(|error| map_runtime_error(&error, started, &self.limits))?;
            if version != SUPPORTED_ABI_VERSION as i32 {
                return Err(PluginError::AbiMismatch);
            }
            if !self.has_health_check {
                return Ok(0);
            }
            let health = instance
                .get_typed_func::<(), i32>(&mut store, "bearust_health_check")
                .map_err(|_| PluginError::AbiMismatch)?;
            health
                .call(&mut store, ())
                .map_err(|error| map_runtime_error(&error, started, &self.limits))
        })();

        match result {
            Ok(status) => Ok(HealthResult {
                status,
                elapsed: started.elapsed(),
            }),
            Err(error) => Err(error),
        }
    }
}

fn clamp_limits(requested: &PluginLimits, policy: &PluginPolicy) -> PluginLimits {
    PluginLimits {
        memory_pages: requested.memory_pages.min(policy.max_memory_pages),
        fuel: requested.fuel.min(policy.max_fuel),
        invocation_timeout_ms: requested
            .invocation_timeout_ms
            .min(policy.max_invocation_timeout_ms),
        max_output_bytes: requested.max_output_bytes.min(policy.max_output_bytes),
    }
}

fn epoch_ticks(timeout_ms: u64) -> u64 {
    // The scheduler ticks once per millisecond; add one tick to avoid a zero
    // deadline for sub-tick values and to account for scheduler wake-up jitter.
    timeout_ms.saturating_add(1)
}

fn new_store(engine: &Engine, limits: &PluginLimits) -> Result<Store<StoreState>, PluginError> {
    let memory_size = (limits.memory_pages as usize)
        .checked_mul(64 * 1024)
        .ok_or(PluginError::MemoryLimit)?;
    let store_limits = StoreLimitsBuilder::new()
        .memory_size(memory_size)
        .memories(1)
        .instances(1)
        .tables(1)
        .table_elements(1024)
        // Turn failed memory.grow operations into a trap so a plugin cannot
        // silently continue after exceeding its declared server limit.
        .trap_on_grow_failure(true)
        .build();
    let mut store = Store::new(
        engine,
        StoreState {
            limits: store_limits,
        },
    );
    store.limiter(|state| &mut state.limits);
    Ok(store)
}

fn map_compile_error(error: &wasmtime::Error) -> PluginError {
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("memory") || text.contains("limit") {
        PluginError::MemoryLimit
    } else {
        PluginError::CompileFailed
    }
}

fn map_runtime_error(
    error: &wasmtime::Error,
    started: Instant,
    limits: &PluginLimits,
) -> PluginError {
    if started.elapsed() >= Duration::from_millis(limits.invocation_timeout_ms) {
        return PluginError::Timeout;
    }
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("fuel") || text.contains("out of fuel") {
        return PluginError::FuelExhausted;
    }
    if text.contains("memory") || text.contains("limit") {
        PluginError::MemoryLimit
    } else {
        PluginError::Trap
    }
}

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
            // The current ABI's only output is a four-byte i32; a smaller
            // declared cap cannot be enforced without changing that ABI.
            // HealthResult is currently represented by one i32 (four bytes).
            || self.limits.max_output_bytes < HEALTH_RESULT_BYTES
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
