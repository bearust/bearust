//! Secure manifest parsing and path validation for WASM plugins.
use crate::config::PluginConfig;
use crate::control_plane::realtime::RealtimeHub;
use crate::observability::PluginMetrics;
use arc_swap::ArcSwap;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
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
            max_fuel: 1_000_000_000,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PluginError {
    InvalidManifest,
    AbiMismatch,
    Disabled,
    Timeout,
    FuelExhausted,
    MemoryLimit,
    Trap,
    CompileFailed,
    NotFound,
    DuplicateId,
    MaxPlugins,
    Io,
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
            Self::NotFound => "not_found",
            Self::DuplicateId => "duplicate_id",
            Self::MaxPlugins => "max_plugins",
            Self::Io => "io_error",
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
    let timed_out = started.elapsed() >= Duration::from_millis(limits.invocation_timeout_ms);
    if let Some(trap) = error.downcast_ref::<wasmtime::Trap>() {
        return match trap {
            wasmtime::Trap::OutOfFuel if timed_out => PluginError::Timeout,
            wasmtime::Trap::OutOfFuel => PluginError::FuelExhausted,
            wasmtime::Trap::Interrupt => PluginError::Timeout,
            wasmtime::Trap::MemoryOutOfBounds
            | wasmtime::Trap::AllocationTooLarge
            | wasmtime::Trap::TableOutOfBounds
            | wasmtime::Trap::ArrayOutOfBounds => PluginError::MemoryLimit,
            _ => PluginError::Trap,
        };
    }
    if timed_out {
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

/// Redacted, stable lifecycle information exposed to the control plane.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginStatus {
    pub id: String,
    pub display_name: String,
    pub abi_version: u32,
    pub digest: String,
    pub enabled: bool,
    pub loaded: bool,
    pub last_error_code: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadSummary {
    pub loaded: usize,
    pub failed: usize,
}

/// Redacted, bounded metadata for a plugin lifecycle audit record. The
/// constructor is the single boundary for values that may reach an audit
/// sink; arbitrary paths, digests, and runtime strings are discarded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginAuditEvent {
    plugin_id: String,
    operation: String,
    outcome: String,
    error_code: Option<String>,
}

impl PluginAuditEvent {
    pub fn new(plugin_id: &str, operation: &str, outcome: &str, error_code: Option<&str>) -> Self {
        Self {
            plugin_id: sanitize_plugin_id(plugin_id),
            operation: sanitize_operation(operation),
            outcome: sanitize_outcome(outcome),
            error_code: error_code.and_then(sanitize_error_code),
        }
    }

    pub fn plugin_id(&self) -> &str {
        &self.plugin_id
    }

    pub fn operation(&self) -> &str {
        &self.operation
    }

    pub fn outcome(&self) -> &str {
        &self.outcome
    }

    pub fn error_code(&self) -> Option<&str> {
        self.error_code.as_deref()
    }
}

pub trait PluginAuditSink: Send + Sync {
    fn record(&self, event: &PluginAuditEvent);
}

fn sanitize_plugin_id(value: &str) -> String {
    if value.is_empty()
        || value.len() > MAX_ID_LEN
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("--")
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        "unavailable".to_owned()
    } else {
        value.to_owned()
    }
}

fn sanitize_operation(value: &str) -> String {
    match value {
        "reload" | "enable" | "disable" | "unload" | "health_check" => value.to_owned(),
        _ => "unknown".to_owned(),
    }
}

fn sanitize_outcome(value: &str) -> String {
    match value {
        "success" | "failure" => value.to_owned(),
        _ => "failure".to_owned(),
    }
}

fn sanitize_error_code(value: &str) -> Option<String> {
    let safe = matches!(
        value,
        "invalid_manifest"
            | "abi_mismatch"
            | "disabled"
            | "timeout"
            | "fuel_exhausted"
            | "memory_limit"
            | "trap"
            | "compile_failed"
            | "not_found"
            | "duplicate_id"
            | "max_plugins"
            | "io_error"
            | "partial_failure"
    );
    safe.then(|| value.to_owned())
}

struct PluginRecord {
    status: PluginStatus,
    compiled: Option<Arc<CompiledPlugin>>,
    source_dir: PathBuf,
}

struct PluginSnapshot {
    plugins: BTreeMap<String, Arc<PluginRecord>>,
}

impl PluginSnapshot {
    fn empty() -> Self {
        Self {
            plugins: BTreeMap::new(),
        }
    }
}

/// Owns plugin compilation and publishes complete immutable snapshots.
/// Reads only clone an `Arc`, so an invocation is never affected by a later
/// reload, disable, or unload operation.
pub struct PluginManager {
    config: PluginConfig,
    policy: PluginPolicy,
    engine: Mutex<Option<Arc<PluginEngine>>>,
    current: ArcSwap<PluginSnapshot>,
    reload_lock: Mutex<()>,
    // Diagnostics are tied to the loaded module digest.  An invocation from
    // an old ArcSwap snapshot must never overwrite diagnostics for a newer
    // module with the same plugin ID.
    last_errors: Mutex<BTreeMap<String, (String, String)>>,
    metrics: Arc<PluginMetrics>,
    realtime: Mutex<Option<Arc<RealtimeHub>>>,
    audit_sink: Mutex<Option<Arc<dyn PluginAuditSink>>>,
}

impl PluginManager {
    pub fn new(config: PluginConfig) -> Arc<Self> {
        let policy = PluginPolicy {
            max_module_bytes: config.max_module_bytes,
            max_memory_pages: config.max_memory_pages,
            max_fuel: config.max_fuel,
            max_invocation_timeout_ms: config.invocation_timeout_ms,
            max_output_bytes: config.max_output_bytes,
            module_root: config.directory.clone(),
        };
        Arc::new(Self {
            config,
            policy,
            engine: Mutex::new(None),
            current: ArcSwap::from_pointee(PluginSnapshot::empty()),
            reload_lock: Mutex::new(()),
            last_errors: Mutex::new(BTreeMap::new()),
            metrics: Arc::new(PluginMetrics::default()),
            realtime: Mutex::new(None),
            audit_sink: Mutex::new(None),
        })
    }

    /// Attach the bounded control-plane event sink. The sink is optional so
    /// standalone runtime users do not need a control-plane dependency.
    pub fn attach_realtime(&self, realtime: Arc<RealtimeHub>) {
        if let Ok(mut sink) = self.realtime.lock() {
            *sink = Some(realtime);
        }
    }

    pub fn metrics(&self) -> Arc<PluginMetrics> {
        Arc::clone(&self.metrics)
    }

    pub fn attach_audit_sink(&self, sink: Arc<dyn PluginAuditSink>) {
        if let Ok(mut current) = self.audit_sink.lock() {
            *current = Some(sink);
        }
    }

    fn record_operation(&self, operation: &str, outcome: &str) {
        self.metrics.record_operation(operation, outcome);
    }

    fn publish_changed(&self) {
        if let Ok(sink) = self.realtime.lock() {
            if let Some(realtime) = sink.as_ref() {
                realtime.publish("plugins.changed");
            }
        }
    }

    fn record_audit(
        &self,
        plugin_id: &str,
        operation: &str,
        outcome: &str,
        error_code: Option<&str>,
    ) {
        let event = PluginAuditEvent::new(plugin_id, operation, outcome, error_code);
        if let Ok(sink) = self.audit_sink.lock() {
            if let Some(sink) = sink.as_ref() {
                sink.record(&event);
            }
        }
    }

    fn update_loaded_metric(&self) {
        let loaded = self
            .current
            .load_full()
            .plugins
            .values()
            .filter(|record| record.status.loaded)
            .count();
        self.metrics.set_loaded(loaded);
    }

    fn engine(&self) -> Result<Arc<PluginEngine>, PluginError> {
        let mut guard = self.engine.lock().map_err(|_| PluginError::CompileFailed)?;
        if let Some(engine) = guard.as_ref() {
            return Ok(Arc::clone(engine));
        }
        let engine = Arc::new(PluginEngine::new(self.policy.clone())?);
        *guard = Some(Arc::clone(&engine));
        Ok(engine)
    }

    pub fn reload_from_disk(&self) -> Result<ReloadSummary, PluginError> {
        self.reload_from_disk_impl(true)
    }

    /// API handlers use this variant when they persist an actor-aware audit
    /// row themselves. Metrics and realtime invalidation remain unchanged.
    pub(crate) fn reload_from_disk_without_audit(&self) -> Result<ReloadSummary, PluginError> {
        self.reload_from_disk_impl(false)
    }

    fn reload_from_disk_impl(&self, emit_audit: bool) -> Result<ReloadSummary, PluginError> {
        let result = self.reload_from_disk_inner();
        self.update_loaded_metric();
        match &result {
            Ok(summary) => {
                let outcome = if summary.failed == 0 {
                    "success"
                } else {
                    "failure"
                };
                self.record_operation("reload", outcome);
                if emit_audit {
                    self.record_audit(
                        "all",
                        "reload",
                        outcome,
                        (summary.failed > 0).then_some("partial_failure"),
                    );
                }
                // reload_from_disk_inner publishes the ArcSwap snapshot before
                // returning, even for a partial reload. This invalidation is
                // therefore emitted only after an atomic publication.
                self.publish_changed();
            }
            Err(error) => {
                self.record_operation("reload", "failure");
                if emit_audit {
                    self.record_audit("all", "reload", "failure", Some(error.code()));
                }
            }
        }
        result
    }

    fn reload_from_disk_inner(&self) -> Result<ReloadSummary, PluginError> {
        let _guard = self
            .reload_lock
            .lock()
            .map_err(|_| PluginError::CompileFailed)?;
        if !self.config.enabled {
            self.current.store(Arc::new(PluginSnapshot::empty()));
            return Ok(ReloadSummary::default());
        }

        let directory = &self.config.directory;
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.current.store(Arc::new(PluginSnapshot::empty()));
                return Ok(ReloadSummary::default());
            }
            Err(_) => return Err(PluginError::Io),
        };
        let mut children = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|_| PluginError::Io)?;
            if entry.file_type().map_err(|_| PluginError::Io)?.is_dir() {
                if children.len() >= self.config.max_plugins {
                    return Err(PluginError::MaxPlugins);
                }
                children.push(entry);
            }
        }
        children.sort_by_key(|entry| entry.file_name());

        let previous = self.current.load_full();
        let engine = self.engine()?;
        let mut candidate = BTreeMap::new();
        let mut seen_ids = BTreeSet::new();
        let mut summary = ReloadSummary::default();
        let mut fatal_existing_failure = false;

        for child in children {
            let manifest_path = child.path().join("plugin.toml");
            let manifest = match fs::metadata(&manifest_path)
                .map_err(|_| PluginError::Io)
                .and_then(|metadata| {
                    if metadata.len() > MAX_MANIFEST_BYTES as u64 {
                        Err(PluginError::InvalidManifest)
                    } else {
                        fs::read(&manifest_path).map_err(|_| PluginError::Io)
                    }
                })
                .and_then(|bytes| PluginManifest::from_toml(&bytes))
            {
                Ok(manifest) => manifest,
                Err(_) => {
                    summary.failed += 1;
                    // Plugin directories are conventionally named by ID. If
                    // a previously loaded directory becomes malformed, retain
                    // its immutable record for this candidate snapshot.
                    if let Some((old_id, old)) = previous
                        .plugins
                        .iter()
                        .find(|(_, record)| record.source_dir == child.path())
                    {
                        candidate.insert(old_id.clone(), Arc::clone(old));
                        fatal_existing_failure = true;
                    } else {
                        let mut safe_id = child
                            .file_name()
                            .to_string_lossy()
                            .chars()
                            .map(|ch| {
                                if ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' {
                                    ch
                                } else {
                                    '-'
                                }
                            })
                            .take(MAX_ID_LEN)
                            .collect::<String>();
                        while safe_id.ends_with('-') {
                            safe_id.pop();
                        }
                        if safe_id.is_empty() {
                            safe_id = "unavailable".to_owned();
                        }
                        if !candidate.contains_key(&safe_id) {
                            candidate.insert(
                                safe_id.clone(),
                                Arc::new(PluginRecord {
                                    status: PluginStatus {
                                        id: safe_id,
                                        display_name: String::new(),
                                        abi_version: 0,
                                        digest: String::new(),
                                        enabled: false,
                                        loaded: false,
                                        last_error_code: Some("invalid_manifest".to_owned()),
                                    },
                                    compiled: None,
                                    source_dir: child.path(),
                                }),
                            );
                        }
                    }
                    continue;
                }
            };
            let id = manifest.id.clone();
            if !seen_ids.insert(id.clone()) {
                return Err(PluginError::DuplicateId);
            }
            let old = previous.plugins.get(&id);
            let build = (|| {
                let mut policy = self.policy.clone();
                policy.module_root = child.path();
                let validated = manifest.validate(&policy)?;
                let metadata =
                    fs::metadata(&validated.module).map_err(|_| PluginError::InvalidManifest)?;
                if metadata.len() > policy.max_module_bytes as u64 {
                    return Err(PluginError::InvalidManifest);
                }
                let bytes =
                    fs::read(&validated.module).map_err(|_| PluginError::InvalidManifest)?;
                let digest = module_digest(&bytes);
                let compiled = engine.compile(validated.clone(), &bytes)?;
                Ok::<_, PluginError>((validated, digest, Arc::new(compiled)))
            })();
            match build {
                Ok((validated, digest, compiled)) => {
                    if candidate.contains_key(&validated.id) {
                        return Err(PluginError::DuplicateId);
                    }
                    let enabled = old
                        .map(|record| {
                            if record.compiled.is_some() {
                                record.status.enabled
                            } else {
                                // An unavailable record is not an explicit
                                // operator disable; a repaired module may
                                // become active on the next reload.
                                true
                            }
                        })
                        .unwrap_or(true);
                    candidate.insert(
                        validated.id.clone(),
                        Arc::new(PluginRecord {
                            status: PluginStatus {
                                id: validated.id,
                                display_name: validated.display_name,
                                abi_version: validated.abi_version,
                                digest,
                                enabled,
                                loaded: true,
                                last_error_code: None,
                            },
                            compiled: Some(compiled),
                            source_dir: child.path(),
                        }),
                    );
                    summary.loaded += 1;
                }
                Err(error) => {
                    summary.failed += 1;
                    if let Some(old) = old {
                        // A failed replacement must not take a healthy
                        // previously published instance out of service.
                        candidate.insert(id, Arc::clone(old));
                        fatal_existing_failure = true;
                    } else if !candidate.contains_key(&id) {
                        let safe_id = id.chars().take(MAX_ID_LEN).collect::<String>();
                        let safe_display_name = manifest
                            .display_name
                            .chars()
                            .take(MAX_DISPLAY_NAME_LEN)
                            .collect::<String>();
                        candidate.insert(
                            safe_id.clone(),
                            Arc::new(PluginRecord {
                                status: PluginStatus {
                                    id: safe_id,
                                    display_name: safe_display_name,
                                    abi_version: manifest.abi_version,
                                    digest: String::new(),
                                    enabled: false,
                                    loaded: false,
                                    last_error_code: Some(error.code().to_string()),
                                },
                                compiled: None,
                                source_dir: child.path(),
                            }),
                        );
                    }
                }
            }
        }
        if fatal_existing_failure {
            return Err(PluginError::CompileFailed);
        }
        if let Ok(mut errors) = self.last_errors.lock() {
            let current_digests = candidate
                .iter()
                .filter(|(_, record)| record.status.loaded)
                .map(|(id, record)| (id.clone(), record.status.digest.clone()))
                .collect::<BTreeMap<_, _>>();
            errors.retain(|id, _| {
                candidate.get(id).is_some_and(|record| {
                    !record.status.loaded
                        || current_digests
                            .get(id)
                            .is_some_and(|digest| digest == &record.status.digest)
                })
            });
        }
        self.current
            .store(Arc::new(PluginSnapshot { plugins: candidate }));
        Ok(summary)
    }

    pub fn set_enabled(&self, id: &str, enabled: bool) -> Result<PluginStatus, PluginError> {
        self.set_enabled_impl(id, enabled, true)
    }

    pub(crate) fn set_enabled_without_audit(
        &self,
        id: &str,
        enabled: bool,
    ) -> Result<PluginStatus, PluginError> {
        self.set_enabled_impl(id, enabled, false)
    }

    fn set_enabled_impl(
        &self,
        id: &str,
        enabled: bool,
        emit_audit: bool,
    ) -> Result<PluginStatus, PluginError> {
        let operation = if enabled { "enable" } else { "disable" };
        let result = self.set_enabled_inner(id, enabled);
        match &result {
            Ok(_) => {
                self.record_operation(operation, "success");
                if emit_audit {
                    self.record_audit(id, operation, "success", None);
                }
                self.update_loaded_metric();
                self.publish_changed();
            }
            Err(error) => {
                self.record_operation(operation, "failure");
                if emit_audit {
                    self.record_audit(id, operation, "failure", Some(error.code()));
                }
            }
        }
        result
    }

    fn set_enabled_inner(&self, id: &str, enabled: bool) -> Result<PluginStatus, PluginError> {
        let _guard = self
            .reload_lock
            .lock()
            .map_err(|_| PluginError::CompileFailed)?;
        let snapshot = self.current.load_full();
        let record = snapshot.plugins.get(id).ok_or(PluginError::NotFound)?;
        if enabled && record.compiled.is_none() {
            return Err(PluginError::InvalidManifest);
        }
        let mut candidate = snapshot
            .plugins
            .iter()
            .map(|(key, value)| (key.clone(), Arc::clone(value)))
            .collect::<BTreeMap<_, _>>();
        let mut status = record.status.clone();
        status.enabled = enabled;
        if let Ok(errors) = self.last_errors.lock() {
            status.last_error_code = errors
                .get(id)
                .filter(|(digest, _)| digest == &status.digest)
                .map(|(_, error)| error.clone())
                .or(status.last_error_code);
        }
        candidate.insert(
            id.to_owned(),
            Arc::new(PluginRecord {
                status: status.clone(),
                compiled: record.compiled.clone(),
                source_dir: record.source_dir.clone(),
            }),
        );
        self.current
            .store(Arc::new(PluginSnapshot { plugins: candidate }));
        Ok(status)
    }

    pub fn unload(&self, id: &str) -> Result<(), PluginError> {
        self.unload_impl(id, true)
    }

    pub(crate) fn unload_without_audit(&self, id: &str) -> Result<(), PluginError> {
        self.unload_impl(id, false)
    }

    fn unload_impl(&self, id: &str, emit_audit: bool) -> Result<(), PluginError> {
        let result = self.unload_inner(id);
        match &result {
            Ok(()) => {
                self.record_operation("unload", "success");
                if emit_audit {
                    self.record_audit(id, "unload", "success", None);
                }
                self.update_loaded_metric();
                self.publish_changed();
            }
            Err(error) => {
                self.record_operation("unload", "failure");
                if emit_audit {
                    self.record_audit(id, "unload", "failure", Some(error.code()));
                }
            }
        }
        result
    }

    fn unload_inner(&self, id: &str) -> Result<(), PluginError> {
        let _guard = self
            .reload_lock
            .lock()
            .map_err(|_| PluginError::CompileFailed)?;
        let snapshot = self.current.load_full();
        if !snapshot.plugins.contains_key(id) {
            return Err(PluginError::NotFound);
        }
        let mut candidate = snapshot
            .plugins
            .iter()
            .filter(|(key, _)| key.as_str() != id)
            .map(|(key, value)| (key.clone(), Arc::clone(value)))
            .collect::<BTreeMap<_, _>>();
        self.current.store(Arc::new(PluginSnapshot {
            plugins: std::mem::take(&mut candidate),
        }));
        if let Ok(mut errors) = self.last_errors.lock() {
            errors.remove(id);
        }
        Ok(())
    }

    pub fn list(&self) -> Vec<PluginStatus> {
        let errors = self.last_errors.lock().ok();
        self.current
            .load_full()
            .plugins
            .values()
            .map(|record| {
                let mut status = record.status.clone();
                if let Some(errors) = errors.as_ref() {
                    if let Some((digest, error)) = errors.get(&status.id) {
                        if digest == &status.digest {
                            status.last_error_code = Some(error.clone());
                        }
                    }
                }
                status
            })
            .collect()
    }

    pub fn health_check(&self, id: &str) -> Result<HealthResult, PluginError> {
        self.health_check_impl(id, true)
    }

    pub(crate) fn health_check_without_audit(&self, id: &str) -> Result<HealthResult, PluginError> {
        self.health_check_impl(id, false)
    }

    fn health_check_impl(&self, id: &str, emit_audit: bool) -> Result<HealthResult, PluginError> {
        let result = self.health_check_inner(id);
        self.record_operation(
            "health_check",
            if result.is_ok() { "success" } else { "failure" },
        );
        if emit_audit {
            self.record_audit(
                id,
                "health_check",
                if result.is_ok() { "success" } else { "failure" },
                result.as_ref().err().map(PluginError::code),
            );
        }
        result
    }

    fn health_check_inner(&self, id: &str) -> Result<HealthResult, PluginError> {
        let snapshot = self.current.load_full();
        let record = snapshot.plugins.get(id).ok_or(PluginError::NotFound)?;
        let digest = record.status.digest.clone();
        if !record.status.enabled {
            return Err(PluginError::Disabled);
        }
        let result = record
            .compiled
            .as_ref()
            .ok_or(PluginError::InvalidManifest)?
            .health_check();
        if let Err(error) = &result {
            let current_snapshot = self.current.load_full();
            if let Some(current) = current_snapshot.plugins.get(id) {
                if current.status.digest == digest {
                    if let Ok(mut errors) = self.last_errors.lock() {
                        errors.insert(id.to_owned(), (digest.clone(), error.code().to_string()));
                    }
                }
            }
        } else {
            let current_snapshot = self.current.load_full();
            if let Some(current) = current_snapshot.plugins.get(id) {
                if current.status.digest == digest {
                    if let Ok(mut errors) = self.last_errors.lock() {
                        errors.remove(id);
                    }
                }
            }
        }
        result
    }
}
