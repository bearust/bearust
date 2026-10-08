use crate::rate_limit::{RateLimitKeyScope, RateLimitPolicy};
use crate::rate_limit_store::IpNetSet;
use crate::{
    certificates::RenewalScheduler,
    config, proxy,
    reload::{self, PidFileGuard},
    runtime::RuntimeStore,
};
use clap::{Parser, Subcommand};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use thiserror::Error;

/// Start certificate renewal outside the Pingora traffic path. The command
/// and API layer supplies the issuer in Phase 3; keeping this hook generic
/// avoids coupling startup to a CA account or DNS provider.
pub fn spawn_renewal_task(
    scheduler: RenewalScheduler,
    interval: Duration,
    stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(scheduler.run_forever(interval, stop))
}

#[derive(Debug, Parser)]
#[command(
    name = "bearust",
    version,
    about = "Configuration-driven reverse proxy and load balancer",
    long_about = "Bearust routes HTTP traffic to backend pools with health checks, TLS, ACME automation, and an authenticated control plane.\n\nStart with `bearust serve --config <file>`, validate a file without binding any port via `bearust validate`, or reload a running server with `bearust reload`."
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Start the proxy, control plane, and background tasks.
    Serve {
        /// Path to the TOML configuration file.
        #[arg(long, default_value = "bearust.toml")]
        config: PathBuf,
        /// Emit structured JSON logs instead of human-readable logs.
        #[arg(long, default_value_t = false)]
        json_logs: bool,
    },
    /// Validate a configuration file without opening any listener.
    Validate {
        /// Path to the TOML configuration file.
        #[arg(long, default_value = "bearust.toml")]
        config: PathBuf,
    },
    /// Send a graceful reload signal to a running server via its pid file.
    Reload {
        /// Path to the pid file written by `bearust serve`.
        #[arg(long, default_value = "./bearust.pid")]
        pid_file: PathBuf,
    },
    /// Manage optional WASM plugins (sign, search, and install).
    Plugin {
        #[command(subcommand)]
        action: PluginCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum PluginCommand {
    /// Generates a new Ed25519 signing keypair for signing plugins.
    Keygen {
        /// Directory where `signing.key` is written (refuses to overwrite).
        #[arg(long)]
        out: PathBuf,
    },
    /// Signs a plugin directory's manifest + wasm module, writing plugin.sig.
    Sign {
        /// Plugin directory containing `plugin.toml` and the wasm module.
        plugin_dir: PathBuf,
        /// Path to the Ed25519 private key created by `plugin keygen`.
        #[arg(long)]
        key: PathBuf,
    },
    /// Searches the plugin registry index for plugins matching a query.
    Search {
        /// Case-insensitive substring matched against id, name, and description.
        query: String,
        /// Registry index URL (overrides `BEARUST_PLUGIN_REGISTRY_URL`).
        #[arg(long)]
        registry_url: Option<String>,
    },
    /// Downloads, verifies, and installs a plugin from the registry index.
    Install {
        /// Plugin id as listed in the registry index.
        id: String,
        /// Plugins directory the new `<id>/` bundle is installed into.
        #[arg(long)]
        out: PathBuf,
        /// Skip the interactive confirmation prompt.
        #[arg(long, default_value_t = false)]
        yes: bool,
        /// Overwrite an already-installed plugin directory with the same id.
        #[arg(long, default_value_t = false)]
        force: bool,
        /// Registry index URL (overrides `BEARUST_PLUGIN_REGISTRY_URL`).
        #[arg(long)]
        registry_url: Option<String>,
    },
}

#[derive(Debug, Error)]
pub enum AppError {
    #[error(transparent)]
    Config(#[from] config::ConfigError),
    #[error(transparent)]
    Runtime(#[from] crate::runtime::RuntimeError),
    #[error(transparent)]
    Pid(#[from] reload::PidError),
    #[error("server error: {0}")]
    Server(String),
    #[error("plugin signing error: {0}")]
    PluginSigning(String),
    #[error("plugin registry error: {0}")]
    PluginRegistry(String),
}

pub fn run(cli: Cli) -> Result<(), AppError> {
    match cli.command {
        Command::Validate { config: path } => {
            config::load(&path)?;
            println!("configuration is valid");
            Ok(())
        }
        Command::Reload { pid_file } => {
            reload::signal_reload(pid_file)?;
            println!("reload signal sent");
            Ok(())
        }
        Command::Serve {
            config: path,
            json_logs,
        } => serve(path, json_logs),
        Command::Plugin { action } => plugin_command(action),
    }
}

fn serve(path: PathBuf, json_logs: bool) -> Result<(), AppError> {
    let config = config::load(&path)?;
    if std::env::var_os("BEARUST_PROXY_CHILD").is_none() {
        let _pid = PidFileGuard::acquire(&config.server.pid_file)?;
        return supervise_child(path, json_logs, config.server.graceful_shutdown_seconds);
    }
    serve_proxy(path, json_logs, config)
}

#[cfg(unix)]
fn supervise_child(
    path: PathBuf,
    json_logs: bool,
    graceful_shutdown_seconds: u64,
) -> Result<(), AppError> {
    use nix::{
        sys::signal::{kill, Signal},
        unistd::Pid,
    };
    let exe = std::env::current_exe().map_err(|e| AppError::Server(e.to_string()))?;
    let spawn_child = |upgrade: bool, ready_path: Option<&Path>| {
        let mut command = std::process::Command::new(&exe);
        command
            .env("BEARUST_PROXY_CHILD", "1")
            .env_remove("BEARUST_PROXY_UPGRADE")
            .args(["serve", "--config"])
            .arg(&path)
            .args(json_logs.then_some(["--json-logs"]).into_iter().flatten());
        if upgrade {
            command.env("BEARUST_PROXY_UPGRADE", "1");
            if let Some(ready_path) = ready_path {
                command.env("BEARUST_UPGRADE_READY", ready_path);
            }
        }
        command.spawn().map_err(|e| AppError::Server(e.to_string()))
    };
    let mut child = spawn_child(false, None)?;
    let mut signals = signal_hook::iterator::Signals::new([
        signal_hook::consts::SIGHUP,
        signal_hook::consts::SIGTERM,
        signal_hook::consts::SIGINT,
    ])
    .map_err(|e| AppError::Server(e.to_string()))?;
    for signal in signals.forever() {
        if child
            .try_wait()
            .map_err(|e| AppError::Server(e.to_string()))?
            .is_some()
        {
            break;
        }
        match signal {
            signal_hook::consts::SIGHUP => {
                // Pingora's SIGQUIT performs a zero-downtime listener handoff:
                // the replacement process receives inherited listener FDs via
                // its upgrade socket before the old process drains sessions.
                // Start the replacement only after its config/TLS validation
                // succeeds during startup; the old child remains authoritative
                // if spawning fails.
                let candidate_valid = config::load(&path).is_ok_and(|candidate| {
                    candidate
                        .server
                        .tls
                        .as_ref()
                        .map(crate::tls::settings)
                        .is_none_or(|result| result.is_ok())
                });
                if candidate_valid {
                    let ready_path = std::env::temp_dir().join(format!(
                        "bearust-upgrade-ready-{}-{}",
                        child.id(),
                        std::process::id()
                    ));
                    let _ = std::fs::remove_file(&ready_path);
                    if let Ok(mut replacement) = spawn_child(true, Some(&ready_path)) {
                        let deadline = std::time::Instant::now() + Duration::from_secs(5);
                        let mut ready = false;
                        while std::time::Instant::now() < deadline {
                            if replacement.try_wait().ok().flatten().is_some() {
                                break;
                            }
                            if matches!(std::fs::read(&ready_path), Ok(bytes) if bytes == b"ready\n")
                            {
                                // Re-check immediately after observing the
                                // marker so an exited replacement never
                                // drains the only serving child.
                                ready = replacement.try_wait().ok().flatten().is_none();
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(20));
                        }
                        let _ = std::fs::remove_file(&ready_path);
                        if ready {
                            let old_pid = child.id() as i32;
                            child = replacement;
                            let _ = kill(Pid::from_raw(old_pid), Signal::SIGQUIT);
                        } else {
                            let _ = replacement.kill();
                            let _ = replacement.wait();
                        }
                    }
                }
            }
            _ => {
                let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM);
                let deadline =
                    std::time::Instant::now() + Duration::from_secs(graceful_shutdown_seconds);
                while child
                    .try_wait()
                    .map_err(|e| AppError::Server(e.to_string()))?
                    .is_none()
                    && std::time::Instant::now() < deadline
                {
                    std::thread::sleep(Duration::from_millis(20));
                }
                if child
                    .try_wait()
                    .map_err(|e| AppError::Server(e.to_string()))?
                    .is_none()
                {
                    let _ = child.kill();
                }
                break;
            }
        }
    }
    child.wait().map_err(|e| AppError::Server(e.to_string()))?;
    Ok(())
}

#[cfg(not(unix))]
fn supervise_child(
    _path: PathBuf,
    _json_logs: bool,
    _graceful_shutdown_seconds: u64,
) -> Result<(), AppError> {
    Err(AppError::Server(
        "process supervisor requires Unix signals".into(),
    ))
}

fn serve_proxy(path: PathBuf, json_logs: bool, config: config::Config) -> Result<(), AppError> {
    // Installed once, process-wide, before any HTTP/3 TLS construction.
    // `pingora-rustls` manages its own provider internally for the
    // existing HTTP/1.1/HTTP/2 path, so this is only needed for the H3
    // listener's `rustls`/`quinn` usage below.
    rustls::crypto::ring::default_provider()
        .install_default()
        .ok();
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned());
    crate::observability::init(json_logs, &filter)
        .map_err(|error| AppError::Server(error.to_string()))?;
    tracing::info!(event = "server_start", json_logs);
    let rt = tokio::runtime::Runtime::new().map_err(|e| AppError::Server(e.to_string()))?;
    rt.block_on(async move {
        let store = Arc::new(RuntimeStore::from_path(&path).await?);
        let database_url_from_env = std::env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let database_url = database_url_from_env
            .clone()
            .unwrap_or_else(|| format!("sqlite://{}", config.server.control_database.display()));
        let sqlite_path = if is_sqlite_database_url(&database_url)
            && !database_url.contains(":memory:")
        {
            match database_url_from_env.as_deref() {
                Some(url) => sqlite_database_path(url),
                None => Some(config.server.control_database.clone()),
            }
        } else {
            None
        };
        if let Some(database_path) = sqlite_path.as_deref() {
            ensure_sqlite_database_file(database_path)?;
        }
        let setup_token_from_env = std::env::var("BEARUST_SETUP_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let setup_token = setup_token_from_env.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        if setup_token_from_env.is_none() {
            if let Some(database_path) = sqlite_path.as_deref() {
                let token_path = database_path.parent().unwrap_or(std::path::Path::new(".")).join("setup-token");
                if let Some(parent) = token_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| {
                        AppError::Server(format!("create setup token directory: {e}"))
                    })?;
                }
                std::fs::write(&token_path, format!("{setup_token}\n"))
                    .map_err(|e| AppError::Server(format!("write setup token: {e}")))?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let _ = std::fs::set_permissions(
                        &token_path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
                tracing::warn!(event = "generated_setup_token_file", path = %token_path.display());
            }
        }
        tracing::info!(event = "control_plane_start", bind = %config.server.control_bind, setup_token_configured = setup_token_from_env.is_some(), generated_setup_token = setup_token_from_env.is_none());
        let mut control_state = crate::control_plane::build_state(&database_url, &config.server.certificate_store, setup_token)
            .await.map_err(|e| AppError::Server(format!("control plane: {e}")))?;
        control_state = control_state.with_runtime(
            Arc::clone(&store),
            Arc::new(path.clone()),
            Arc::new(config.server.pid_file.clone()),
        );
        if let Some(persisted) = crate::control_plane::repository::get_runtime_config(
            &control_state.db,
        )
        .await
        .map_err(|error| AppError::Server(format!("load persisted runtime config: {error}")))?
        {
            control_state
                .reloader
                .apply_runtime_config(persisted)
                .await
                .map_err(|error| AppError::Server(format!("activate persisted runtime config: {error}")))?;
        } else {
            let existing_hosts = crate::control_plane::repository::list_hosts(&control_state.db)
                .await
                .map_err(|error| AppError::Server(format!("load proxy hosts: {error}")))?;
            control_state
                .reloader
                .apply(crate::control_plane::models::DesiredConfig {
                    proxy_hosts: existing_hosts,
                })
                .await
                .map_err(|error| AppError::Server(format!("activate proxy hosts: {error}")))?;
        }
        let plugin_manager = crate::plugin_runtime::PluginManager::new(config.plugins.clone());
        plugin_manager.attach_realtime(control_state.realtime.clone());
        plugin_manager.attach_audit_sink(Arc::new(
            crate::control_plane::audit::PluginAuditDbSink::new(
                control_state.db.clone(),
                control_state.realtime.clone(),
            ),
        ));
        control_state.plugin_manager = plugin_manager;
        if config.plugins.enabled {
            match control_state.plugin_manager.reload_from_disk() {
                Err(error) => {
                    tracing::warn!(event = "plugin_startup_failed", code = error.code());
                }
                Ok(summary) if summary.failed > 0 => {
                    tracing::warn!(event = "plugin_startup_partial", failed = summary.failed);
                }
                Ok(_) => {}
            }
        }
        let plugin_notify_sink =
            crate::plugin_notify::NotificationSink::spawn(control_state.plugin_manager.clone());
        control_state.ai_advisor = Arc::new(
            crate::ai_advisor::AiAdvisorService::from_env()
                .map(|service| service.with_metrics(control_state.advisor_metrics.clone()))
                .map(crate::ai_advisor::AiAdvisorService::with_configured_provider)
                .unwrap_or_else(|error| {
                    tracing::warn!(event = "ai_advisor_disabled", reason = %error);
                    crate::ai_advisor::AiAdvisorService::disabled()
                }),
        );
        let ai_report_task = if control_state.ai_advisor.status().enabled {
            let interval_hours = std::env::var("BEARUST_AI_REPORT_INTERVAL_HOURS")
                .ok()
                .and_then(|value| value.parse::<u64>().ok())
                .filter(|hours| (1..=168).contains(hours))
                .unwrap_or(24);
            let state = control_state.clone();
            Some(tokio::spawn(async move {
                let delay = Duration::from_secs(interval_hours.saturating_mul(60 * 60));
                loop {
                    tokio::time::sleep(delay).await;
                    if let Err(error) = crate::control_plane::ai_advisor::schedule_security_summary(
                        &state,
                    )
                    .await
                    {
                        tracing::warn!(event = "ai_periodic_report_failed", code = ?error);
                    }
                }
            }))
        } else {
            None
        };
        control_state.prometheus = config.prometheus.clone();
        // Construct the Raft runtime only for an explicitly configured,
        // authenticated cluster. Construction does not bootstrap membership
        // or promote this node; those transitions remain explicit lifecycle
        // operations. Keep the handle so shutdown can stop its tick task.
        let raft_handle = if !config.cluster.auth_token.trim().is_empty() {
            let peer_ids = config
                .cluster
                .peers
                .iter()
                .map(|peer| peer.node_id.clone())
                .collect::<Vec<_>>();
            let raft_id = crate::cluster_raft_runtime::deterministic_raft_id(
                &config.cluster.node_id,
                &peer_ids,
            )
            .map_err(|error| AppError::Server(format!("raft identity: {error}")))?;
            Some(crate::cluster_raft_runtime::construct_raft_with_id(
                control_state.db.clone(),
                config.cluster.node_id.clone(),
                config.cluster.auth_token.as_bytes(),
                raft_id,
            )
            .await
            .map_err(|error| AppError::Server(format!("raft startup: {error}")))?)
        } else {
            None
        };
        let cluster_service = Arc::new(crate::cluster::ClusterService::new(&config.cluster));
        let mut cluster_status_task = None;
        if let Some(raft) = raft_handle.as_ref() {
            cluster_service.set_raft_handler(Arc::new(
                crate::cluster_raft_runtime::OpenRaftRpcHandler::new(raft.clone()),
            ));
            let gateway = crate::cluster_command::ConfigCommandGateway::new(
                Arc::new(raft.clone()),
                cluster_service.clone(),
                control_state.db.clone(),
            );
            cluster_service.set_command_handler(Arc::new(gateway.clone()));
            control_state = control_state.with_config_gateway(gateway);
            cluster_status_task = Some(crate::cluster_raft_runtime::spawn_cluster_status_sync(
                cluster_service.clone(),
                raft.clone(),
            ));
        }
        let cluster_event_fanout = if raft_handle.is_some() {
            let receiver = Arc::new(crate::cluster_events::ClusterEventReceiver::new(
                control_state.realtime.clone(),
                Arc::new(crate::cluster_events::SqlxAppliedStateLoader::new(
                    control_state.db.clone(),
                    config.cluster.node_id.clone(),
                    Duration::from_secs(config.cluster.timeout_seconds),
                )),
            )
            .with_reloader(control_state.reloader.clone()));
            cluster_service.set_event_handler(receiver);
            Some(
                crate::cluster_events::ClusterEventFanout::start(
                    cluster_service.clone(),
                    control_state.realtime.clone(),
                    crate::cluster_events::MAX_CLUSTER_EVENT_QUEUE_CAPACITY,
                )
                .map_err(|error| {
                    AppError::Server(format!("cluster event fanout startup: {error}"))
                })?,
            )
        } else {
            None
        };
        control_state = control_state.with_cluster(cluster_service.clone());
        let (cluster_shutdown_tx, cluster_shutdown_rx) = tokio::sync::watch::channel(false);
        let cluster_health_task = tokio::spawn(crate::cluster::monitor_cluster_health(
            cluster_service.clone(),
            cluster_shutdown_rx.clone(),
        ));
        let cluster_task = tokio::spawn(crate::cluster::run_cluster_listener(
            cluster_service,
            cluster_shutdown_rx,
        ));
        let waf_store = control_state.waf.clone();
        let bot_store = control_state.bot.clone();
        let challenge_service = control_state.challenges.clone();
        let rate_limiter = control_state.rate_limiter.clone();
        let analytics = control_state.analytics.clone();
        let realtime = control_state.realtime.clone();
        let analytics_persistence_task = {
            let database = control_state.db.clone();
            let collector = control_state.analytics.clone();
            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    let buckets = collector.persistence_snapshot();
                    if let Err(error) = crate::control_plane::repository::persist_analytics_buckets(
                        &database,
                        &buckets,
                        collector.retention_minutes(),
                    )
                    .await
                    {
                        tracing::warn!(event = "analytics_persistence_failed", error = %error);
                    }
                }
            })
        };
        let analytics_changed: Arc<dyn Fn() + Send + Sync> = {
            let realtime = realtime.clone();
            Arc::new(move || {
                realtime.publish("analytics.changed");
            })
        };
        let trusted_proxies = IpNetSet::new(config.server.trusted_proxy_cidrs.iter().map(String::as_str));
        let (http3_shutdown_tx, http3_shutdown_rx) = tokio::sync::watch::channel(false);
        let http3_alt_svc = config
            .server
            .http3
            .enabled
            .then(|| format!("h3=\":{}\"; ma=86400", config.server.http3.bind.port()));
        let http3_task = if config.server.http3.enabled {
            let tls = config
                .server
                .tls
                .as_ref()
                .expect("config validation already requires tls when http3.enabled");
            let tls_config = crate::http3::build_rustls_server_config(tls)
                .map_err(|e| AppError::Server(format!("HTTP/3 TLS setup: {e}")))?;
            let bind = config.server.http3.bind;
            let store = store.clone();
            let http3_options = crate::http3::Http3Options {
                waf: Some(waf_store.clone()),
                ip_security: Some(control_state.ip_security.clone()),
                host_auth: Some(control_state.host_auth.clone()),
                trusted_proxies: Some(Arc::new(trusted_proxies.clone())),
                analytics: Some(Arc::new(crate::http3::AnalyticsContext {
                    collector: analytics.clone(),
                    host_ids: Arc::new(HashMap::new()),
                    changed: Some(analytics_changed.clone()),
                })),
                rate_limit: Some(Arc::new(crate::http3::RateLimitContext {
                    limiter: rate_limiter.clone(),
                    trusted_proxies: Arc::new(trusted_proxies.clone()),
                })),
                bot: Some(Arc::new(crate::http3::BotContext {
                    store: bot_store.clone(),
                    challenges: Some(challenge_service.clone()),
                })),
                plugin_manager: Some(control_state.plugin_manager.clone()),
                plugin_notify: Some(plugin_notify_sink.clone()),
            };
            Some(tokio::spawn(async move {
                if let Err(error) =
                    crate::http3::serve(bind, tls_config, store, http3_options, http3_shutdown_rx)
                        .await
                {
                    tracing::error!(event = "http3_listener_stopped", error = %error);
                }
            }))
        } else {
            None
        };
        let rate_policy = RateLimitPolicy {
            enabled: config.rate_limit.enabled,
            action: match config.rate_limit.action { config::RateLimitAction::Block => crate::rate_limit::RateLimitAction::Block, config::RateLimitAction::Monitor => crate::rate_limit::RateLimitAction::Monitor },
            capacity: config.rate_limit.capacity as u32,
            refill_per_second: config.rate_limit.refill_per_second,
            key_scope: match config.rate_limit.key_scope { config::RateLimitKeyScope::ProxyHostIp => RateLimitKeyScope::ProxyHostIp, config::RateLimitKeyScope::ProxyHostPathIp => RateLimitKeyScope::ProxyHostPathIp },
        };
        rate_limiter.set_policy(rate_policy.clone());
        if let Ok(host_configs) = crate::control_plane::repository::list_host_rate_limit_configs(&control_state.db).await {
            for (host_id, cfg) in host_configs {
                rate_limiter.set_host_policy(
                    host_id,
                    RateLimitPolicy {
                        enabled: cfg.enabled,
                        action: cfg.action,
                        capacity: cfg.capacity,
                        refill_per_second: cfg.refill_per_second,
                        key_scope: cfg.key_scope,
                    },
                );
            }
        }
        let proxy_upgrade = std::env::var_os("BEARUST_PROXY_UPGRADE").is_some();
        let control_bind = config.server.control_bind;
        let control_listener = if proxy_upgrade {
            None
        } else {
            Some(
                tokio::net::TcpListener::bind(control_bind)
                    .await
                    .map_err(|e| AppError::Server(format!("control plane bind: {e}")))?,
            )
        };
        let control_router = crate::control_plane::router_with_metrics(
            control_state.clone(),
            config.prometheus.bind == config.server.control_bind,
        );
        let eval_state = control_state.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                crate::control_plane::run_adaptive_evaluation_tick(&eval_state, true).await;
            }
        });

        let control_task = tokio::spawn(async move {
            let control_listener = match control_listener {
                Some(listener) => listener,
                None => loop {
                    match tokio::net::TcpListener::bind(control_bind).await {
                        Ok(listener) => break listener,
                        Err(error) => {
                            tracing::debug!(
                                event = "control_plane_bind_retry",
                                bind = %control_bind,
                                reason = %error,
                                "waiting for the previous process to release the control listener"
                            );
                            tokio::time::sleep(Duration::from_millis(100)).await;
                        }
                    }
                },
            };
            let _ = axum::serve(control_listener, control_router).await;
        });
        if config.prometheus.enabled && config.prometheus.bind != config.server.control_bind {
            let metrics_listener = tokio::net::TcpListener::bind(config.prometheus.bind).await
                .map_err(|e| AppError::Server(format!("prometheus bind: {e}")))?;
            let metrics_router = crate::control_plane::prometheus_router(control_state.clone());
            tokio::spawn(async move {
                let _ = axum::serve(metrics_listener, metrics_router).await;
            });
            tracing::info!(event = "prometheus_start", bind = %config.prometheus.bind, internal_only = config.prometheus.internal_only, require_auth = config.prometheus.require_auth);
        }
        let pingora_options = std::env::var_os("BEARUST_PROXY_UPGRADE").map(|_| {
            pingora_core::server::configuration::Opt {
                upgrade: true,
                ..Default::default()
            }
        });
        let mut server = pingora_core::server::Server::new(pingora_options)
            .map_err(|e| AppError::Server(e.to_string()))?;
        // Bound Pingora's graceful drain by the operator's configured
        // shutdown timeout. A zero grace period starts draining immediately.
        let server_config = std::sync::Arc::get_mut(&mut server.configuration)
            .ok_or_else(|| AppError::Server("Pingora server configuration is shared".into()))?;
        server_config.grace_period_seconds = Some(config.server.graceful_shutdown_seconds);
        server_config.graceful_shutdown_timeout_seconds =
            Some(config.server.graceful_shutdown_seconds);
        let ready_path = std::env::var_os("BEARUST_UPGRADE_READY").map(PathBuf::from);
        let mut proxy_handler = crate::proxy::BearustProxy::new(store.clone()).with_waf_store(waf_store)
                .with_ip_security_store(control_state.ip_security.clone())
                .with_host_auth_store(control_state.host_auth.clone())
                .with_bot_store(bot_store, challenge_service)
                .with_analytics(analytics)
                .with_analytics_changed_notifier(analytics_changed)
                .with_baseline(control_state.baseline.clone())
                .with_anomaly(control_state.anomaly.clone())
                .with_plugin_notify_sink(plugin_notify_sink)
                .with_plugin_manager(control_state.plugin_manager.clone())
                .with_rate_limiter(rate_limiter)
                .with_rate_limit_policy(rate_policy)
                .with_trusted_proxies(trusted_proxies);
        if let Some(alt_svc) = http3_alt_svc {
            proxy_handler = proxy_handler.with_http3_alt_svc(alt_svc);
        }
        let mut service = proxy::http_service(proxy_handler, &server.configuration);
        if let Some(tls_config) = &config.server.tls {
            let tls = crate::tls::settings(tls_config)
                .map_err(|error| AppError::Server(error.to_string()))?;
            service.add_tls_with_settings(&config.server.bind.to_string(), None, tls);
        } else {
            service.add_tcp(&config.server.bind.to_string());
        }
        server.add_service(service);
        // The upgrade protocol requires the old process to transfer listener
        // FDs before bootstrap can complete. Publish an exact, atomic marker
        // after candidate TLS/service setup and immediately before starting
        // the server task; the parent then triggers SIGQUIT on the old child.
        if let Some(ready_path) = &ready_path {
            let temp = ready_path.with_extension("tmp");
            let _ =
                std::fs::write(&temp, b"ready\n").and_then(|_| std::fs::rename(&temp, ready_path));
        }
        server.bootstrap();
        let mut execution_phase = server.watch_execution_phase();
        // Pingora owns SIGTERM/SIGINT so it can stop accepting connections
        // and drain in-flight requests using its graceful shutdown timeout.
        // Bearust handles SIGHUP independently for atomic config reloads.
        let (done_tx, done_rx) = tokio::sync::watch::channel(false);
        #[cfg(unix)]
        let (term_tx, term_rx) = tokio::sync::oneshot::channel();
        #[cfg(unix)]
        std::thread::spawn(move || {
            let Ok(mut signals) = signal_hook::iterator::Signals::new([
                signal_hook::consts::SIGTERM,
                signal_hook::consts::SIGINT,
            ]) else {
                return;
            };
            if signals.forever().next().is_some() {
                let _ = term_tx.send(());
            }
        });
        let mut server_task = tokio::task::spawn_blocking(move || {
            server.run(pingora_core::server::RunArgs::default());
            let _ = done_tx.send(true);
        });
        if let Some(ready_path) = ready_path {
            tokio::spawn(async move {
                while let Ok(phase) = execution_phase.recv().await {
                    if matches!(phase, pingora_core::server::ExecutionPhase::Running) {
                        let _ = std::fs::write(ready_path, b"ready\n");
                        break;
                    }
                }
            });
        }
        let mut reload_task = tokio::spawn(crate::reload::reload_loop(
            Arc::clone(&store),
            path,
            done_rx,
        ));
        #[cfg(unix)]
        tokio::select! {
            result = &mut server_task => {
                result.map_err(|error| AppError::Server(error.to_string()))?;
            }
            _ = term_rx => {
                // Pingora drains listeners and in-flight requests in response
                // to the same signal. Bound the wait independently of its
                // signal implementation so shutdown cannot hang forever.
                if tokio::time::timeout(
                    Duration::from_secs(config.server.graceful_shutdown_seconds),
                    &mut server_task,
                ).await.is_err() {
                    std::process::exit(0);
                }
            }
            _ = &mut reload_task => {
                // Pingora is draining listeners and in-flight requests in
                // response to the same signal. Bound the wait so a stuck
                // runtime cannot keep the process alive indefinitely.
                if tokio::time::timeout(
                    Duration::from_secs(config.server.graceful_shutdown_seconds),
                    &mut server_task,
                ).await.is_err() {
                    std::process::exit(0);
                }
            }
        }
        #[cfg(not(unix))]
        server_task
            .await
            .map_err(|error| AppError::Server(error.to_string()))?;
        reload_task.abort();
        control_task.abort();
        analytics_persistence_task.abort();
        let _ = analytics_persistence_task.await;
        if let Some(task) = ai_report_task {
            task.abort();
            let _ = task.await;
        }
        let _ = http3_shutdown_tx.send(true);
        if let Some(http3_task) = http3_task {
            let _ = tokio::time::timeout(
                Duration::from_secs(config.server.graceful_shutdown_seconds),
                http3_task,
            )
            .await;
        }
        if let Some(fanout) = cluster_event_fanout {
            fanout.shutdown().await;
        }
        if let Some(status_task) = cluster_status_task {
            status_task.abort();
            let _ = status_task.await;
        }
        let _ = cluster_shutdown_tx.send(true);
        let _ = cluster_health_task.await;
        tokio::time::timeout(
            Duration::from_secs(config.server.graceful_shutdown_seconds),
            cluster_task,
        )
        .await
        .map_err(|_| AppError::Server("cluster shutdown timed out".into()))?
        .map_err(|_| AppError::Server("cluster listener task failed".into()))?;
        if let Some(raft) = raft_handle {
            tokio::time::timeout(
                Duration::from_secs(config.server.graceful_shutdown_seconds),
                raft.shutdown(),
            )
            .await
            .map_err(|_| AppError::Server("raft shutdown timed out".into()))?
            .map_err(|_| AppError::Server("raft shutdown failed".into()))?;
        }
        tokio::time::timeout(
            Duration::from_secs(config.server.graceful_shutdown_seconds),
            store.shutdown(),
        )
        .await
        .map_err(|_| AppError::Server("health shutdown timed out".into()))??;
        tracing::info!(event = "server_stop");
        Ok(())
    })
}

fn is_sqlite_database_url(url: &str) -> bool {
    url.trim_start().to_ascii_lowercase().starts_with("sqlite:")
}

fn sqlite_database_path(url: &str) -> Option<PathBuf> {
    let trimmed = url.trim_start();
    let path = if trimmed
        .get(.."sqlite://".len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("sqlite://"))
    {
        &trimmed["sqlite://".len()..]
    } else if trimmed
        .get(.."sqlite:".len())
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("sqlite:"))
    {
        &trimmed["sqlite:".len()..]
    } else {
        return None;
    };
    let path = path.split(['?', '#']).next()?.trim();
    if path.is_empty() || path == ":memory:" {
        return None;
    }
    Some(PathBuf::from(path))
}

fn ensure_sqlite_database_file(path: &Path) -> Result<(), AppError> {
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        std::fs::create_dir_all(parent)
            .map_err(|error| AppError::Server(format!("create database directory: {error}")))?;
    }
    std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .map(|_| ())
        .map_err(|error| AppError::Server(format!("create database file: {error}")))
}

fn plugin_command(action: PluginCommand) -> Result<(), AppError> {
    match action {
        PluginCommand::Keygen { out } => plugin_keygen(&out),
        PluginCommand::Sign { plugin_dir, key } => plugin_sign(&plugin_dir, &key),
        PluginCommand::Search {
            query,
            registry_url,
        } => plugin_search(&query, registry_url.as_deref()),
        PluginCommand::Install {
            id,
            out,
            yes,
            force,
            registry_url,
        } => plugin_install(&id, &out, yes, force, registry_url.as_deref()),
    }
}

fn plugin_keygen(out: &Path) -> Result<(), AppError> {
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;
    use rand::rngs::OsRng;

    std::fs::create_dir_all(out).map_err(|e| AppError::PluginSigning(e.to_string()))?;
    let signing_key = SigningKey::generate(&mut OsRng);
    let key_path = out.join("signing.key");
    #[cfg(unix)]
    {
        use std::io::Write as _;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&key_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    AppError::PluginSigning(format!(
                        "a signing key already exists at {} — remove it first if you intend to replace it",
                        key_path.display()
                    ))
                } else {
                    AppError::PluginSigning(e.to_string())
                }
            })?;
        file.write_all(&signing_key.to_bytes())
            .map_err(|e| AppError::PluginSigning(e.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        use std::io::Write as _;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&key_path)
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::AlreadyExists {
                    AppError::PluginSigning(format!(
                        "a signing key already exists at {} — remove it first if you intend to replace it",
                        key_path.display()
                    ))
                } else {
                    AppError::PluginSigning(e.to_string())
                }
            })?;
        file.write_all(&signing_key.to_bytes())
            .map_err(|e| AppError::PluginSigning(e.to_string()))?;
    }
    let public_key =
        base64::engine::general_purpose::STANDARD.encode(signing_key.verifying_key().to_bytes());
    println!("{public_key}");
    Ok(())
}

fn plugin_sign(plugin_dir: &Path, key_path: &Path) -> Result<(), AppError> {
    use ed25519_dalek::SigningKey;

    let key_bytes = std::fs::read(key_path).map_err(|e| AppError::PluginSigning(e.to_string()))?;
    let key_bytes: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| AppError::PluginSigning("signing key has the wrong length".to_string()))?;
    let signing_key = SigningKey::from_bytes(&key_bytes);

    let manifest_path = plugin_dir.join("plugin.toml");
    let manifest_bytes =
        std::fs::read(&manifest_path).map_err(|e| AppError::PluginSigning(e.to_string()))?;
    let manifest = crate::plugin_runtime::PluginManifest::from_toml(&manifest_bytes)
        .map_err(|e| AppError::PluginSigning(e.to_string()))?;
    let module_path = plugin_dir.join(&manifest.module);
    let wasm_bytes =
        std::fs::read(&module_path).map_err(|e| AppError::PluginSigning(e.to_string()))?;

    let signature = crate::plugin_signing::sign(&manifest, &wasm_bytes, &signing_key);
    let sig_toml =
        toml::to_string(&signature).map_err(|e| AppError::PluginSigning(e.to_string()))?;
    let sig_path = plugin_dir.join("plugin.sig");
    std::fs::write(&sig_path, sig_toml).map_err(|e| AppError::PluginSigning(e.to_string()))?;
    println!("wrote {}", sig_path.display());
    Ok(())
}

const DEFAULT_PLUGIN_REGISTRY_URL: &str =
    "https://raw.githubusercontent.com/Bearust/bearust-plugin-index/main/index.json";

fn resolve_registry_url(flag: Option<&str>) -> String {
    if let Some(url) = flag {
        return url.to_owned();
    }
    if let Ok(url) = std::env::var("BEARUST_PLUGIN_REGISTRY_URL") {
        if !url.trim().is_empty() {
            return url;
        }
    }
    DEFAULT_PLUGIN_REGISTRY_URL.to_owned()
}

fn plugin_search(query: &str, registry_url: Option<&str>) -> Result<(), AppError> {
    let url = resolve_registry_url(registry_url);
    let client = reqwest::blocking::Client::new();
    let index = crate::plugin_registry::RegistryIndex::fetch(&client, &url)
        .map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let results = index.search(query);
    if results.is_empty() {
        println!("no plugins match \"{query}\"");
        return Ok(());
    }
    for entry in results {
        println!(
            "{}  v{}  {}",
            sanitize_for_terminal(&entry.id),
            sanitize_for_terminal(&entry.version),
            sanitize_for_terminal(&entry.description)
        );
    }
    Ok(())
}

/// Strips control characters (which could otherwise inject newlines or
/// terminal escapes to visually spoof the confirmation summary an operator
/// relies on), plus the Unicode line/paragraph separators and bidi-control
/// characters that `char::is_control()` does not classify as control
/// characters but which many terminals still honor to reorder or break up
/// displayed text, and caps the length of an index-sourced string before it
/// is printed. The index is a catalog, not a trust source, so nothing in it
/// should be able to affect what the operator sees on screen.
fn sanitize_for_terminal(s: &str) -> String {
    s.chars()
        .filter(|c| {
            !c.is_control()
                && *c != '\u{2028}'
                && *c != '\u{2029}'
                && !('\u{202A}'..='\u{202E}').contains(c)
                && !('\u{2066}'..='\u{2069}').contains(c)
        })
        .take(200)
        .collect()
}

fn plugin_install(
    id: &str,
    plugins_directory: &Path,
    yes: bool,
    force: bool,
    registry_url: Option<&str>,
) -> Result<(), AppError> {
    use crate::plugin_registry::{
        download_and_verify, extract_tarball, verify_signer, RegistryIndex,
    };

    if id.is_empty()
        || id.len() > crate::plugin_runtime::MAX_ID_LEN
        || !crate::plugin_runtime::valid_id(id)
    {
        return Err(AppError::PluginRegistry(format!(
            "\"{id}\" is not a valid plugin id (lowercase letters, digits, and hyphens only)"
        )));
    }

    let url = resolve_registry_url(registry_url);
    let client = reqwest::blocking::Client::new();
    let index =
        RegistryIndex::fetch(&client, &url).map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let entry = index.find(id).ok_or_else(|| {
        AppError::PluginRegistry(
            crate::plugin_registry::RegistryError::NotFound(id.to_owned()).to_string(),
        )
    })?;

    let target_dir = plugins_directory.join(id);
    if target_dir.parent() != Some(plugins_directory) {
        return Err(AppError::PluginRegistry(format!(
            "\"{id}\" is not a valid plugin id (lowercase letters, digits, and hyphens only)"
        )));
    }
    if target_dir.exists() && !force {
        return Err(AppError::PluginRegistry(format!(
            "{} already exists -- pass --force to overwrite",
            target_dir.display()
        )));
    }

    let tarball =
        download_and_verify(&client, entry).map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let extracted =
        extract_tarball(&tarball, id).map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let signer = verify_signer(&extracted, entry.signer_public_key.as_deref())
        .map_err(|e| AppError::PluginRegistry(e.to_string()))?;

    println!(
        "{}  v{}\ncapabilities: {}\nsigner: {}",
        entry.id,
        sanitize_for_terminal(&entry.version),
        if extracted.manifest.capabilities.is_empty() {
            "(none)".to_owned()
        } else {
            extracted.manifest.capabilities.join(", ")
        },
        signer.as_deref().unwrap_or("unsigned"),
    );
    if !yes {
        print!("Install this plugin? [y/N]: ");
        std::io::Write::flush(&mut std::io::stdout())
            .map_err(|e| AppError::PluginRegistry(e.to_string()))?;
        let mut answer = String::new();
        std::io::stdin()
            .read_line(&mut answer)
            .map_err(|e| AppError::PluginRegistry(e.to_string()))?;
        let answer = answer.trim().to_ascii_lowercase();
        if answer != "y" && answer != "yes" {
            println!("aborted");
            return Ok(());
        }
    }

    std::fs::create_dir_all(plugins_directory)
        .map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let temp_dir = plugins_directory.join(format!(".{id}.install-tmp"));
    let _ = std::fs::remove_dir_all(&temp_dir);
    std::fs::create_dir_all(&temp_dir).map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    let write_result = (|| -> std::io::Result<()> {
        std::fs::write(temp_dir.join("plugin.toml"), &extracted.manifest_bytes)?;
        std::fs::write(
            temp_dir.join(&extracted.manifest.module),
            &extracted.wasm_bytes,
        )?;
        if let Some(signature_bytes) = &extracted.signature_bytes {
            std::fs::write(temp_dir.join("plugin.sig"), signature_bytes)?;
        }
        Ok(())
    })();
    if let Err(error) = write_result {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return Err(AppError::PluginRegistry(error.to_string()));
    }

    if target_dir.exists() {
        std::fs::remove_dir_all(&target_dir)
            .map_err(|e| AppError::PluginRegistry(e.to_string()))?;
    }
    std::fs::rename(&temp_dir, &target_dir).map_err(|e| AppError::PluginRegistry(e.to_string()))?;

    println!(
        "installed {} to {} -- run `POST /api/plugins/reload` to load it",
        id,
        target_dir.display()
    );
    Ok(())
}

#[cfg(test)]
mod sqlite_startup_tests {
    use super::{ensure_sqlite_database_file, sqlite_database_path};
    use std::fs;

    #[test]
    fn parses_file_backed_sqlite_urls_without_query_parameters() {
        assert_eq!(
            sqlite_database_path("sqlite:///data/bearust.sqlite?mode=rwc"),
            Some("/data/bearust.sqlite".into())
        );
        assert_eq!(sqlite_database_path("sqlite::memory:"), None);
    }

    #[test]
    fn creates_missing_database_without_truncating_an_existing_file() {
        let directory = tempfile::tempdir().expect("temp directory");
        let path = directory.path().join("nested").join("bearust.sqlite");

        ensure_sqlite_database_file(&path).expect("create database file");
        fs::write(&path, b"existing database bytes").expect("seed database file");
        ensure_sqlite_database_file(&path).expect("keep database file");

        assert_eq!(
            fs::read(&path).expect("read database file"),
            b"existing database bytes"
        );
    }
}
