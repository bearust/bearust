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
#[command(name = "bearust", version, about)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    Serve {
        #[arg(long, default_value = "bearust.toml")]
        config: PathBuf,
        #[arg(long, default_value_t = false)]
        json_logs: bool,
    },
    Validate {
        #[arg(long, default_value = "bearust.toml")]
        config: PathBuf,
    },
    Reload {
        #[arg(long, default_value = "./bearust.pid")]
        pid_file: PathBuf,
    },
    Plugin {
        #[command(subcommand)]
        action: PluginCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum PluginCommand {
    /// Generates a new Ed25519 signing keypair for signing plugins.
    Keygen {
        #[arg(long)]
        out: PathBuf,
    },
    /// Signs a plugin directory's manifest + wasm module, writing plugin.sig.
    Sign {
        plugin_dir: PathBuf,
        #[arg(long)]
        key: PathBuf,
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
    let filter = std::env::var("RUST_LOG").unwrap_or_else(|_| "info".to_owned());
    crate::observability::init(json_logs, &filter)
        .map_err(|error| AppError::Server(error.to_string()))?;
    tracing::info!(event = "server_start", json_logs);
    let rt = tokio::runtime::Runtime::new().map_err(|e| AppError::Server(e.to_string()))?;
    rt.block_on(async move {
        let store = Arc::new(RuntimeStore::from_path(&path).await?);
        let database_url = std::env::var("DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| format!("sqlite://{}", config.server.control_database.display()));
        if std::env::var_os("DATABASE_URL").is_none()
            && is_sqlite_database_url(&database_url)
            && !database_url.contains(":memory:")
        {
            if let Some(parent) = config.server.control_database.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| AppError::Server(format!("create database directory: {e}")))?;
            }
            std::fs::File::create(&config.server.control_database)
                .map_err(|e| AppError::Server(format!("create database file: {e}")))?;
        }
        let setup_token_from_env = std::env::var("BEARUST_SETUP_TOKEN")
            .ok()
            .filter(|value| !value.trim().is_empty());
        let setup_token = setup_token_from_env.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
        if setup_token_from_env.is_none() && is_sqlite_database_url(&database_url) {
            let token_path = config.server.control_database.parent().unwrap_or(std::path::Path::new(".")).join("setup-token");
            if let Some(parent) = token_path.parent() { std::fs::create_dir_all(parent).map_err(|e| AppError::Server(format!("create setup token directory: {e}")))?; }
            std::fs::write(&token_path, format!("{setup_token}\n")).map_err(|e| AppError::Server(format!("write setup token: {e}")))?;
            #[cfg(unix)]
            { use std::os::unix::fs::PermissionsExt; let _ = std::fs::set_permissions(&token_path, std::fs::Permissions::from_mode(0o600)); }
            tracing::warn!(event = "generated_setup_token_file", path = %token_path.display());
        }
        tracing::info!(event = "control_plane_start", bind = %config.server.control_bind, setup_token_configured = setup_token_from_env.is_some(), generated_setup_token = setup_token_from_env.is_none());
        let mut control_state = crate::control_plane::build_state(&database_url, &config.server.certificate_store, setup_token)
            .await.map_err(|e| AppError::Server(format!("control plane: {e}")))?;
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
            ));
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
        let analytics_host_ids = crate::control_plane::repository::list_hosts(&control_state.db)
            .await
            .map_err(|e| AppError::Server(format!("load proxy hosts for analytics: {e}")))?
            .into_iter()
            .filter_map(|host| crate::router::normalize_host(&host.domain).map(|domain| (domain, host.id)))
            .collect::<HashMap<_, _>>();
        let rate_policy = RateLimitPolicy {
            enabled: config.rate_limit.enabled,
            action: match config.rate_limit.action { config::RateLimitAction::Block => crate::rate_limit::RateLimitAction::Block, config::RateLimitAction::Monitor => crate::rate_limit::RateLimitAction::Monitor },
            capacity: config.rate_limit.capacity as u32,
            refill_per_second: config.rate_limit.refill_per_second,
            key_scope: match config.rate_limit.key_scope { config::RateLimitKeyScope::ProxyHostIp => RateLimitKeyScope::ProxyHostIp },
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
        let trusted_proxies = IpNetSet::new(config.server.trusted_proxy_cidrs.iter().map(String::as_str));
        let control_listener = tokio::net::TcpListener::bind(config.server.control_bind).await
            .map_err(|e| AppError::Server(format!("control plane bind: {e}")))?;
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
        let mut service = proxy::http_service(
            crate::proxy::BeaRustProxy::new(store.clone()).with_waf_store(waf_store).with_bot_store(bot_store, challenge_service)
                .with_analytics(analytics)
                .with_analytics_changed_notifier(Arc::new(move || { realtime.publish("analytics.changed"); }))
                .with_analytics_host_ids(analytics_host_ids)
                .with_baseline(control_state.baseline.clone())
                .with_anomaly(control_state.anomaly.clone())
                .with_plugin_notify_sink(plugin_notify_sink)
                .with_plugin_manager(control_state.plugin_manager.clone())
                .with_rate_limiter(rate_limiter)
                .with_rate_limit_policy(rate_policy)
                .with_trusted_proxies(trusted_proxies),
            &server.configuration,
        );
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
        // BeaRust handles SIGHUP independently for atomic config reloads.
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
        if let Some(fanout) = cluster_event_fanout {
            fanout.shutdown().await;
        }
        if let Some(status_task) = cluster_status_task {
            status_task.abort();
            let _ = status_task.await;
        }
        let _ = cluster_shutdown_tx.send(true);
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

fn plugin_command(action: PluginCommand) -> Result<(), AppError> {
    match action {
        PluginCommand::Keygen { out } => plugin_keygen(&out),
        PluginCommand::Sign { plugin_dir, key } => plugin_sign(&plugin_dir, &key),
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
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&key_path)
            .map_err(|e| AppError::PluginSigning(e.to_string()))?;
        file.write_all(&signing_key.to_bytes())
            .map_err(|e| AppError::PluginSigning(e.to_string()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(&key_path, signing_key.to_bytes())
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
