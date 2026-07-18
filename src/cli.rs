use crate::{
    config, proxy,
    reload::{self, PidFileGuard},
    runtime::RuntimeStore,
};
use clap::{Parser, Subcommand};
use std::{path::PathBuf, sync::Arc, time::Duration};
use thiserror::Error;

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
    let mut child = std::process::Command::new(exe)
        .env("BEARUST_PROXY_CHILD", "1")
        .args(["serve", "--config"])
        .arg(path)
        .args(json_logs.then_some(["--json-logs"]).into_iter().flatten())
        .spawn()
        .map_err(|e| AppError::Server(e.to_string()))?;
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
                let _ = kill(Pid::from_raw(child.id() as i32), Signal::SIGHUP);
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
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    if json_logs {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(filter).init();
    }
    let rt = tokio::runtime::Runtime::new().map_err(|e| AppError::Server(e.to_string()))?;
    rt.block_on(async move {
        let store = Arc::new(RuntimeStore::from_path(&path).await?);
        let mut server =
            pingora_core::server::Server::new(None).map_err(|e| AppError::Server(e.to_string()))?;
        // Bound Pingora's graceful drain by the operator's configured
        // shutdown timeout. A zero grace period starts draining immediately.
        let server_config = std::sync::Arc::get_mut(&mut server.configuration)
            .ok_or_else(|| AppError::Server("Pingora server configuration is shared".into()))?;
        server_config.grace_period_seconds = Some(config.server.graceful_shutdown_seconds);
        server_config.graceful_shutdown_timeout_seconds =
            Some(config.server.graceful_shutdown_seconds);
        server.bootstrap();
        let mut service = proxy::http_service(
            crate::proxy::BeaRustProxy::new(store.clone()),
            &server.configuration,
        );
        service.add_tcp(&config.server.bind.to_string());
        server.add_service(service);
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
        tokio::time::timeout(
            Duration::from_secs(config.server.graceful_shutdown_seconds),
            store.shutdown(),
        )
        .await
        .map_err(|_| AppError::Server("health shutdown timed out".into()))??;
        Ok(())
    })
}
