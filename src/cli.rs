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
    let pid = PidFileGuard::acquire(&config.server.pid_file)?;
    let _ = pid;
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
        server_config.grace_period_seconds = Some(0);
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
