use crate::{
    config, proxy,
    reload::{self, PidFileGuard},
    runtime::RuntimeStore,
};
use clap::{Parser, Subcommand};
use std::{path::PathBuf, sync::Arc};
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
        server.bootstrap();
        let mut service = proxy::http_service(
            crate::proxy::BeaRustProxy::new(store.clone()),
            &server.configuration,
        );
        service.add_tcp(&config.server.bind.to_string());
        server.add_service(service);
        // Pingora owns the accept loop and blocks until the process receives a
        // termination signal. Keep the store alive for the lifetime of it.
        let _store = store;
        server.run_forever();
        #[allow(unreachable_code)]
        Ok(())
    })
}
