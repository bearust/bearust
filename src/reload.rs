use nix::{
    errno::Errno,
    sys::signal::{kill, Signal},
    unistd::Pid,
};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PidError {
    #[error("pid file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("pid file {0} contains an invalid PID")]
    Invalid(PathBuf),
    #[error("process {0} is already running")]
    AlreadyRunning(i32),
    #[error("process {0} is not running")]
    NotRunning(i32),
    #[error("unable to signal process {pid}: {source}")]
    Signal { pid: i32, source: nix::Error },
}

pub struct PidFileGuard {
    path: PathBuf,
    pid: i32,
}
impl PidFileGuard {
    pub fn acquire(path: impl AsRef<Path>) -> Result<Self, PidError> {
        let path = path.as_ref().to_path_buf();
        loop {
            match OpenOptions::new().create_new(true).write(true).open(&path) {
                Ok(mut file) => {
                    let pid = std::process::id() as i32;
                    writeln!(file, "{pid}")
                        .and_then(|_| file.flush())
                        .and_then(|_| file.sync_all())
                        .map_err(|source| PidError::Io {
                            path: path.clone(),
                            source,
                        })?;
                    return Ok(Self { path, pid });
                }
                Err(source) if source.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(PidError::Io {
                        path: path.clone(),
                        source,
                    })
                }
            }

            // Read and inspect an existing owner. We only remove the stale
            // file if its inode is unchanged since the read; this prevents a
            // concurrent server from replacing it between our check and
            // cleanup. The create_new retry then re-checks any race winner.
            let before = fs::metadata(&path).map_err(|source| PidError::Io {
                path: path.clone(),
                source,
            })?;
            let text = fs::read_to_string(&path).map_err(|source| PidError::Io {
                path: path.clone(),
                source,
            })?;
            let pid = text.trim().parse::<i32>().ok().filter(|p| *p > 0);
            if let Some(pid) = pid {
                match kill(Pid::from_raw(pid), None) {
                    Ok(()) => return Err(PidError::AlreadyRunning(pid)),
                    Err(Errno::ESRCH) => {}
                    Err(_) => return Err(PidError::AlreadyRunning(pid)),
                }
            }
            let after = fs::metadata(&path).map_err(|source| PidError::Io {
                path: path.clone(),
                source,
            })?;
            if !same_file(&before, &after) {
                continue;
            }
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => {
                    return Err(PidError::Io {
                        path: path.clone(),
                        source,
                    })
                }
            }
        }
    }
    pub fn pid(&self) -> i32 {
        self.pid
    }
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.dev() == b.dev() && a.ino() == b.ino()
}

#[cfg(not(unix))]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.len() == b.len() && a.modified().ok() == b.modified().ok()
}
impl Drop for PidFileGuard {
    fn drop(&mut self) {
        if fs::read_to_string(&self.path)
            .ok()
            .and_then(|s| s.trim().parse::<i32>().ok())
            == Some(self.pid)
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

pub fn signal_reload(path: impl AsRef<Path>) -> Result<(), PidError> {
    let path = path.as_ref().to_path_buf();
    let text = fs::read_to_string(&path).map_err(|source| PidError::Io {
        path: path.clone(),
        source,
    })?;
    let pid = text
        .trim()
        .parse::<i32>()
        .ok()
        .filter(|p| *p > 0)
        .ok_or_else(|| PidError::Invalid(path.clone()))?;
    match kill(Pid::from_raw(pid), None) {
        Ok(()) => kill(Pid::from_raw(pid), Some(Signal::SIGHUP))
            .map_err(|source| PidError::Signal { pid, source }),
        Err(Errno::ESRCH) => Err(PidError::NotRunning(pid)),
        Err(source) => Err(PidError::Signal { pid, source }),
    }
}

/// Runs the process signal loop used by `serve`.
///
/// SIGHUP is deliberately handled here instead of being delegated to
/// Pingora: parsing/building the candidate snapshot happens before it is
/// published, so an invalid reload can never replace the active snapshot.
/// SIGINT and SIGTERM first stop the health workers and then return to the
/// caller, which owns the Pingora server task and its graceful shutdown.
#[cfg(unix)]
pub async fn signal_loop(
    store: std::sync::Arc<crate::runtime::RuntimeStore>,
    config_path: PathBuf,
    graceful_shutdown: std::time::Duration,
) -> Result<(), crate::runtime::RuntimeError> {
    use tokio::signal::unix::{signal, SignalKind};

    let mut hup = signal(SignalKind::hangup())
        .map_err(|error| crate::runtime::RuntimeError::Signal(error.to_string()))?;
    let mut terminate = signal(SignalKind::terminate())
        .map_err(|error| crate::runtime::RuntimeError::Signal(error.to_string()))?;
    let mut interrupt = signal(SignalKind::interrupt())
        .map_err(|error| crate::runtime::RuntimeError::Signal(error.to_string()))?;
    loop {
        tokio::select! {
            _ = hup.recv() => {
                match store.reload(&config_path).await {
                    Ok(outcome) => tracing::info!(event = "reload_complete", old_generation = outcome.old_generation, new_generation = outcome.new_generation),
                    Err(_error) => tracing::error!(event = "reload_rejected", config_path = %config_path.display()),
                }
            }
            _ = terminate.recv() => break,
            _ = interrupt.recv() => break,
        }
    }
    // Health probes are independent Tokio tasks. Stop and join them before
    // allowing the server task to finish; bounded waiting is required so a
    // wedged probe cannot keep process shutdown open indefinitely.
    tokio::time::timeout(graceful_shutdown, store.shutdown())
        .await
        .unwrap_or_else(|_| Ok(()))
}

/// Reload-only signal loop. Pingora owns SIGTERM/SIGINT so it can drain
/// listeners and in-flight requests; this task handles SIGHUP and exits when
/// the server task completes.
#[cfg(unix)]
pub async fn reload_loop(
    store: std::sync::Arc<crate::runtime::RuntimeStore>,
    config_path: PathBuf,
    mut server_done: tokio::sync::watch::Receiver<bool>,
) -> Result<(), crate::runtime::RuntimeError> {
    use tokio::signal::unix::{signal, SignalKind};
    let mut hup = signal(SignalKind::hangup())
        .map_err(|error| crate::runtime::RuntimeError::Signal(error.to_string()))?;
    let mut terminate = signal(SignalKind::terminate())
        .map_err(|error| crate::runtime::RuntimeError::Signal(error.to_string()))?;
    loop {
        tokio::select! {
            _ = hup.recv() => {
                match store.reload(&config_path).await {
                    Ok(outcome) => tracing::info!(event = "reload_complete", old_generation = outcome.old_generation, new_generation = outcome.new_generation),
                    Err(_error) => tracing::error!(event = "reload_rejected", config_path = %config_path.display()),
                }
            }
            changed = server_done.changed() => {
                if changed.is_err() || *server_done.borrow() { break; }
            }
            _ = terminate.recv() => break,
        }
    }
    Ok(())
}

#[cfg(not(unix))]
pub async fn signal_loop(
    _store: std::sync::Arc<crate::runtime::RuntimeStore>,
    _config_path: PathBuf,
    _graceful_shutdown: std::time::Duration,
) -> Result<(), crate::runtime::RuntimeError> {
    tokio::signal::ctrl_c()
        .await
        .map_err(|error| crate::runtime::RuntimeError::Signal(error.to_string()))?;
    Ok(())
}
