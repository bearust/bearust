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
        if path.exists() {
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
            let _ = fs::remove_file(&path);
        }
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|source| PidError::Io {
                path: path.clone(),
                source,
            })?;
        let pid = std::process::id() as i32;
        writeln!(file, "{pid}")
            .and_then(|_| file.flush())
            .map_err(|source| PidError::Io {
                path: path.clone(),
                source,
            })?;
        Ok(Self { path, pid })
    }
    pub fn pid(&self) -> i32 {
        self.pid
    }
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
