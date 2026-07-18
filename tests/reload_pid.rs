#![cfg(unix)]

use bearust::reload::{signal_reload, PidError, PidFileGuard};
use std::process::Command;

struct ChildGuard(std::process::Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

#[test]
fn pid_file_missing_is_reported() {
    let path = tempfile::tempdir().unwrap().path().join("missing.pid");
    let error = signal_reload(&path).unwrap_err();
    assert!(matches!(error, PidError::Io { .. }));
}

#[test]
fn pid_file_stale_is_reported() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("stale.pid");
    std::fs::write(&path, "999999").unwrap();
    let error = signal_reload(&path).unwrap_err();
    assert!(matches!(error, PidError::NotRunning(999999)));
}

#[test]
fn pid_file_live_process_is_signaled() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("live.pid");
    let child = Command::new("sleep").arg("2").spawn().unwrap();
    let mut child = ChildGuard(child);
    std::fs::write(&path, child.0.id().to_string()).unwrap();
    assert!(signal_reload(&path).is_ok());
    let _ = child.0.kill();
    let _ = child.0.wait();
}

#[test]
fn acquire_rejects_live_pid_owner() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("owned.pid");
    let child = ChildGuard(Command::new("sleep").arg("2").spawn().unwrap());
    std::fs::write(&path, child.0.id().to_string()).unwrap();
    let error = match PidFileGuard::acquire(&path) {
        Ok(_) => panic!("live PID must retain ownership"),
        Err(error) => error,
    };
    assert!(matches!(error, PidError::AlreadyRunning(pid) if pid == child.0.id() as i32));
}

#[test]
fn malformed_pid_is_replaced_on_acquire() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("malformed.pid");
    std::fs::write(&path, "not-a-pid\n").unwrap();
    let guard = PidFileGuard::acquire(&path).unwrap();
    assert_eq!(guard.pid() as u32, std::process::id());
}

#[test]
fn stale_pid_is_reclaimed_on_acquire() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reclaim.pid");
    std::fs::write(&path, "999999\n").unwrap();
    let guard = PidFileGuard::acquire(&path).unwrap();
    assert_eq!(guard.pid() as u32, std::process::id());
}
