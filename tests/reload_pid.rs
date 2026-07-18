#![cfg(unix)]

use bearust::reload::{signal_reload, PidError, PidFileGuard};
use std::process::Command;

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
    let mut child = Command::new("sleep").arg("2").spawn().unwrap();
    std::fs::write(&path, child.id().to_string()).unwrap();
    assert!(signal_reload(&path).is_ok());
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn stale_pid_is_reclaimed_on_acquire() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("reclaim.pid");
    std::fs::write(&path, "999999\n").unwrap();
    let guard = PidFileGuard::acquire(&path).unwrap();
    assert_eq!(guard.pid() as u32, std::process::id());
}
