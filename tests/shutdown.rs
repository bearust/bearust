#![cfg(unix)]

use bearust::{config, reload::signal_loop, runtime::{RuntimeSnapshot, RuntimeStore}};
use nix::{sys::signal::{kill, Signal}, unistd::Pid};
use std::{sync::Arc, time::Duration};
use std::process::Command;

#[tokio::test]
async fn signal_loop_rejects_invalid_hup_then_stops_workers_on_term() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("bearust.toml");
    std::fs::write(&path, include_str!("fixtures/valid.toml")).unwrap();
    let snapshot = RuntimeSnapshot::build(config::load(&path).unwrap(), None).unwrap();
    let store = Arc::new(RuntimeStore::new(snapshot));
    let task = tokio::spawn(signal_loop(
        Arc::clone(&store),
        path.clone(),
        Duration::from_millis(250),
    ));
    // Give Tokio a scheduling turn to install the process signal handlers
    // before delivering the first signal.
    tokio::task::yield_now().await;
    tokio::time::sleep(Duration::from_millis(20)).await;

    std::fs::write(&path, "[server]\nbind = \"broken\"\n").unwrap();
    kill(Pid::this(), Signal::SIGHUP).unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(store.load().generation(), 1);

    kill(Pid::this(), Signal::SIGTERM).unwrap();
    task.await.unwrap().unwrap();
}

#[test]
fn serve_exits_promptly_on_sigterm() {
    let temp = tempfile::tempdir().unwrap();
    let config = temp.path().join("bearust.toml");
    let pid = temp.path().join("bearust.pid");
    let text = include_str!("fixtures/valid.toml")
        .replace("bind = \"127.0.0.1:18080\"", &format!("bind = \"127.0.0.1:18180\"\npid_file = \"{}\"", pid.display()));
    std::fs::write(&config, text).unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_bearust"))
        .args(["serve", "--config"])
        .arg(&config)
        .spawn()
        .unwrap();
    for _ in 0..50 {
        if pid.exists() { break; }
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(pid.exists(), "server did not create pid file");
    kill(Pid::from_raw(child.id() as i32), Signal::SIGTERM).unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        if child.try_wait().unwrap().is_some() { break; }
        assert!(std::time::Instant::now() < deadline, "server did not exit");
        std::thread::sleep(Duration::from_millis(20));
    }
}
