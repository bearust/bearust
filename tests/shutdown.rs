#![cfg(unix)]

use bearust::{config, reload::signal_loop, runtime::{RuntimeSnapshot, RuntimeStore}};
use nix::{sys::signal::{kill, Signal}, unistd::Pid};
use std::{sync::Arc, time::Duration};

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
