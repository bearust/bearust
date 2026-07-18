use std::process::Command;

#[test]
fn validate_accepts_valid_file_without_opening_listener() {
    let output = Command::new(env!("CARGO_BIN_EXE_bearust"))
        .args(["validate", "--config", "tests/fixtures/valid.toml"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    assert!(String::from_utf8_lossy(&output.stdout).contains("configuration is valid"));
}

#[test]
fn validate_reports_missing_file_actionably() {
    let output = Command::new(env!("CARGO_BIN_EXE_bearust"))
        .args(["validate", "--config", "/definitely/missing/bearust.toml"])
        .output()
        .unwrap();
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("cannot read configuration"));
}

#[test]
fn version_is_reported() {
    let output = Command::new(env!("CARGO_BIN_EXE_bearust"))
        .arg("--version")
        .output()
        .unwrap();
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("bearust 0.1.0"));
}
