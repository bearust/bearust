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
fn help_documents_every_subcommand() {
    let output = Command::new(env!("CARGO_BIN_EXE_bearust"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    for command in ["serve", "validate", "reload", "plugin"] {
        assert!(stdout.contains(command), "{stdout}");
    }
    // No subcommand may render without a description.
    for line in stdout
        .lines()
        .skip_while(|line| !line.contains("Commands:"))
    {
        let trimmed = line.trim();
        if ["serve", "validate", "reload", "plugin", "help"]
            .iter()
            .any(|command| trimmed.starts_with(command))
            && !trimmed.starts_with("help")
        {
            assert!(
                trimmed.len() > trimmed.split_whitespace().next().unwrap_or_default().len() + 1,
                "subcommand without description: {trimmed:?}"
            );
        }
    }
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
