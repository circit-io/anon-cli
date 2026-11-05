use std::path::PathBuf;
use std::process::Command;

fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_anon-cli"))
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(name)
}

#[test]
fn version_flag_reports_crate_version() {
    let output = cli()
        .arg("--version")
        .output()
        .expect("run anon-cli --version");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains(env!("CARGO_PKG_VERSION")),
        "stdout: {stdout}"
    );
}

#[test]
fn bench_subcommand_reports_throughput_for_generated_rows() {
    let tmpdir = std::env::temp_dir().join(format!("anon-cli-bench-cli-{}", std::process::id()));
    let output = cli()
        .arg("bench")
        .arg("--policy")
        .arg(fixture("policy_valid.yaml"))
        .args(["--rows", "2000"])
        .arg("--tmpdir")
        .arg(&tmpdir)
        .output()
        .expect("run anon-cli bench");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&stdout).expect("bench prints JSON");
    assert_eq!(parsed["rows_generated"], 2000);
    assert_eq!(parsed["rows_processed"], 2000);
    assert!(parsed["rows_per_sec"].as_f64().unwrap_or(0.0) > 0.0);
    std::fs::remove_dir_all(&tmpdir).ok();
}
