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
fn pdf_rejects_date_false_positive_in_sort_code_roster_entry() {
    let tmpdir = std::env::temp_dir().join(format!("anon-cli-roster-cli-{}", std::process::id()));
    std::fs::create_dir_all(&tmpdir).unwrap();
    let input = tmpdir.join("in.pdf");
    let output = tmpdir.join("out.pdf");
    // minimal valid one-page pdf
    std::fs::write(&input, b"%PDF-1.7\n").unwrap();
    let result = cli()
        .arg("pdf")
        .arg("--input")
        .arg(&input)
        .arg("--output")
        .arg(&output)
        .arg("--policy")
        .arg(fixture("policy_valid.yaml"))
        .arg("--redact")
        .arg("2024-01-15:sort_code")
        .output()
        .expect("run anon-cli pdf");
    assert!(
        !result.status.success(),
        "date-shaped sort_code roster entry must be rejected"
    );
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        stderr.contains("sort_code"),
        "stderr should name the failed validation: {stderr}"
    );
    std::fs::remove_dir_all(&tmpdir).ok();
}

#[test]
fn roster_extract_emits_narrowed_matches_from_text_file() {
    let tmpdir =
        std::env::temp_dir().join(format!("anon-cli-roster-extract-{}", std::process::id()));
    std::fs::create_dir_all(&tmpdir).unwrap();
    let input = tmpdir.join("doc.txt");
    std::fs::write(
        &input,
        "dated 2024-01-15, sort code 20-30-40, acct 12345678, card 1234-5678-9012-3456\n",
    )
    .unwrap();
    let output = cli()
        .arg("roster")
        .arg("extract")
        .arg("--input")
        .arg(&input)
        .output()
        .expect("run anon-cli roster extract");
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut lines: Vec<&str> = stdout.lines().collect();
    lines.sort_unstable();
    assert_eq!(lines, vec!["12345678:account_number", "20-30-40:sort_code"]);
    std::fs::remove_dir_all(&tmpdir).ok();
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
