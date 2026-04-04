use assert_cmd::Command;
use predicates::prelude::PredicateBooleanExt;
use predicates::str::contains;

fn conan() -> Command {
    Command::cargo_bin("conan").unwrap()
}

// ── top-level flags ───────────────────────────────────────────────────────────

#[test]
fn help_flag_succeeds() {
    conan()
        .arg("--help")
        .assert()
        .success()
        .stdout(contains("conan"));
}

#[test]
fn version_flag_succeeds() {
    conan()
        .arg("--version")
        .assert()
        .success()
        .stdout(contains("conan"));
}

// ── doctor ───────────────────────────────────────────────────────────────────

#[test]
fn doctor_runs_without_panic() {
    conan().arg("doctor").assert().success();
}

#[test]
fn doctor_output_contains_expected_labels() {
    conan()
        .arg("doctor")
        .assert()
        .success()
        .stdout(contains("data directory"))
        .stdout(contains("signatures loaded"))
        .stdout(contains("findings database"));
}

// ── signatures ───────────────────────────────────────────────────────────────

#[test]
fn signatures_validate_openai_yaml() {
    conan()
        .args(["signatures", "validate", "signatures/openai.yaml"])
        .assert()
        .success()
        .stdout(contains("Valid signature"));
}

#[test]
fn signatures_validate_all_bundled() {
    let sig_dir = std::fs::read_dir("signatures").unwrap();
    for entry in sig_dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("yaml") {
            conan()
                .args(["signatures", "validate", path.to_str().unwrap()])
                .assert()
                .success();
        }
    }
}

#[test]
fn signatures_validate_invalid_yaml_fails() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.yaml");
    std::fs::write(&bad, "id: \nname: \nversion: bad\nrisk_base: not_a_number").unwrap();

    conan()
        .args(["signatures", "validate", bad.to_str().unwrap()])
        .assert()
        .failure();
}

#[test]
fn signatures_list_runs() {
    conan().args(["signatures", "list"]).assert().success();
}

// ── policy ────────────────────────────────────────────────────────────────────

#[test]
fn policy_lint_default_toml() {
    conan()
        .args(["policy", "lint", "policy/default.toml"])
        .assert()
        .success()
        .stdout(contains("Valid policy"));
}

#[test]
fn policy_check_default_toml() {
    conan()
        .args(["policy", "check", "policy/default.toml"])
        .assert()
        .success();
}

#[test]
fn policy_lint_invalid_toml_fails() {
    let dir = tempfile::tempdir().unwrap();
    let bad = dir.path().join("bad.toml");
    std::fs::write(&bad, "this is not valid toml !!!").unwrap();

    conan()
        .args(["policy", "lint", bad.to_str().unwrap()])
        .assert()
        .failure();
}

// ── status ────────────────────────────────────────────────────────────────────

#[test]
fn status_runs_when_no_daemon() {
    // daemon is not running → should still exit 0 with a clear message
    conan()
        .arg("status")
        .assert()
        .success()
        .stdout(contains("daemon"));
}

// ── report ────────────────────────────────────────────────────────────────────

#[test]
fn report_runs_with_empty_db() {
    conan()
        .args(["report"])
        .assert()
        .success()
        .stdout(contains("No findings").or(contains("risk_level").or(contains("["))));
}
