use anyhow::Result;

pub async fn run() -> Result<()> {
    println!("conan doctor\n");

    let data_dir = crate::data_dir()?;
    check(
        "data directory",
        data_dir.exists(),
        &data_dir.display().to_string(),
    );

    let sig_dir = data_dir.join("signatures");
    let sig_count = if sig_dir.exists() {
        std::fs::read_dir(&sig_dir)
            .map(|d| {
                d.filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("yaml"))
                    .count()
            })
            .unwrap_or(0)
    } else {
        0
    };
    check(
        "signatures loaded",
        sig_count > 0,
        &format!("{sig_count} YAML files in {}", sig_dir.display()),
    );

    let policy_file = data_dir.join("policy.toml");
    check(
        "default policy",
        policy_file.exists(),
        &policy_file.display().to_string(),
    );

    let db_file = data_dir.join("findings.db");
    check(
        "findings database",
        db_file.exists(),
        &db_file.display().to_string(),
    );

    // Check for libpcap (needed for --source net)
    let pcap_available = std::process::Command::new("which")
        .arg("tcpdump")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    check(
        "libpcap (for net scanning)",
        pcap_available,
        "install with: brew install libpcap",
    );

    Ok(())
}

fn check(label: &str, ok: bool, detail: &str) {
    let icon = if ok { "✓" } else { "✗" };
    let note = if ok {
        detail.to_string()
    } else {
        format!("MISSING — {detail}")
    };
    println!("  {icon} {label:<30} {note}");
}
