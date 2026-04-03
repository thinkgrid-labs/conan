use anyhow::Result;

pub async fn run() -> Result<()> {
    let data_dir = crate::data_dir()?;
    let pid_file = data_dir.join("daemon.pid");

    if !pid_file.exists() {
        println!("○ conan daemon is not running.");
        println!("  Start it with: conan daemon start");
        return Ok(());
    }

    let pid = std::fs::read_to_string(&pid_file).unwrap_or_default();
    let pid = pid.trim();

    // Check findings count for today
    let findings_today = if data_dir.join("findings.db").exists() {
        conan_db::Store::open(&data_dir.join("findings.db"))
            .and_then(|s| s.finding_count_today())
            .unwrap_or(0)
    } else {
        0
    };

    println!("● conan daemon running (pid {pid})");
    println!("  findings today : {findings_today}");
    println!("  data dir       : {}", data_dir.display());

    Ok(())
}
