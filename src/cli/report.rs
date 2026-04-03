use anyhow::Result;
use clap::Args;

#[derive(Args, Debug)]
pub struct ReportArgs {
    /// Show findings from the last N hours. (e.g. 24)
    #[arg(long)]
    pub last: Option<u32>,

    /// Stream new findings live from the daemon.
    #[arg(long)]
    pub live: bool,
}

pub async fn run(args: ReportArgs) -> Result<()> {
    let data_dir = crate::data_dir()?;
    let store = conan_db::Store::open(&data_dir.join("findings.db"))?;
    let findings = store.query_findings(args.last)?;

    if findings.is_empty() {
        println!("No findings.");
        return Ok(());
    }

    for f in &findings {
        let level = f["risk_level"].as_str().unwrap_or("?");
        let service = f["service_name"].as_str().unwrap_or("unknown");
        let detail = f["detail"].as_str().unwrap_or("");
        let ts = f["timestamp"].as_str().unwrap_or("");
        println!("[{level:<8}]  {service:<20} {detail}  ({ts})");
    }

    Ok(())
}
