use anyhow::Result;
use clap::{Args, ValueEnum};
use conan_core::{
    policy::Policy,
    registry::Registry,
    traits::{Analyzer, ScanContext},
};
use std::path::PathBuf;

use crate::{analyzer::CoreAnalyzer, reporter};

#[derive(Debug, Clone, ValueEnum)]
pub enum ScanSource {
    Net,
    Os,
    Browser,
    Shell,
    Codebase,
    All,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
    Markdown,
}

#[derive(Args, Debug)]
pub struct ScanArgs {
    /// Sources to scan.
    #[arg(short, long, value_enum, default_value = "all")]
    pub source: ScanSource,

    /// Path to policy TOML file.
    #[arg(short, long)]
    pub policy: Option<PathBuf>,

    /// Output format.
    #[arg(short, long, value_enum, default_value = "pretty")]
    pub output: OutputFormat,

    /// Path for codebase scanning (used with --source codebase).
    #[arg(long, default_value = ".")]
    pub path: PathBuf,

    /// Run continuously, re-scanning every N seconds.
    #[arg(short, long)]
    pub watch: Option<u64>,
}

pub async fn run(args: ScanArgs) -> Result<()> {
    let data_dir = crate::data_dir()?;
    let sig_dir = data_dir.join("signatures");

    let registry = Registry::load_from_dir(&sig_dir)?;

    if registry.is_empty() {
        eprintln!("No signatures loaded. Run `conan signatures update` first.");
    } else {
        eprintln!("Loaded {} signatures.", registry.len());
    }

    let policy = if let Some(p) = &args.policy {
        Policy::load(p)?
    } else {
        let default_policy = data_dir.join("policy.toml");
        if default_policy.exists() {
            Policy::load(&default_policy)?
        } else {
            Policy::default()
        }
    };

    let ctx = ScanContext { registry, policy };
    let store = conan_db::Store::open(&data_dir.join("findings.db"))?;

    loop {
        let events = collect_events(&args, &ctx).await?;
        let analyzer = CoreAnalyzer;
        let findings = analyzer.analyze(events, &ctx).await;

        // Persist to DB
        for f in &findings {
            store.insert_finding(f)?;
        }

        // Output
        let output = match args.output {
            OutputFormat::Json => reporter::json(&findings),
            OutputFormat::Markdown => reporter::markdown(&findings),
            OutputFormat::Pretty => reporter::pretty(&findings),
        };
        println!("{output}");

        match args.watch {
            Some(secs) => tokio::time::sleep(tokio::time::Duration::from_secs(secs)).await,
            None => break,
        }
    }

    Ok(())
}

async fn collect_events(
    args: &ScanArgs,
    ctx: &ScanContext,
) -> Result<Vec<conan_core::event::Event>> {
    use conan_core::traits::Ingestor;

    // We need a fresh Registry clone per ingestor since they take ownership.
    // This is acceptable at scan-time (not hot path).
    let mut all_events = vec![];

    match args.source {
        ScanSource::Os | ScanSource::All => {
            let proc = conan_os::ProcessIngestor::new(rebuild_registry(ctx)?);
            all_events.extend(proc.ingest().await?);

            let shell = conan_os::ShellHistoryIngestor::new(rebuild_registry(ctx)?);
            all_events.extend(shell.ingest().await?);
        }
        _ => {}
    }

    match args.source {
        ScanSource::Browser | ScanSource::All => {
            let browser = conan_os::BrowserHistoryIngestor::new(rebuild_registry(ctx)?);
            all_events.extend(browser.ingest().await?);
        }
        _ => {}
    }

    match args.source {
        ScanSource::Net | ScanSource::All => {
            let dns = conan_net::DnsIngestor::new(rebuild_registry(ctx)?);
            all_events.extend(dns.ingest().await?);

            let conns = conan_net::ActiveConnectionIngestor::new(rebuild_registry(ctx)?);
            all_events.extend(conns.ingest().await?);
        }
        _ => {}
    }

    if let ScanSource::Codebase = args.source {
        let cb = conan_os::CodebaseIngestor::new(rebuild_registry(ctx)?, args.path.clone());
        all_events.extend(cb.ingest().await?);
    }

    Ok(all_events)
}

/// Reload the registry from disk to give ownership to each ingestor.
fn rebuild_registry(_ctx: &ScanContext) -> Result<Registry> {
    let data_dir = crate::data_dir()?;
    let sig_dir = data_dir.join("signatures");
    Ok(Registry::load_from_dir(&sig_dir)?)
}
