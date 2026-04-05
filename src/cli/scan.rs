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
    /// Live packet capture via libpcap. Requires elevated privileges and
    /// the pcap-capture feature (cargo build --features pcap-capture).
    Pcap,
    All,
}

#[derive(Debug, Clone, ValueEnum)]
pub enum OutputFormat {
    Pretty,
    Json,
    Markdown,
    Sarif,
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

    /// Seconds to capture packets (--source pcap only). Default: 10.
    #[arg(long, default_value = "10")]
    pub pcap_secs: u64,

    /// Network interface for pcap capture (--source pcap only). Default: system default.
    #[arg(long)]
    pub pcap_iface: Option<String>,

    /// Only re-scan files changed since the last run (git-aware, codebase source only).
    #[arg(long, default_value = "false")]
    pub diff: bool,
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
    let cfg = crate::config::ConanConfig::load(&data_dir)?;
    let mut webhook = cfg
        .webhook
        .as_ref()
        .map(crate::webhook::WebhookClient::from_config);

    // --diff: load persisted scan state once before the loop
    let scan_root = args
        .path
        .canonicalize()
        .unwrap_or_else(|_| args.path.clone());
    let mut scan_state = if args.diff {
        crate::diff::ScanState::load(&data_dir)
    } else {
        crate::diff::ScanState::default()
    };

    loop {
        // Compute the set of changed files (only used when --diff + codebase source)
        let diff_filter = if args.diff {
            let commit = crate::diff::current_commit(&scan_root);
            let changed = crate::diff::changed_files(&scan_root, &scan_state, commit.as_deref());
            if changed.is_empty() {
                eprintln!("--diff: no changed files detected, skipping codebase scan.");
            } else {
                eprintln!("--diff: {} changed file(s) will be scanned.", changed.len());
            }
            Some(changed)
        } else {
            None
        };

        let events = collect_events(&args, &ctx, diff_filter.as_ref()).await?;
        let analyzer = CoreAnalyzer;
        let findings = analyzer.analyze(events, &ctx).await;

        // Persist to DB
        for f in &findings {
            store.insert_finding(f)?;
        }

        // Webhook: fire for high/critical findings
        if let Some(ref mut wh) = webhook {
            use conan_core::finding::RiskLevel;
            let actionable: Vec<_> = findings
                .iter()
                .filter(|f| matches!(f.risk_level, RiskLevel::High | RiskLevel::Critical))
                .cloned()
                .collect();
            if !actionable.is_empty() {
                wh.fire(&actionable).await;
            }
        }

        // Output
        let output = match args.output {
            OutputFormat::Json => reporter::json(&findings),
            OutputFormat::Markdown => reporter::markdown(&findings),
            OutputFormat::Pretty => reporter::pretty(&findings),
            OutputFormat::Sarif => crate::sarif::sarif(&findings),
        };
        println!("{output}");

        // Persist --diff state after each pass
        if args.diff {
            let commit = crate::diff::current_commit(&scan_root);
            scan_state.last_commit = commit;
            scan_state.mtimes = crate::diff::snapshot_mtimes(&scan_root);
            if let Err(e) = scan_state.save(&data_dir) {
                eprintln!("Warning: failed to save scan state: {e}");
            }
        }

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
    diff_filter: Option<&std::collections::HashSet<std::path::PathBuf>>,
) -> Result<Vec<conan_core::event::Event>> {
    use conan_core::traits::Ingestor;

    let mut all_events = vec![];

    match args.source {
        ScanSource::Os | ScanSource::All => {
            let proc = conan_os::ProcessIngestor::new(ctx.registry.clone());
            all_events.extend(proc.ingest().await?);

            let shell = conan_os::ShellHistoryIngestor::new(ctx.registry.clone());
            all_events.extend(shell.ingest().await?);
        }
        _ => {}
    }

    match args.source {
        ScanSource::Browser | ScanSource::All => {
            let browser = conan_os::BrowserHistoryIngestor::new(ctx.registry.clone());
            all_events.extend(browser.ingest().await?);
        }
        _ => {}
    }

    match args.source {
        ScanSource::Net | ScanSource::All => {
            let dns = conan_net::DnsIngestor::new(ctx.registry.clone());
            all_events.extend(dns.ingest().await?);

            let conns = conan_net::ActiveConnectionIngestor::new(ctx.registry.clone());
            all_events.extend(conns.ingest().await?);
        }
        _ => {}
    }

    if matches!(args.source, ScanSource::Codebase | ScanSource::All) {
        let mut cb = conan_os::CodebaseIngestor::new(ctx.registry.clone(), args.path.clone());
        if let Some(filter) = diff_filter {
            cb = cb.with_filter(filter.clone());
        }
        all_events.extend(cb.ingest().await?);
    }

    if let ScanSource::Pcap = args.source {
        all_events.extend(collect_pcap(ctx, args.pcap_secs, args.pcap_iface.as_deref()).await?);
    }

    Ok(all_events)
}

#[cfg(feature = "pcap-capture")]
async fn collect_pcap(
    ctx: &ScanContext,
    secs: u64,
    iface: Option<&str>,
) -> Result<Vec<conan_core::event::Event>> {
    use conan_core::traits::Ingestor;
    eprintln!("Starting pcap capture for {secs}s (Ctrl-C to stop early)...");
    let mut ing = conan_net::PcapIngestor::new(ctx.registry.clone()).with_duration(secs);
    if let Some(i) = iface {
        ing = ing.with_interface(i);
    }
    Ok(ing.ingest().await?)
}

#[cfg(not(feature = "pcap-capture"))]
async fn collect_pcap(
    _ctx: &ScanContext,
    _secs: u64,
    _iface: Option<&str>,
) -> Result<Vec<conan_core::event::Event>> {
    anyhow::bail!(
        "pcap capture requires the pcap-capture feature and libpcap.\n\
         Install libpcap: apt install libpcap-dev  OR  brew install libpcap\n\
         Then rebuild:    cargo build --features pcap-capture"
    )
}
