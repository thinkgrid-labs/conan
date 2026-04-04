use anyhow::Result;
use clap::{Args, Subcommand};
use conan_core::{
    policy::Policy,
    registry::Registry,
    traits::{Analyzer, Ingestor, ScanContext},
};

#[derive(Args, Debug)]
pub struct DaemonArgs {
    #[command(subcommand)]
    pub command: DaemonCommands,
}

#[derive(Subcommand, Debug)]
pub enum DaemonCommands {
    /// Start the background daemon.
    Start,
    /// Stop the background daemon.
    Stop,
    /// Restart the background daemon.
    Restart,
    /// Tail the daemon logs.
    Logs {
        #[arg(short, long)]
        follow: bool,
    },
}

fn terminate_process(pid: u32) {
    #[cfg(unix)]
    unsafe {
        libc::kill(pid as i32, libc::SIGTERM);
    }

    #[cfg(windows)]
    unsafe {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::{
            OpenProcess, TerminateProcess, PROCESS_TERMINATE,
        };
        let handle = OpenProcess(PROCESS_TERMINATE, 0, pid);
        if !handle.is_null() {
            TerminateProcess(handle, 1);
            CloseHandle(handle);
        }
    }
}

pub async fn run(args: DaemonArgs) -> Result<()> {
    let data_dir = crate::data_dir()?;
    let pid_file = data_dir.join("daemon.pid");
    let log_file = data_dir.join("daemon.log");

    match args.command {
        DaemonCommands::Start => {
            if pid_file.exists() {
                let pid = std::fs::read_to_string(&pid_file)?;
                eprintln!(
                    "Daemon already running (pid {}). Use `conan daemon restart` to restart.",
                    pid.trim()
                );
                return Ok(());
            }

            let exe = std::env::current_exe()?;
            let log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file)?;
            let log_err = log.try_clone()?;

            let child = std::process::Command::new(&exe)
                .arg("_run-daemon")
                .stdout(log)
                .stderr(log_err)
                .spawn()?;

            let pid = child.id();
            std::fs::write(&pid_file, pid.to_string())?;
            println!("Daemon started (pid {pid}). Logs: {}", log_file.display());
        }

        DaemonCommands::Stop => {
            if !pid_file.exists() {
                eprintln!("Daemon is not running.");
                return Ok(());
            }
            let pid: u32 = std::fs::read_to_string(&pid_file)?.trim().parse()?;
            terminate_process(pid);
            std::fs::remove_file(&pid_file)?;
            println!("Terminated daemon (pid {pid}).");
        }

        DaemonCommands::Restart => {
            if pid_file.exists() {
                let pid: u32 = std::fs::read_to_string(&pid_file)?.trim().parse()?;
                terminate_process(pid);
                std::fs::remove_file(&pid_file)?;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }

            let exe = std::env::current_exe()?;
            let log = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file)?;
            let log_err = log.try_clone()?;

            let child = std::process::Command::new(&exe)
                .arg("_run-daemon")
                .stdout(log)
                .stderr(log_err)
                .spawn()?;

            let pid = child.id();
            std::fs::write(&pid_file, pid.to_string())?;
            println!("Daemon restarted (pid {pid}).");
        }

        DaemonCommands::Logs { follow } => {
            if !log_file.exists() {
                println!("No daemon log found at {}", log_file.display());
                return Ok(());
            }
            let content = std::fs::read_to_string(&log_file)?;
            print!("{content}");
            if follow {
                println!(
                    "(--follow: use `tail -f {}` for real-time tailing)",
                    log_file.display()
                );
            }
        }
    }

    Ok(())
}

/// The actual daemon event loop — invoked via `conan _run-daemon`.
pub async fn run_inner() -> Result<()> {
    let data_dir = crate::data_dir()?;
    let pid_file = data_dir.join("daemon.pid");
    let sig_dir = data_dir.join("signatures");
    let policy_path = data_dir.join("policy.toml");
    let db_path = data_dir.join("findings.db");

    // Write our own PID (the parent wrote the child PID but this confirms it)
    std::fs::write(&pid_file, std::process::id().to_string())?;

    let cfg = crate::config::ConanConfig::load(&data_dir)?;
    let interval = cfg
        .daemon
        .as_ref()
        .and_then(|d| d.scan_interval_secs)
        .unwrap_or(300);

    let store = conan_db::Store::open(&db_path)?;
    let mut webhook = cfg
        .webhook
        .as_ref()
        .map(crate::webhook::WebhookClient::from_config);

    tracing::info!(
        pid = std::process::id(),
        interval_secs = interval,
        "conan daemon started"
    );

    loop {
        let registry = match Registry::load_from_dir(&sig_dir) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!("daemon: failed to load signatures: {e}");
                tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
                continue;
            }
        };

        let policy = if policy_path.exists() {
            Policy::load(&policy_path).unwrap_or_default()
        } else {
            Policy::default()
        };

        let ctx = ScanContext {
            registry: registry.clone(),
            policy,
        };

        let mut events = vec![];

        let proc = conan_os::ProcessIngestor::new(registry.clone());
        events.extend(proc.ingest().await.unwrap_or_default());

        let shell = conan_os::ShellHistoryIngestor::new(registry.clone());
        events.extend(shell.ingest().await.unwrap_or_default());

        let browser = conan_os::BrowserHistoryIngestor::new(registry.clone());
        events.extend(browser.ingest().await.unwrap_or_default());

        let net = conan_net::ActiveConnectionIngestor::new(registry.clone());
        events.extend(net.ingest().await.unwrap_or_default());

        let dns = conan_net::DnsIngestor::new(registry.clone());
        events.extend(dns.ingest().await.unwrap_or_default());

        let analyzer = crate::analyzer::CoreAnalyzer;
        let findings = analyzer.analyze(events, &ctx).await;

        for f in &findings {
            if let Err(e) = store.insert_finding(f) {
                tracing::warn!("daemon: failed to store finding: {e}");
            }
        }

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

        if !findings.is_empty() {
            tracing::info!("daemon: {} new findings this cycle", findings.len());
        }

        tokio::time::sleep(tokio::time::Duration::from_secs(interval)).await;
    }
}
