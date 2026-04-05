use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

use crate::sig_updater;

#[derive(Args, Debug)]
pub struct SignatureArgs {
    #[command(subcommand)]
    pub command: SignatureCommands,
}

#[derive(Subcommand, Debug)]
pub enum SignatureCommands {
    /// List all loaded signatures.
    List,
    /// Validate a signature YAML file.
    Validate { file: PathBuf },
    /// Fetch the latest signatures from upstream.
    Update {
        /// Override the upstream base URL.
        #[arg(long)]
        upstream: Option<String>,
    },
    /// View or configure the automatic update schedule.
    Schedule {
        /// Set the auto-update interval in hours (0 to disable).
        #[arg(long)]
        set_hours: Option<u64>,
        /// Disable automatic signature updates.
        #[arg(long, conflicts_with = "set_hours")]
        disable: bool,
    },
}

pub async fn run(args: SignatureArgs) -> Result<()> {
    let data_dir = crate::data_dir()?;
    let sig_dir = data_dir.join("signatures");

    match args.command {
        SignatureCommands::List => {
            let registry = conan_core::registry::Registry::load_from_dir(&sig_dir)?;
            if registry.is_empty() {
                println!("No signatures loaded. Run `conan signatures update`.");
                return Ok(());
            }
            println!("{:<20} {:<10} {:<6}  NAME", "ID", "VERSION", "RISK");
            println!("{}", "-".repeat(60));
            let mut sigs: Vec<_> = registry.all().collect();
            sigs.sort_by(|a, b| a.id.cmp(&b.id));
            for sig in sigs {
                println!(
                    "{:<20} {:<10} {:<6}  {}",
                    sig.id, sig.version, sig.risk_base, sig.name
                );
            }
        }

        SignatureCommands::Validate { file } => {
            let content = std::fs::read_to_string(&file)?;
            match serde_yaml::from_str::<conan_core::registry::Signature>(&content) {
                Ok(sig) => println!("✓ Valid signature: {} ({})", sig.name, sig.id),
                Err(e) => {
                    eprintln!("✗ Invalid signature: {e}");
                    std::process::exit(1);
                }
            }
        }

        SignatureCommands::Update { upstream } => {
            let base = upstream.as_deref().unwrap_or(sig_updater::UPSTREAM_BASE);
            println!(
                "Fetching {} signatures from {base} ...",
                sig_updater::SIGNATURE_FILES.len()
            );
            let (ok, fail) = sig_updater::fetch_and_write(&sig_dir, base).await?;
            // Print per-file status was already handled via tracing; summarise here
            println!("Done: {ok} updated, {fail} failed.");
            if fail > 0 {
                anyhow::bail!("{fail} signature(s) failed to update");
            }
        }

        SignatureCommands::Schedule { set_hours, disable } => {
            let mut cfg = crate::config::ConanConfig::load(&data_dir)?;

            if disable {
                let sig = cfg.signatures.get_or_insert_with(|| crate::config::SigConfig {
                    upstream_base: None,
                    auto_update: None,
                    update_interval_hours: None,
                });
                sig.auto_update = Some(false);
                cfg.save(&data_dir)?;
                println!("Signature auto-update disabled.");
                return Ok(());
            }

            if let Some(hours) = set_hours {
                let sig = cfg.signatures.get_or_insert_with(|| crate::config::SigConfig {
                    upstream_base: None,
                    auto_update: None,
                    update_interval_hours: None,
                });
                if hours == 0 {
                    sig.auto_update = Some(false);
                    println!("Signature auto-update disabled.");
                } else {
                    sig.auto_update = Some(true);
                    sig.update_interval_hours = Some(hours);
                    println!("Signature auto-update set to every {hours} hour(s).");
                }
                cfg.save(&data_dir)?;
                return Ok(());
            }

            // No flags: show current schedule
            let state = sig_updater::SigUpdateState::load(&data_dir);
            match &cfg.signatures {
                Some(s) if s.auto_update == Some(true) => {
                    let interval = s.update_interval_hours.unwrap_or(24);
                    let base = s.upstream_base.as_deref().unwrap_or(sig_updater::UPSTREAM_BASE);
                    println!("Auto-update:  enabled");
                    println!("Interval:     every {interval} hour(s)");
                    println!("Upstream:     {base}");
                    if state.last_updated_at > 0 {
                        let dt = chrono::DateTime::from_timestamp(
                            state.last_updated_at as i64,
                            0,
                        )
                        .map(|t: chrono::DateTime<chrono::Utc>| {
                            t.format("%Y-%m-%d %H:%M UTC").to_string()
                        })
                        .unwrap_or_else(|| "unknown".to_string());
                        println!("Last updated: {dt}");
                        let next_secs =
                            state.last_updated_at + interval * 3600;
                        let next = chrono::DateTime::from_timestamp(next_secs as i64, 0)
                            .map(|t: chrono::DateTime<chrono::Utc>| {
                                t.format("%Y-%m-%d %H:%M UTC").to_string()
                            })
                            .unwrap_or_else(|| "unknown".to_string());
                        println!("Next update:  {next}");
                    } else {
                        println!("Last updated: never");
                    }
                }
                Some(s) if s.auto_update == Some(false) => {
                    println!("Auto-update:  disabled");
                    println!("Tip: enable with `conan signatures schedule --set-hours 24`");
                }
                _ => {
                    println!("Auto-update:  not configured (default: disabled)");
                    println!("Tip: enable with `conan signatures schedule --set-hours 24`");
                }
            }
        }
    }

    Ok(())
}
