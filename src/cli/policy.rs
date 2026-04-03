use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

#[derive(Args, Debug)]
pub struct PolicyArgs {
    #[command(subcommand)]
    pub command: PolicyCommands,
}

#[derive(Subcommand, Debug)]
pub enum PolicyCommands {
    /// Dry-run a policy file — show what rules would fire.
    Check { file: PathBuf },
    /// Lint a policy file for syntax errors.
    Lint { file: PathBuf },
}

pub async fn run(args: PolicyArgs) -> Result<()> {
    match args.command {
        PolicyCommands::Lint { file } | PolicyCommands::Check { file } => {
            let content = std::fs::read_to_string(&file)?;
            match toml::from_str::<conan_core::policy::Policy>(&content) {
                Ok(policy) => {
                    println!("✓ Valid policy: {} rules, default mode: {:?}", policy.rules.len(), policy.mode);
                    for rule in &policy.rules {
                        println!("  - [{}] {:?} → {:?}", rule.id, rule.trigger, rule.action);
                    }
                }
                Err(e) => {
                    eprintln!("✗ Invalid policy: {e}");
                    std::process::exit(1);
                }
            }
        }
    }

    Ok(())
}
