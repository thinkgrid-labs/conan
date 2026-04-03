use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

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
    /// Fetch the latest signatures from the upstream registry.
    Update,
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
                println!("{:<20} {:<10} {:<6}  {}", sig.id, sig.version, sig.risk_base, sig.name);
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

        SignatureCommands::Update => {
            println!("Fetching latest signatures from upstream...");
            // TODO: implement HTTP fetch from GitHub releases in M2
            println!("Signature update not yet implemented. Copy YAML files to: {}", sig_dir.display());
        }
    }

    Ok(())
}
