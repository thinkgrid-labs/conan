use anyhow::Result;
use clap::{Args, Subcommand};
use std::path::PathBuf;

/// Known bundled signature filenames (kept in sync with the `signatures/` directory).
const SIGNATURE_FILES: &[&str] = &[
    "anthropic.yaml",
    "azure-openai.yaml",
    "cohere.yaml",
    "google-ai.yaml",
    "groq.yaml",
    "huggingface.yaml",
    "localai.yaml",
    "mistral.yaml",
    "ollama.yaml",
    "openai.yaml",
    "perplexity.yaml",
];

const UPSTREAM_BASE: &str =
    "https://raw.githubusercontent.com/thinkgrid-labs/conan/main/signatures";

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
            let base = upstream.as_deref().unwrap_or(UPSTREAM_BASE);
            println!(
                "Fetching {} signatures from {base} ...",
                SIGNATURE_FILES.len()
            );
            std::fs::create_dir_all(&sig_dir)?;

            let client = reqwest::Client::builder()
                .user_agent(concat!("conan/", env!("CARGO_PKG_VERSION")))
                .timeout(std::time::Duration::from_secs(30))
                .build()?;

            let mut ok = 0usize;
            let mut fail = 0usize;

            for filename in SIGNATURE_FILES {
                let url = format!("{base}/{filename}");
                match client.get(&url).send().await {
                    Ok(resp) if resp.status().is_success() => {
                        match resp.text().await {
                            Ok(body) => {
                                // Validate before writing
                                if let Err(e) =
                                    serde_yaml::from_str::<conan_core::registry::Signature>(&body)
                                {
                                    eprintln!("  ✗ {filename}: invalid YAML ({e})");
                                    fail += 1;
                                } else {
                                    std::fs::write(sig_dir.join(filename), &body)?;
                                    println!("  ✓ {filename}");
                                    ok += 1;
                                }
                            }
                            Err(e) => {
                                eprintln!("  ✗ {filename}: read error ({e})");
                                fail += 1;
                            }
                        }
                    }
                    Ok(resp) => {
                        eprintln!("  ✗ {filename}: HTTP {}", resp.status());
                        fail += 1;
                    }
                    Err(e) => {
                        eprintln!("  ✗ {filename}: {e}");
                        fail += 1;
                    }
                }
            }

            println!("\nDone: {ok} updated, {fail} failed.");
            if fail > 0 {
                anyhow::bail!("{fail} signature(s) failed to update");
            }
        }
    }

    Ok(())
}
