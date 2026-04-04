mod analyzer;
mod cli;
mod config;
mod reporter;
mod sarif;
mod webhook;

use anyhow::Result;
use clap::Parser;
use std::path::PathBuf;
use tracing_subscriber::{fmt, EnvFilter};

pub fn data_dir() -> Result<PathBuf> {
    let dir = directories::BaseDirs::new()
        .map(|b| b.home_dir().join(".conan"))
        .unwrap_or_else(|| PathBuf::from(".conan"));
    std::fs::create_dir_all(&dir)?;
    std::fs::create_dir_all(dir.join("signatures"))?;
    Ok(dir)
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = cli::Cli::parse();

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(if cli.verbose { "debug" } else { "warn" }));
    fmt().with_env_filter(filter).without_time().init();

    match cli.command {
        cli::Commands::Scan(args) => cli::scan::run(args).await,
        cli::Commands::Report(args) => cli::report::run(args).await,
        cli::Commands::Signatures(args) => cli::signatures::run(args).await,
        cli::Commands::Policy(args) => cli::policy::run(args).await,
        cli::Commands::Daemon(args) => cli::daemon_cmd::run(args).await,
        cli::Commands::Service(args) => cli::service::run(args).await,
        cli::Commands::Status => cli::status::run().await,
        cli::Commands::Doctor => cli::doctor::run().await,
        cli::Commands::RunDaemon => cli::daemon_cmd::run_inner().await,
    }
}
