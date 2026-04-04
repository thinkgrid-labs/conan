pub mod daemon_cmd;
pub mod doctor;
pub mod policy;
pub mod report;
pub mod scan;
pub mod service;
pub mod signatures;
pub mod status;

use clap::{Parser, Subcommand};

#[derive(Parser)]
#[command(
    name = "conan",
    about = "Detect, inspect, and govern AI service usage across your infrastructure.",
    version,
    propagate_version = true
)]
pub struct Cli {
    /// Enable verbose/debug output.
    #[arg(short, long, global = true)]
    pub verbose: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Run a one-shot scan against one or more sources.
    Scan(scan::ScanArgs),
    /// Query findings from the local database.
    Report(report::ReportArgs),
    /// Manage AI service signatures.
    Signatures(signatures::SignatureArgs),
    /// Validate or lint policy files.
    Policy(policy::PolicyArgs),
    /// Control the background daemon.
    Daemon(daemon_cmd::DaemonArgs),
    /// Install/uninstall conan as an OS service.
    Service(service::ServiceArgs),
    /// Show the status of the running daemon.
    Status,
    /// Check that conan's environment is healthy.
    Doctor,
    /// Internal: run the daemon event loop in this process (do not call directly).
    #[command(name = "_run-daemon", hide = true)]
    RunDaemon,
}
