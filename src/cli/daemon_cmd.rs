use anyhow::Result;
use clap::{Args, Subcommand};

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

pub async fn run(args: DaemonArgs) -> Result<()> {
    let data_dir = crate::data_dir()?;
    let pid_file = data_dir.join("daemon.pid");

    match args.command {
        DaemonCommands::Start => {
            if pid_file.exists() {
                let pid = std::fs::read_to_string(&pid_file)?;
                eprintln!(
                    "Daemon already running (pid {pid}). Use `conan daemon restart` to restart."
                );
                return Ok(());
            }
            println!("Starting conan daemon...");
            // TODO: fork process, write PID file, start tokio runtime with watcher tasks
            println!("Daemon start not yet fully implemented. (M2)");
        }

        DaemonCommands::Stop => {
            if !pid_file.exists() {
                eprintln!("Daemon is not running.");
                return Ok(());
            }
            let pid: u32 = std::fs::read_to_string(&pid_file)?.trim().parse()?;
            unsafe {
                libc::kill(pid as i32, libc::SIGTERM);
            }
            std::fs::remove_file(&pid_file)?;
            println!("Sent SIGTERM to daemon (pid {pid}).");
        }

        DaemonCommands::Restart => {
            // Stop then start
            if pid_file.exists() {
                let pid: u32 = std::fs::read_to_string(&pid_file)?.trim().parse()?;
                unsafe {
                    libc::kill(pid as i32, libc::SIGTERM);
                }
                std::fs::remove_file(&pid_file)?;
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
            println!("Restarting conan daemon... (M2)");
        }

        DaemonCommands::Logs { follow } => {
            let log_file = data_dir.join("daemon.log");
            if !log_file.exists() {
                println!("No daemon log found at {}", log_file.display());
                return Ok(());
            }
            let content = std::fs::read_to_string(&log_file)?;
            println!("{content}");
            if follow {
                println!("(--follow not yet implemented in M1)");
            }
        }
    }

    Ok(())
}
