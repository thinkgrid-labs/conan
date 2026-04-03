use anyhow::Result;
use clap::{Args, Subcommand};

#[derive(Args, Debug)]
pub struct ServiceArgs {
    #[command(subcommand)]
    pub command: ServiceCommands,
}

#[derive(Subcommand, Debug)]
pub enum ServiceCommands {
    /// Install conan as a system service (launchd/systemd).
    Install,
    /// Uninstall the system service.
    Uninstall,
    /// Show service status.
    Status,
}

pub async fn run(args: ServiceArgs) -> Result<()> {
    match args.command {
        ServiceCommands::Status => {
            println!("Service management not yet implemented. (M2)");
        }
        ServiceCommands::Install => {
            #[cfg(target_os = "macos")]
            {
                println!("Installing launchd plist... (M2)");
            }
            #[cfg(target_os = "linux")]
            {
                println!("Installing systemd unit... (M2)");
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                eprintln!("Service install not supported on this platform.");
            }
        }
        ServiceCommands::Uninstall => {
            println!("Service uninstall not yet implemented. (M2)");
        }
    }

    Ok(())
}
