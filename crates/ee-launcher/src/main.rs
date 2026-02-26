mod config;
mod oci;
mod preflight;
mod qemu;

use clap::{Parser, Subcommand};
use ee_common::config::LauncherConfig;

#[derive(Debug, Parser)]
#[command(name = "ee")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    Launch {
        image: String,
        #[arg(long)]
        cp: bool,
        #[arg(long)]
        owner: Option<String>,
    },
    Stop {
        vm_id: String,
    },
    List,
    Logs {
        vm_id: String,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    let config = LauncherConfig::from_env();

    if let Err(err) = preflight::run(&config).await {
        eprintln!("preflight failed: {err}");
        std::process::exit(1);
    }

    let result = match cli.command {
        Command::Launch { image, cp, owner } => match oci::extract_image(&image).await {
            Ok(extracted) => qemu::launch_vm(&config, &extracted, cp, owner).await,
            Err(err) => Err(err),
        },
        Command::Stop { vm_id } => qemu::stop_vm(&config, &vm_id).await,
        Command::List => qemu::list_vms(&config).await,
        Command::Logs { vm_id } => qemu::logs(&config, &vm_id).await,
    };

    if let Err(err) = result {
        eprintln!("launcher failed: {err}");
        std::process::exit(1);
    }
}
