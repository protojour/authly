use std::path::PathBuf;

use authly::{initialize, issue_service_identity, serve};
use clap::{Parser, Subcommand};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(version, about, arg_required_else_help(true))]
struct Cli {
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Run Authly in server/cluster mode
    Serve,
    /// Issue mTLS credentials for a service
    IssueServiceIdentity {
        #[clap(long)]
        eid: String,

        #[clap(long)]
        out: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::from("info"))
        .init();

    match Cli::parse().command {
        Some(Command::Serve) => serve().await?,
        Some(Command::IssueServiceIdentity { eid, out }) => {
            issue_service_identity(eid, out).await?
        }
        None => {}
    }

    Ok(())
}
