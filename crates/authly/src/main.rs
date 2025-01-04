use std::path::PathBuf;

use authly::{cert::MakeSigningRequest, issue_service_identity, serve};
use clap::{Parser, Subcommand};
use rcgen::KeyPair;
use time::Duration;
use tracing::info;
use tracing_subscriber::EnvFilter;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

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
    IssueClusterKey {
        #[clap(long)]
        out_path: PathBuf,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::from("info"))
        .init();

    info!("🧠 Authly v{VERSION}");

    match Cli::parse().command {
        Some(Command::Serve) => serve().await?,
        Some(Command::IssueServiceIdentity { eid, out }) => {
            issue_service_identity(eid, out).await?
        }
        Some(Command::IssueClusterKey { out_path }) => {
            let req = KeyPair::generate()?.server_cert("*.authly-cluster", Duration::days(10000));
            let certificate = req.params.self_signed(&req.key)?;

            std::fs::write(out_path.join("cluster.key"), req.key.serialize_pem())?;
            std::fs::write(out_path.join("cluster.crt"), certificate.pem())?;
        }
        None => {}
    }

    Ok(())
}
