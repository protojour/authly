use authly::{cert::MakeSigningRequest, configure, serve, EnvConfig};
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

    /// Import documents and do general configuration, then exit
    Configure,

    /// Issue a cluster key. Exports to `$AUTHLY_ETC_DIR/cluster/`.
    IssueClusterKey,
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
        Some(Command::Configure) => configure().await?,
        Some(Command::IssueClusterKey) => {
            let env_config = EnvConfig::load();
            let req = KeyPair::generate()?.server_cert("*.authly-cluster", Duration::days(10000));
            let certificate = req.params.self_signed(&req.key)?;

            std::fs::create_dir_all(env_config.cluster_cert_path().parent().unwrap())?;

            std::fs::write(env_config.cluster_key_path(), req.key.serialize_pem())?;
            std::fs::write(env_config.cluster_cert_path(), certificate.pem())?;
        }
        None => {}
    }

    Ok(())
}
