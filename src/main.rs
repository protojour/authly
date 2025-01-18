use std::env;

use authly::{cert::MakeSigningRequest, configure, env_config::ClusterTlsPath, serve, EnvConfig};
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

            issue_cluster_key(&env_config.hostname, env_config.cluster_tls_path())?;

            if env_config.k8s {
                issue_cluster_key(
                    &format!("*.{host}", host = &env_config.k8s_headless_svc),
                    ClusterTlsPath(env_config.etc_dir.join("cluster-k8s")),
                )?;
            }
        }
        None => {}
    }

    Ok(())
}

fn issue_cluster_key(common_name: &str, tls_path: ClusterTlsPath) -> anyhow::Result<()> {
    let req = KeyPair::generate()?.server_cert(common_name, Duration::days(10000));
    let certificate = req.params.self_signed(&req.key)?;

    std::fs::create_dir_all(&tls_path.0)?;

    std::fs::write(tls_path.key_path(), req.key.serialize_pem())?;
    std::fs::write(tls_path.cert_path(), certificate.pem())?;

    Ok(())
}
