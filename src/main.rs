use std::env;

use authly::{
    cert::{server_cert, CertificateParamsExt},
    configure,
    env_config::ClusterTlsPath,
    serve, EnvConfig,
};
use clap::{Parser, Subcommand};
use mimalloc::MiMalloc;
use rand::{rngs::OsRng, Rng};
use time::Duration;
use tracing::info;
use tracing_subscriber::EnvFilter;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

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

    /// Check if an Authly server is running at localhost
    Ready,

    /// Import documents and do general configuration, then exit
    Configure,

    /// Generate a new unique AUTHLY_ID.
    GenerateAuthlyId,

    /// Issue a cluster key. Exports to `$AUTHLY_ETC_DIR/cluster/`.
    IssueClusterKey,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::from_env("AUTHLY_LOG"))
        .init();

    match Cli::parse().command {
        Some(Command::Serve) => {
            info!("🔒 Authly v{VERSION}");
            serve().await?
        }
        Some(Command::Ready) => {
            reqwest::Client::new()
                .get("http://localhost:5555/health/readiness")
                .send()
                .await?
                .error_for_status()?;
        }
        Some(Command::Configure) => configure().await?,
        Some(Command::GenerateAuthlyId) => {
            let mut id = [0u8; 32];
            OsRng.fill(id.as_mut_slice());

            println!("Generated Authly ID: {}", hexhex::hex(&id));
        }
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

fn issue_cluster_key(hostname: &str, tls_path: ClusterTlsPath) -> anyhow::Result<()> {
    let req = server_cert("authly", vec![hostname.to_string()], Duration::days(10000))?
        .with_new_key_pair();
    let certificate = req.params.self_signed(&req.key)?;

    std::fs::create_dir_all(&tls_path.0)?;

    std::fs::write(tls_path.key_path(), req.key.serialize_pem())?;
    std::fs::write(tls_path.cert_path(), certificate.pem())?;

    Ok(())
}
