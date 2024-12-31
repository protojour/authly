use std::{fs::File, io::BufReader, sync::Arc};

use anyhow::Context;
use axum::{routing::post, Router};
pub use config::AuthlyConfig;
use hiqlite::{Row, ServerTlsConfig};
use rand::Rng;
use tokio_util::sync::CancellationToken;
use tower_server::{Scheme, TlsConfigFactory};

mod auth;
mod config;
mod testdata;
mod user;

#[derive(rust_embed::Embed)]
#[folder = "migrations"]
struct Migrations;

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EID(pub u128);

impl EID {
    fn random() -> Self {
        Self(rand::thread_rng().gen())
    }

    fn from_row(row: &mut Row, idx: &str) -> Self {
        let postcard: Vec<u8> = row.get(idx);
        Self(postcard::from_bytes(&postcard).unwrap())
    }

    fn as_param(&self) -> hiqlite::Param {
        hiqlite::Param::Blob(postcard::to_allocvec(&self.0).unwrap())
    }
}

#[derive(Clone)]
struct AuthlyCtx {
    db: hiqlite::Client,
}

pub async fn run_authly(config: AuthlyConfig) -> anyhow::Result<()> {
    let cancel = termination_signal();
    let rustls = authly_rustls(&config)?;

    let node_config = hiqlite_node_config(&config);
    let db = hiqlite::start_node(node_config).await?;

    db.migrate::<Migrations>().await.map_err(|err| {
        tracing::error!(?err, "failed to migrate");
        err
    })?;

    let ctx = AuthlyCtx { db };

    // test environment setup
    testdata::try_init_testdata(&ctx).await?;

    let app = Router::new()
        .route("/auth/authenticate", post(auth::authenticate))
        .with_state(ctx);

    let server = tower_server::Server::bind(
        tower_server::ServerConfig::new("0.0.0.0:10443".parse()?)
            .with_scheme(Scheme::Https)
            .with_tls_config(rustls)
            .with_cancellation_token(cancel.clone()),
    )
    .await?;

    tokio::spawn(server.serve(app));

    cancel.cancelled().await;

    Ok(())
}

fn authly_rustls(config: &AuthlyConfig) -> anyhow::Result<TlsConfigFactory> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let certs = rustls_pemfile::certs(&mut BufReader::new(
        &mut File::open(&config.cert_file).context("TLS cert file not found")?,
    ))
    .collect::<Result<Vec<_>, _>>()
    .context("invalid cert file")?;

    let private_key = rustls_pemfile::private_key(&mut BufReader::new(
        &mut File::open(&config.key_file).context("TLS private key not found")?,
    ))
    .context("invalid TLS private key")?
    .unwrap();

    let mut config = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, private_key)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let config = Arc::new(config);

    Ok(Arc::new(move || config.clone()))
}

fn hiqlite_node_config(config: &AuthlyConfig) -> hiqlite::NodeConfig {
    hiqlite::NodeConfig {
        node_id: 1,
        nodes: vec![hiqlite::Node {
            id: 1,
            addr_api: "127.0.0.1:10444".to_string(),
            addr_raft: "127.0.0.1:10445".to_string(),
        }],
        data_dir: config.data_dir.to_str().unwrap().to_string().into(),
        filename_db: "authly.db".into(),
        log_statements: false,
        prepared_statement_cache_capacity: 1024,
        read_pool_size: 4,
        sync_immediate: false,
        raft_config: {
            let logs_until_snapshot = 10_000;
            hiqlite::RaftConfig {
                cluster_name: "authly".to_string(),
                election_timeout_min: 750,
                election_timeout_max: 1500,
                heartbeat_interval: 150,
                install_snapshot_timeout: 10_000,
                max_payload_entries: 128,
                replication_lag_threshold: logs_until_snapshot * 2,
                snapshot_policy: hiqlite::SnapshotPolicy::LogsSinceLast(logs_until_snapshot),
                snapshot_max_chunk_size: 3 * 1024 * 1024,
                max_in_snapshot_log_to_keep: 1,
                purge_batch_size: 1,
                enable_tick: true,
                enable_heartbeat: true,
                enable_elect: true,

                ..Default::default()
            }
        },
        tls_raft: Some(ServerTlsConfig {
            key: config.key_file.to_str().unwrap().to_string().into(),
            cert: config.cert_file.to_str().unwrap().to_string().into(),
            danger_tls_no_verify: true,
        }),
        tls_api: Some(ServerTlsConfig {
            key: config.key_file.to_str().unwrap().to_string().into(),
            cert: config.cert_file.to_str().unwrap().to_string().into(),
            danger_tls_no_verify: true,
        }),
        secret_raft: config.raft_secret.clone(),
        secret_api: config.api_secret.clone(),
    }
}

fn termination_signal() -> CancellationToken {
    let cancel = CancellationToken::new();
    tokio::spawn({
        let cancel = cancel.clone();
        async move {
            let terminate = async {
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                    .expect("failed to install signal handler")
                    .recv()
                    .await;
            };
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {
                    cancel.cancel();
                }
                _ = terminate => {
                    cancel.cancel();
                }
            }
        }
    });

    cancel
}
