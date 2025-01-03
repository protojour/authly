use std::{path::PathBuf, sync::Arc};

use anyhow::anyhow;
use axum::{routing::post, Router};
use cert::MakeSigningRequest;
use db::config_db::{self, DynamicConfig};
pub use env_config::EnvConfig;
use hiqlite::{Row, ServerTlsConfig};
use kubernetes::spawn_kubernetes_manager;
use rand::Rng;
use rcgen::KeyPair;
use rustls::{pki_types::PrivateKeyDer, server::WebPkiClientVerifier, RootCertStore};
use time::Duration;
use tokio_util::sync::CancellationToken;
use tower_server::{Scheme, TlsConfigFactory};
use tracing::info;
use util::protocol_router::ProtocolRouter;

pub mod cert;

mod auth;
mod db;
mod env_config;
mod kubernetes;
mod proto;
mod testdata;
mod util;

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

pub struct Init {
    ctx: AuthlyCtx,
    env_config: EnvConfig,
    dynamic_config: DynamicConfig,
}

pub async fn serve() -> anyhow::Result<()> {
    let Init {
        ctx,
        env_config,
        dynamic_config,
    } = initialize().await?;

    info!("local CA:\n{}", dynamic_config.local_ca.certificate_pem());

    let cancel = termination_signal();

    let http_api = Router::new()
        .route("/api/auth/authenticate", post(auth::authenticate))
        .with_state(ctx.clone());

    let rustls_config = main_service_rustls(&env_config, &dynamic_config)?;
    let server = tower_server::Server::bind(
        tower_server::ServerConfig::new("0.0.0.0:10443".parse()?)
            .with_scheme(Scheme::Https)
            .with_tls_config(rustls_config)
            .with_cancellation_token(cancel.clone()),
    )
    .await?;

    tokio::spawn(
        server.serve(
            ProtocolRouter::default()
                .with_grpc({
                    let mut grpc_routes = tonic::service::RoutesBuilder::default();
                    grpc_routes.add_service(
                        proto::service_server::AuthlyServiceServerImpl::from(ctx).into_service(),
                    );
                    grpc_routes.routes().into_axum_router()
                })
                .or_default(http_api)
                .into_service(),
        ),
    );

    cancel.cancelled().await;

    Ok(())
}

pub async fn issue_service_identity(eid: String, out: Option<PathBuf>) -> anyhow::Result<()> {
    let Init { dynamic_config, .. } = initialize().await?;
    let eid = EID(eid.parse()?);

    let pem = dynamic_config
        .local_ca
        .sign(KeyPair::generate()?.client_cert(&eid.0.to_string(), Duration::days(7)))
        .certificate_and_key_pem();

    if let Some(out_path) = out {
        std::fs::write(out_path, pem)?;
    } else {
        println!("{pem}");
    }

    Ok(())
}

pub async fn initialize() -> anyhow::Result<Init> {
    let env_config = EnvConfig::load();
    let node_config = hiqlite_node_config(&env_config);
    let db = hiqlite::start_node(node_config).await?;

    db.migrate::<Migrations>().await.map_err(|err| {
        tracing::error!(?err, "failed to migrate");
        err
    })?;

    let ctx = AuthlyCtx { db };

    let dynamic_config = config_db::load_db_config(&ctx).await?;

    if ctx.db.is_leader_db().await {
        if let Some(export_path) = &env_config.export_local_ca {
            std::fs::write(
                export_path,
                dynamic_config.local_ca.certificate_pem().as_bytes(),
            )?;
        }

        // test environment setup
        testdata::try_init_testdata(&ctx).await?;
    }

    if env_config.kubernetes {
        spawn_kubernetes_manager(ctx.clone());
    }

    Ok(Init {
        ctx,
        env_config,
        dynamic_config,
    })
}

fn main_service_rustls(
    env_config: &EnvConfig,
    dynamic_config: &DynamicConfig,
) -> anyhow::Result<TlsConfigFactory> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    info!(
        "generating server certificate for hostname={}",
        env_config.hostname
    );

    let server_cert = dynamic_config
        .local_ca
        .sign(KeyPair::generate()?.server_cert(&env_config.hostname, time::Duration::days(365)));

    let server_private_key_der = PrivateKeyDer::try_from(server_cert.key.serialize_der())
        .map_err(|err| anyhow!("server private key: {err}"))?;

    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(dynamic_config.local_ca.der.clone())?;

    let mut config = rustls::server::ServerConfig::builder()
        .with_client_cert_verifier(WebPkiClientVerifier::builder(root_cert_store.into()).build()?)
        .with_single_cert(vec![server_cert.der.clone()], server_private_key_der)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    let config = Arc::new(config);

    Ok(Arc::new(move || config.clone()))
}

fn hiqlite_node_config(env_config: &EnvConfig) -> hiqlite::NodeConfig {
    let cluster_tls_config = ServerTlsConfig {
        key: env_config
            .cluster_key_file
            .to_str()
            .unwrap()
            .to_string()
            .into(),
        cert: env_config
            .cluster_cert_file
            .to_str()
            .unwrap()
            .to_string()
            .into(),
        danger_tls_no_verify: true,
    };

    hiqlite::NodeConfig {
        node_id: 1,
        nodes: vec![hiqlite::Node {
            id: 1,
            addr_api: "127.0.0.1:10444".to_string(),
            addr_raft: "127.0.0.1:10445".to_string(),
        }],
        data_dir: env_config.data_dir.to_str().unwrap().to_string().into(),
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
        tls_raft: Some(cluster_tls_config.clone()),
        tls_api: Some(cluster_tls_config),
        secret_raft: env_config.raft_secret.clone(),
        secret_api: env_config.api_secret.clone(),
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
