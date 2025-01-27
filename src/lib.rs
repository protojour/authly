use std::{
    net::{Ipv4Addr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};

use arc_swap::ArcSwap;
use authly_common::id::Eid;
use axum::{response::IntoResponse, Json};
use db::{cryptography_db, settings_db};
use document::load::load_cfg_documents;
use encryption::DecryptedDeks;
pub use env_config::EnvConfig;
use instance::AuthlyInstance;
use openraft::RaftMetrics;
use serde::{Deserialize, Serialize};
use serde_json::json;
use settings::Settings;
use tokio_util::sync::CancellationToken;
use tower_server::Scheme;
use tracing::info;
use util::protocol_router::ProtocolRouter;

// These are public for the integration test crate
pub mod access_token;
pub mod audit;
pub mod authority_mandate;
pub mod cert;
pub mod ctx;
pub mod db;
pub mod document;
pub mod encryption;
pub mod env_config;
pub mod instance;
pub mod proto;
pub mod serde_util;
pub mod session;
pub mod tls;

mod access_control;
mod authority;
mod broadcast;
mod id;
mod k8s;
mod openapi;
mod policy;
mod settings;
mod util;
mod webauth;

#[derive(rust_embed::Embed)]
#[folder = "migrations"]
pub struct Migrations;

const HIQLITE_API_PORT: u16 = 7855;
const HIQLITE_RAFT_PORT: u16 = 7856;

/// Common context for the whole application
#[derive(Clone)]
struct AuthlyCtx {
    /// The client for hiqlite, an embedded database
    hql: hiqlite::Client,
    instance: Arc<AuthlyInstance>,
    /// Dynamically updatable settings:
    settings: Arc<ArcSwap<Settings>>,
    /// Data Encryption Keys
    deks: Arc<ArcSwap<DecryptedDeks>>,
    /// Signal triggered when the app is shutting down:
    shutdown: CancellationToken,
    etc_dir: PathBuf,
    export_tls_to_etc: bool,
}

impl AuthlyCtx {
    /// Get local database raft metrics. This is synchronous and never fails.
    async fn metrics_db(&self) -> RaftMetrics<u64, hiqlite::Node> {
        self.hql.metrics_db().await.expect("never fails")
    }
}

pub struct Init {
    ctx: AuthlyCtx,
    env_config: EnvConfig,
}

pub async fn serve() -> anyhow::Result<()> {
    let Init { ctx, env_config } = initialize().await?;

    info!(
        "root CA:\n{}",
        ctx.instance.trust_root_ca().certificate_pem()
    );

    broadcast::spawn_global_message_handler(&ctx);

    if env_config.k8s {
        k8s::k8s_manager::spawn_k8s_manager(ctx.clone()).await;

        k8s::k8s_auth_server::spawn_k8s_auth_server(&env_config, &ctx).await?;
    }

    let main_server = tower_server::Builder::new(SocketAddr::new(
        Ipv4Addr::new(0, 0, 0, 0).into(),
        env_config.server_port,
    ))
    .with_scheme(Scheme::Https)
    .with_tls_config(
        tls::main_service_tls_configurer(
            env_config.hostname.clone(),
            ctx.settings.clone(),
            ctx.instance.clone(),
        )
        .await?,
    )
    .with_tls_connection_middleware(authly_common::mtls_server::MTLSMiddleware)
    .with_graceful_shutdown(ctx.shutdown.clone())
    .bind()
    .await?;

    tokio::spawn(
        main_server.serve(
            ProtocolRouter::default()
                .with_grpc(proto::main_service_grpc_router(ctx.clone())?)
                .or_default(main_service_http_router(ctx.clone()))
                .into_service(),
        ),
    );

    #[cfg(feature = "dev")]
    if let Some(debug_web_port) = env_config.debug_web_port {
        tokio::spawn(
            tower_server::Builder::new(format!("0.0.0.0:{debug_web_port}").parse()?)
                .with_scheme(Scheme::Http)
                .bind()
                .await?
                .serve(webauth::router().with_state(ctx.clone())),
        );
    }

    let shutdown = ctx.shutdown.clone();

    tokio::spawn(
        tower_server::Builder::new("0.0.0.0:5555".parse()?)
            .with_graceful_shutdown(shutdown.clone())
            .bind()
            .await?
            .serve(axum::Router::new().route(
                "/health/readiness",
                axum::routing::get(|| async { Json(json!({ "status": "UP" })).into_response() }),
            )),
    );

    // App is fully running, wait for it to shut down
    shutdown.cancelled().await;

    Ok(())
}

fn main_service_http_router(ctx: AuthlyCtx) -> axum::Router {
    axum::Router::new()
        .merge(openapi::router::router())
        .merge(webauth::router())
        .with_state(ctx.clone())
}

pub async fn configure() -> anyhow::Result<()> {
    initialize().await?;

    Ok(())
}

#[derive(Debug, Serialize, Deserialize, strum::EnumIter, num_derive::ToPrimitive)]
enum CacheEntry {
    DummyForNow,
}

async fn initialize() -> anyhow::Result<Init> {
    tls::init_tls_ring();

    let env_config = EnvConfig::load();
    let node_config = hiqlite_node_config(&env_config);
    let hql = hiqlite::start_node_with_cache::<CacheEntry>(node_config).await?;

    hql.wait_until_healthy_db().await;

    hql.migrate::<Migrations>().await.map_err(|err| {
        tracing::error!(?err, "failed to migrate");
        err
    })?;

    let deks = encryption::load_decrypted_deks(&hql, hql.is_leader_db().await, &env_config).await?;
    let instance = cryptography_db::load_authly_instance(&hql, &deks).await?;

    let ctx = AuthlyCtx {
        hql,
        instance: Arc::new(instance),
        settings: Arc::new(ArcSwap::new(Arc::new(Settings::default()))),
        deks: Arc::new(ArcSwap::new(Arc::new(deks))),
        shutdown: tower_server::signal::termination_signal(),
        etc_dir: env_config.etc_dir.clone(),
        export_tls_to_etc: env_config.export_tls_to_etc,
    };

    if ctx.hql.is_leader_db().await {
        if env_config.export_tls_to_etc {
            std::fs::create_dir_all(env_config.etc_dir.join("certs"))?;

            std::fs::write(
                env_config.etc_dir.join("certs/root.crt"),
                ctx.instance.trust_root_ca().certificate_pem().as_bytes(),
            )?;
            std::fs::write(
                env_config.etc_dir.join("certs/local.crt"),
                ctx.instance.local_ca().certificate_pem().as_bytes(),
            )?;
        }

        load_cfg_documents(&env_config, &ctx).await?;
    }

    let settings = settings_db::load_local_settings(&ctx).await?;

    info!("local settings: {settings:#?}");

    ctx.settings.store(Arc::new(settings));

    Ok(Init { ctx, env_config })
}

fn hiqlite_node_config(env_config: &EnvConfig) -> hiqlite::NodeConfig {
    let cluster_tls_config = hiqlite::ServerTlsConfig {
        key: env_config
            .cluster_tls_path()
            .key_path()
            .to_str()
            .unwrap()
            .to_string()
            .into(),
        cert: env_config
            .cluster_tls_path()
            .cert_path()
            .to_str()
            .unwrap()
            .to_string()
            .into(),
        danger_tls_no_verify: true,
    };

    let node_id = if env_config.k8s {
        let hostname = hostname::get()
            .expect("hostname not found")
            .to_str()
            .unwrap()
            .to_string();

        match hostname.rsplit_once('-') {
            None => {
                panic!(
                    "Cannot split off the NODE_ID from the hostname {}",
                    hostname
                );
            }
            Some((_, id)) => {
                let id_hostname = id.parse::<u64>().expect("Cannot parse HQL_NODE_ID to u64");
                // the hostnames for k8s sts always start at 0, but we need to start at 1
                id_hostname + 1
            }
        }
    } else {
        env_config.cluster_node_id.unwrap_or(1)
    };

    let hiqlite_nodes: Vec<hiqlite::Node> = if env_config.k8s {
        let statefulset = env_config.k8s_statefulset.as_deref().unwrap_or("authly");
        let headless_svc = env_config.k8s_headless_svc.as_str();
        let replica_count = env_config.k8s_replicas;

        (0..replica_count)
            .map(|idx| hiqlite::Node {
                id: idx + 1,
                addr_api: format!("{statefulset}-{idx}.{headless_svc}:{HIQLITE_API_PORT}"),
                addr_raft: format!("{statefulset}-{idx}.{headless_svc}:{HIQLITE_RAFT_PORT}"),
            })
            .collect()
    } else {
        match (
            &env_config.cluster_api_nodes,
            &env_config.cluster_raft_nodes,
        ) {
            (Some(api_nodes), Some(raft_nodes)) => api_nodes
                .iter()
                .zip(raft_nodes)
                .enumerate()
                .map(|(idx, (api_node, raft_node))| hiqlite::Node {
                    id: idx as u64 + 1,
                    addr_api: api_node.to_string(),
                    addr_raft: raft_node.to_string(),
                })
                .collect(),
            _ => {
                vec![hiqlite::Node {
                    id: 1,
                    addr_api: format!("localhost:{HIQLITE_API_PORT}"),
                    addr_raft: format!("localhost:{HIQLITE_RAFT_PORT}"),
                }]
            }
        }
    };

    info!("hiqlite nodes: {hiqlite_nodes:?}");
    info!("data dir={:?}", env_config.data_dir);

    hiqlite::NodeConfig {
        node_id,
        nodes: hiqlite_nodes,
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
        secret_raft: env_config.cluster_raft_secret.clone(),
        secret_api: env_config.cluster_api_secret.clone(),
    }
}
