#![deny(unsafe_code)]

use std::{
    collections::HashMap,
    net::{Ipv4Addr, SocketAddr},
    ops::Deref,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::anyhow;
use arc_swap::ArcSwap;
use authly_domain::{
    builtins::Builtins,
    bus::{service_events::ServiceEventDispatcher, ServiceMessage},
    ctx::{GetDb, ServiceBus},
    directory::{load_persona_directories, PersonaDirectory},
    encryption::DecryptedDeks,
    instance::AuthlyInstance,
    migration::Migrations,
    remote_addr::remote_addr_middleware,
    repo::{crypto_repo, init_repo, settings_repo},
    settings::Settings,
    webauthn::Webauthn,
    IsLeaderDb,
};
use authly_hiqlite::HiqliteClient;
use axum::{response::IntoResponse, Json};
pub use env_config::EnvConfig;
use hiqlite::cache_idx::CacheIndex;
use http::Uri;
use indexmap::IndexMap;
use load_docs::load_cfg_documents;
use openraft::RaftMetrics;
use platform::CertificateDistributionPlatform;
use serde_json::json;
use tokio_util::sync::CancellationToken;
use tower_server::Scheme;
use tracing::info;
use util::protocol_router::ProtocolRouter;

// These are public for the integration test crate
pub mod ctx;
pub mod encryption;
pub mod env_config;
pub mod grpc;
pub mod platform;
pub mod tls;

mod cluster_bus;
mod k8s;
mod load_docs;
mod util;

const HIQLITE_API_PORT: u16 = 7855;
const HIQLITE_RAFT_PORT: u16 = 7856;

/// Common context for the whole application.
///
/// A clonable wrapper for [AuthlyState].
#[derive(Clone)]
struct AuthlyCtx {
    state: Arc<AuthlyState>,
}

impl Deref for AuthlyCtx {
    type Target = Arc<AuthlyState>;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

impl AuthlyCtx {
    /// Get local database raft metrics. This is synchronous and never fails.
    async fn metrics_db(&self) -> RaftMetrics<u64, hiqlite::Node> {
        self.hql.metrics_db().await.expect("never fails")
    }
}

struct AuthlyState {
    /// The client for hiqlite, an embedded database
    hql: HiqliteClient,
    builtins: Builtins,
    instance: ArcSwap<AuthlyInstance>,
    /// Dynamically updatable settings:
    settings: ArcSwap<Settings>,
    svc_event_dispatcher: ServiceEventDispatcher,
    /// Data Encryption Keys
    deks: ArcSwap<DecryptedDeks>,
    persona_directories: ArcSwap<IndexMap<String, PersonaDirectory>>,
    internet_http_client: reqwest::Client,
    webauthn_per_uri: Mutex<HashMap<Uri, Arc<Webauthn>>>,
    /// Signal triggered when the app is shutting down:
    shutdown: CancellationToken,
    cert_distribution_platform: CertificateDistributionPlatform,
    etc_dir: PathBuf,
    export_tls_to_etc: bool,
    hostname: String,
    /// The kubernetes namespace the local Authly runs in (if any, default is "default")
    k8s_local_namespace: String,
}

pub struct Init {
    ctx: AuthlyCtx,
    env_config: EnvConfig,
}

pub async fn serve() -> anyhow::Result<()> {
    let Init { ctx, env_config } = initialize().await?;

    info!(
        "root CA:\n{}",
        ctx.instance.load().trust_root_ca().certificate_pem()
    );

    cluster_bus::spawn_global_cluster_message_handler(&ctx);

    if env_config.k8s {
        k8s::k8s_auth_server::spawn_k8s_auth_server(&env_config, &ctx).await?;
    }

    let main_server = tower_server::Builder::new(SocketAddr::new(
        Ipv4Addr::new(0, 0, 0, 0).into(),
        env_config.server_port,
    ))
    .with_scheme(Scheme::Https)
    .with_tls_config(
        tls::main_service_tls_configurer(env_config.hostname.clone(), ctx.clone()).await?,
    )
    .with_connection_middleware(remote_addr_middleware)
    .with_tls_connection_middleware(authly_common::mtls_server::MTLSMiddleware)
    .with_graceful_shutdown(ctx.shutdown.clone())
    .bind()
    .await?;

    tokio::spawn(
        main_server.serve(
            ProtocolRouter::default()
                .with_grpc(grpc::main_service_grpc_router(ctx.clone())?)
                .or_default(main_service_http_router(ctx.clone()))
                .into_service(),
        ),
    );

    // spawn service pinger
    {
        let ctx = ctx.clone();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(60 * 5)) => {
                        ctx.service_event_dispatcher().broadcast_all(ServiceMessage::Ping);
                    }
                    _ = ctx.shutdown.cancelled() => {
                        return;
                    }
                }
            }
        });
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
        .merge(authly_web::router())
        .merge(authly_service::openapi::router::router())
        .with_state(ctx.clone())
}

pub async fn configure() -> anyhow::Result<()> {
    initialize().await?;

    Ok(())
}

#[derive(Debug, strum::EnumIter, num_derive::ToPrimitive)]
enum CacheEntry {
    WebAuthnRegistration,
    WebAuthnAuth,
}

impl CacheIndex for CacheEntry {
    fn to_usize(self) -> usize {
        self as usize
    }
}

async fn initialize() -> anyhow::Result<Init> {
    tls::init_tls_ring();

    let env_config = EnvConfig::load();
    let secrets = authly_secrets::AuthlySecretsBuilder {
        authly_uid: env_config.uid.0,
        danger_disable_encryption: env_config.danger_disable_encryption,
        bao_url: env_config.bao_url.clone(),
        bao_token: env_config.bao_token.clone(),
    }
    .build(reqwest::Client::new())
    .map_err(|err| anyhow!("fatal: Failed to select secrets backend: {err}"))?;

    info!("using `{}` secret backend", secrets.name());

    let node_config = hiqlite_node_config(&env_config);
    let hql = HiqliteClient::new(hiqlite::start_node_with_cache::<CacheEntry>(node_config).await?);

    hql.wait_until_healthy_db().await;

    hql.migrate::<Migrations>().await.map_err(|err| {
        tracing::error!(?err, "failed to migrate");
        err
    })?;

    let builtins =
        init_repo::load_authly_builtins(&hql, IsLeaderDb(hql.is_leader_db().await)).await?;

    let deks = encryption::load_decrypted_deks(
        &hql,
        IsLeaderDb(hql.is_leader_db().await),
        secrets.as_ref(),
    )
    .await?;
    let instance =
        crypto_repo::load_authly_instance(IsLeaderDb(hql.is_leader_db().await), &hql, &deks)
            .await?;

    let cert_distribution_platform = if env_config.k8s {
        CertificateDistributionPlatform::KubernetesConfigMap
    } else {
        CertificateDistributionPlatform::EtcDir
    };

    let persona_directories = load_persona_directories(&hql, &deks).await?;

    let shutdown = tower_server::signal::termination_signal();

    let ctx = AuthlyCtx {
        state: Arc::new(AuthlyState {
            hql,
            builtins,
            instance: ArcSwap::new(Arc::new(instance)),
            settings: ArcSwap::new(Arc::new(Settings::default())),
            deks: ArcSwap::new(Arc::new(deks)),
            persona_directories: ArcSwap::new(Arc::new(persona_directories)),
            internet_http_client: reqwest::Client::new(),
            webauthn_per_uri: Default::default(),
            cert_distribution_platform,
            svc_event_dispatcher: ServiceEventDispatcher::new(shutdown.clone()),
            shutdown,
            etc_dir: env_config.etc_dir.clone(),
            export_tls_to_etc: env_config.export_tls_to_etc,
            hostname: env_config.hostname.clone(),
            k8s_local_namespace: env_config.k8s_namespace.clone(),
        }),
    };

    platform::redistribute_certificates(&ctx).await;

    if ctx.hql.is_leader_db().await {
        load_cfg_documents(&env_config, &ctx).await?;
    }

    let settings = settings_repo::load_local_settings(ctx.get_db()).await?;

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
        shutdown_delay_millis: 5000,
        ..Default::default()
    }
}
