use axum::{routing::post, Router};
use hiqlite::Row;
use rand::Rng;
use tracing::info;
use user::{try_register_user, user_count};

mod auth;
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

pub async fn run_authly(node_config: hiqlite::NodeConfig) -> anyhow::Result<()> {
    let db = hiqlite::start_node(node_config).await?;

    db.migrate::<Migrations>().await.map_err(|err| {
        tracing::error!(?err, "failed to migrate");
        err
    })?;

    let ctx = AuthlyCtx { db };

    // test environment setup
    {
        let register_result =
            try_register_user("testuser".to_string(), "secret".to_string(), ctx.clone()).await;

        if let Err(err) = register_result {
            info!(?err, "failed to register user");
        }

        let user_count = user_count(ctx.clone()).await?;

        info!("There are {user_count} users");
    }

    let app = Router::new()
        .route("/auth/authenticate", post(auth::authenticate))
        .with_state(ctx);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8888").await.unwrap();
    axum::serve(listener, app).await?;

    Ok(())
}

pub fn test_node_config(data_dir: &str) -> hiqlite::NodeConfig {
    hiqlite::NodeConfig {
        node_id: 1,
        nodes: vec![hiqlite::Node {
            id: 1,
            addr_api: "127.0.0.1:8101".to_string(),
            addr_raft: "127.0.0.1:8102".to_string(),
        }],
        data_dir: data_dir.to_string().into(),
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
        tls_raft: None,
        tls_api: None,
        secret_raft: "superultramegasecret1".to_string(),
        secret_api: "superultramegasecret2".to_string(),
    }
}

#[tokio::test]
async fn test_hiqlite() {
    let node_config = test_node_config(".data");
    let client = hiqlite::start_node(node_config).await.unwrap();

    client.migrate::<Migrations>().await.unwrap();
}
