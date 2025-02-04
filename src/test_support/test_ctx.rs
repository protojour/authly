use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;
use authly_common::id::Eid;
use authly_db::sqlite_pool::{SqlitePool, Storage};
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::info;

use crate::{
    bus::{
        handler::authly_node_handle_incoming_message,
        message::{ClusterMessage, ServiceMessage},
        service_events::{ServiceEventDispatcher, ServiceMessageConnection},
        BusError,
    },
    cert::{authly_ca, client_cert, key_pair},
    ctx::{
        ClusterBus, GetDb, GetDecryptedDeks, GetInstance, LoadInstance, RedistributeCertificates,
        ServiceBus, SetInstance,
    },
    db::cryptography_db,
    encryption::{gen_prop_deks, DecryptedDeks, DecryptedMaster},
    instance::{AuthlyId, AuthlyInstance},
    tls::{AuthlyCert, AuthlyCertKind},
    IsLeaderDb, Migrations,
};

/// The TestCtx allows writing tests that don't require the whole app running.
/// E.g. it supports an in-memory database.
#[derive(Clone)]
pub struct TestCtx {
    db: Option<SqlitePool>,
    instance: Option<Arc<ArcSwap<AuthlyInstance>>>,
    deks: Arc<ArcSwap<DecryptedDeks>>,
    svc_event_dispatcher: ServiceEventDispatcher,

    cluster_message_log: Arc<Mutex<Vec<ClusterMessage>>>,

    /// When all TestCtx clones go out of scope,
    /// the associated cancellation token will emit `cancelled` automatically
    #[expect(unused)]
    cancel_guard: Arc<DropGuard>,
}

impl TestCtx {
    pub fn new() -> Self {
        let cancel = CancellationToken::new();

        Self {
            db: None,
            instance: None,
            deks: Default::default(),
            svc_event_dispatcher: ServiceEventDispatcher::new(cancel.clone()),
            cluster_message_log: Default::default(),
            cancel_guard: Arc::new(cancel.drop_guard()),
        }
    }

    pub async fn inmemory_db(mut self) -> Self {
        let pool = SqlitePool::new(Storage::Memory, 1);
        {
            let mut conn = pool.get().await.unwrap();
            sqlite_migrate::<Migrations>(&mut conn).await;
        }

        self.db = Some(pool);
        self
    }

    /// Run test with a file DB, so the the file can be inspected after the test
    pub async fn new_file_db(mut self, path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let _ = fs::remove_file(&path);
        let pool = SqlitePool::new(Storage::File(path), 1);
        {
            let mut conn = pool.get().await.unwrap();
            sqlite_migrate::<Migrations>(&mut conn).await;
        }

        self.db = Some(pool);
        self
    }

    /// With AuthlyInstance that doesn't use the database
    pub fn lite_instance(mut self) -> Self {
        let authly_id = AuthlyId {
            eid: Eid::random(),
            private_key: key_pair(),
        };
        let certs = vec![
            {
                let certificate = authly_ca().self_signed(&authly_id.private_key).unwrap();
                AuthlyCert {
                    kind: AuthlyCertKind::Ca,
                    certifies: authly_id.eid,
                    signed_by: authly_id.eid,
                    params: certificate.params().clone(),
                    der: certificate.der().clone(),
                }
            },
            {
                let certificate =
                    client_cert(&authly_id.eid.to_string(), time::Duration::days(365 * 100))
                        .self_signed(&authly_id.private_key)
                        .unwrap();
                AuthlyCert {
                    kind: AuthlyCertKind::Identity,
                    certifies: authly_id.eid,
                    signed_by: authly_id.eid,
                    params: certificate.params().clone(),
                    der: certificate.der().clone(),
                }
            },
        ];
        self.instance = Some(Arc::new(ArcSwap::new(Arc::new(AuthlyInstance::new(
            authly_id, certs,
        )))));
        self
    }

    /// Make a supreme instance with cryptographic keys and certificates
    pub async fn supreme_instance(mut self) -> Self {
        let db = self.db.unwrap();

        let decrypted_master = DecryptedMaster::fake_for_test();
        let decrypted_deks = DecryptedDeks::new(
            gen_prop_deks(&db, &decrypted_master, IsLeaderDb(true))
                .await
                .unwrap(),
        );

        let instance =
            cryptography_db::load_authly_instance(IsLeaderDb(true), &db, &decrypted_deks)
                .await
                .unwrap();

        self.db = Some(db);
        self.deks = Arc::new(ArcSwap::new(Arc::new(decrypted_deks)));
        self.instance = Some(Arc::new(ArcSwap::new(Arc::new(instance))));
        self
    }

    pub async fn with_db_instance(mut self) -> Self {
        let db = self.db.unwrap();

        let decrypted_master = DecryptedMaster::fake_for_test();
        self.deks = Arc::new(ArcSwap::new(Arc::new(DecryptedDeks::new(
            gen_prop_deks(&db, &decrypted_master, IsLeaderDb(true))
                .await
                .unwrap(),
        ))));

        self.db = Some(db);
        self
    }

    pub fn get_decrypted_deks(&self) -> Arc<DecryptedDeks> {
        self.deks.as_ref().load_full()
    }

    pub fn clear_cluster_message_log(&self) {
        self.cluster_message_log.lock().unwrap().clear();
    }

    #[track_caller]
    fn instance(&self) -> &ArcSwap<AuthlyInstance> {
        self.instance.as_ref().expect("TestCtx has no instance")
    }
}

impl GetDb for TestCtx {
    type Db = SqlitePool;

    #[track_caller]
    fn get_db(&self) -> &Self::Db {
        self.db.as_ref().expect("TestCtx has no database")
    }
}

impl GetInstance for TestCtx {
    #[track_caller]
    fn get_instance(&self) -> arc_swap::Guard<Arc<AuthlyInstance>> {
        self.instance().load()
    }
}

impl LoadInstance for TestCtx {
    #[track_caller]
    fn load_instance(&self) -> Arc<AuthlyInstance> {
        self.instance().load_full()
    }
}

impl SetInstance for TestCtx {
    #[track_caller]
    fn set_instance(&self, instance: AuthlyInstance) {
        self.instance().store(Arc::new(instance));
    }
}

impl GetDecryptedDeks for TestCtx {
    #[track_caller]
    fn get_decrypted_deks(&self) -> arc_swap::Guard<Arc<DecryptedDeks>> {
        self.deks.load()
    }

    #[track_caller]
    fn load_decrypted_deks(&self) -> Arc<DecryptedDeks> {
        self.deks.load_full()
    }
}

impl ClusterBus for TestCtx {
    /// There isn't actually any broadcasting being done for the TestCtx,
    /// it's all done "synchronously":
    async fn broadcast_to_cluster(&self, message: ClusterMessage) -> Result<(), BusError> {
        self.cluster_message_log
            .lock()
            .unwrap()
            .push(message.clone());

        if let Err(err) = Box::pin(authly_node_handle_incoming_message(self, message.clone())).await
        {
            panic!("Failed to handle cluster-wide message {message:?}: {err:?}");
        }

        Ok(())
    }

    async fn broadcast_to_cluster_if_leader(
        &self,
        message: ClusterMessage,
    ) -> Result<(), BusError> {
        self.broadcast_to_cluster(message).await
    }
}

impl ServiceBus for TestCtx {
    fn service_subscribe(&self, svc_eid: Eid, connection: ServiceMessageConnection) {
        self.svc_event_dispatcher.subscribe(svc_eid, connection);
    }

    fn service_broadcast(&self, svc_eid: Eid, msg: ServiceMessage) {
        self.svc_event_dispatcher.broadcast(svc_eid, msg);
    }

    fn service_broadcast_all(&self, msg: ServiceMessage) {
        self.svc_event_dispatcher.broadcast_all(msg);
    }
}

impl RedistributeCertificates for TestCtx {
    async fn redistribute_certificates_if_leader(&self) {
        info!("TestCtx redistribute certificates: ignored");
    }
}

async fn sqlite_migrate<T: rust_embed::RustEmbed>(conn: &mut rusqlite::Connection) {
    let mut files: Vec<_> = T::iter().collect();
    files.sort();

    let txn = conn.transaction().unwrap();

    for file in files {
        let migration = T::get(&file).unwrap();
        txn.execute_batch(std::str::from_utf8(&migration.data).unwrap())
            .unwrap();
    }

    txn.commit().unwrap();
}
