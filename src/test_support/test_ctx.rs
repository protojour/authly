use std::{
    fs,
    path::PathBuf,
    sync::{Arc, Mutex},
};

use arc_swap::ArcSwap;
use authly_common::id::Eid;
use authly_db::sqlite_pool::{SqlitePool, Storage};
use tracing::info;

use crate::{
    bus::{handler::authly_node_handle_incoming_message, message::ClusterMessage, BusError},
    cert::{authly_ca, client_cert, key_pair},
    ctx::{
        Broadcast, GetDb, GetDecryptedDeks, GetInstance, LoadInstance, RedistributeCertificates,
        SetInstance,
    },
    db::cryptography_db,
    encryption::{gen_prop_deks, DecryptedDeks, DecryptedMaster},
    instance::{AuthlyId, AuthlyInstance},
    tls::{AuthlyCert, AuthlyCertKind},
    IsLeaderDb, Migrations,
};

/// The TestCtx allows writing tests that don't require the whole app running.
/// E.g. it supports an in-memory database.
#[derive(Clone, Default)]
pub struct TestCtx {
    db: Option<SqlitePool>,
    instance: Option<Arc<ArcSwap<AuthlyInstance>>>,
    deks: Option<Arc<ArcSwap<DecryptedDeks>>>,

    cluster_message_log: Arc<Mutex<Vec<ClusterMessage>>>,
}

impl TestCtx {
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
        self.deks = Some(Arc::new(ArcSwap::new(Arc::new(decrypted_deks))));
        self.instance = Some(Arc::new(ArcSwap::new(Arc::new(instance))));
        self
    }

    pub async fn with_db_instance(mut self) -> Self {
        let db = self.db.unwrap();

        let decrypted_master = DecryptedMaster::fake_for_test();
        self.deks = Some(Arc::new(ArcSwap::new(Arc::new(DecryptedDeks::new(
            gen_prop_deks(&db, &decrypted_master, IsLeaderDb(true))
                .await
                .unwrap(),
        )))));

        self.db = Some(db);
        self
    }

    pub fn get_decrypted_deks(&self) -> Arc<DecryptedDeks> {
        self.deks.as_ref().unwrap().load_full()
    }

    #[track_caller]
    fn instance(&self) -> &ArcSwap<AuthlyInstance> {
        self.instance.as_ref().expect("TestCtx has no instance")
    }

    #[track_caller]
    fn deks(&self) -> &ArcSwap<DecryptedDeks> {
        self.deks.as_ref().expect("TestCtx has no deks")
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
        self.deks().load()
    }

    #[track_caller]
    fn load_decrypted_deks(&self) -> Arc<DecryptedDeks> {
        self.deks().load_full()
    }
}

impl Broadcast for TestCtx {
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
