//! Traits for abstracting away application context

use std::sync::Arc;

use authly_db::Db;

use crate::{instance::AuthlyInstance, AuthlyCtx};

pub trait GetDb {
    type Db: Db;

    fn get_db(&self) -> &Self::Db;
}

pub trait GetInstance {
    fn get_instance(&self) -> &Arc<AuthlyInstance>;
}

impl GetDb for AuthlyCtx {
    type Db = hiqlite::Client;

    fn get_db(&self) -> &Self::Db {
        &self.hql
    }
}

impl GetInstance for AuthlyCtx {
    fn get_instance(&self) -> &Arc<AuthlyInstance> {
        &self.instance
    }
}

pub mod test {
    use std::{
        borrow::Cow,
        sync::{Arc, RwLock},
    };

    use arc_swap::ArcSwap;
    use authly_common::id::Eid;
    use authly_db::{Db, DbError, IsLeaderDb};
    use hiqlite::Params;

    use crate::{
        cert::{authly_ca, client_cert, key_pair},
        db::cryptography_db,
        encryption::{gen_prop_deks, DecryptedDeks, DecryptedMaster},
        instance::{AuthlyId, AuthlyInstance},
        tls::{AuthlyCert, AuthlyCertKind},
        Migrations,
    };

    use super::{GetDb, GetInstance};

    #[derive(Default)]
    pub struct TestCtx {
        db: Option<RwLock<rusqlite::Connection>>,
        instance: Option<Arc<AuthlyInstance>>,
        deks: Option<Arc<ArcSwap<DecryptedDeks>>>,
    }

    impl TestCtx {
        pub async fn inmemory_db(mut self) -> Self {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            sqlite_migrate::<Migrations>(&mut conn).await;

            self.db = Some(RwLock::new(conn));
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
            self.instance = Some(Arc::new(AuthlyInstance::new(authly_id, certs)));
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
            self.instance = Some(Arc::new(instance));
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
    }

    impl GetDb for TestCtx {
        type Db = RwLock<rusqlite::Connection>;

        #[track_caller]
        fn get_db(&self) -> &Self::Db {
            self.db.as_ref().expect("TestCtx has no database")
        }
    }

    impl GetInstance for TestCtx {
        #[track_caller]
        fn get_instance(&self) -> &Arc<AuthlyInstance> {
            self.instance.as_ref().expect("TestCtx has no instance")
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

    impl Db for TestCtx {
        type Row<'a> = <<TestCtx as GetDb>::Db as Db>::Row<'a>;

        async fn query_raw(
            &self,
            stmt: Cow<'static, str>,
            params: Params,
        ) -> Result<Vec<Self::Row<'_>>, DbError> {
            Db::query_raw(self.get_db(), stmt, params).await
        }

        async fn execute(&self, sql: Cow<'static, str>, params: Params) -> Result<usize, DbError> {
            Db::execute(self.get_db(), sql, params).await
        }
    }
}
