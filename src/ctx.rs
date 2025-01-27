//! Traits for abstracting away application context

use std::sync::Arc;

use crate::{db::Db, instance::AuthlyInstance, AuthlyCtx};

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
    use std::sync::{Arc, RwLock};

    use arc_swap::ArcSwap;

    use crate::{
        db::{cryptography_db, IsLeaderDb},
        encryption::{gen_prop_deks, DecryptedDeks, DecryptedMaster},
        instance::AuthlyInstance,
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
}
