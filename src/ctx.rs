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

    use authly_common::id::Eid;

    use crate::{
        cert::{authly_ca, client_cert, key_pair},
        instance::{AuthlyId, AuthlyInstance},
        tls::{AuthlyCert, AuthlyCertKind},
        Migrations,
    };

    use super::{GetDb, GetInstance};

    #[derive(Default)]
    pub struct TestCtx {
        db: Option<RwLock<rusqlite::Connection>>,
        instance: Option<Arc<AuthlyInstance>>,
    }

    impl TestCtx {
        pub async fn inmemory_db(mut self) -> Self {
            let mut conn = rusqlite::Connection::open_in_memory().unwrap();
            sqlite_migrate::<Migrations>(&mut conn).await;

            self.db = Some(RwLock::new(conn));
            self
        }

        pub fn supreme_instance(mut self) -> Self {
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
