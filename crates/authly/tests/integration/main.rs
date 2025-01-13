use std::sync::RwLock;

use authly::{
    db::{
        document_db,
        service_db::{self, ServicePropertyKind},
        sqlite::sqlite_txn,
    },
    document::{compiled_document::DocumentMeta, doc_compiler::compile_doc},
};
use authly_common::{document::Document, service::PropertyMapping, Eid};
use tracing::info;

mod test_access_control;
mod test_document;

async fn new_inmemory_db() -> RwLock<rusqlite::Connection> {
    info!("new inmemory db");
    use authly::Migrations;

    let mut conn = rusqlite::Connection::open_in_memory().unwrap();
    sqlite_migrate::<Migrations>(&mut conn).await;

    RwLock::new(conn)
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

async fn compile_and_apply_doc(doc: Document, conn: &RwLock<rusqlite::Connection>) {
    let compiled_doc = compile_doc(doc, DocumentMeta::default(), conn)
        .await
        .unwrap();
    sqlite_txn(conn, document_db::document_txn_statements(compiled_doc))
        .await
        .unwrap();
}

struct ServiceProperties {
    resource: PropertyMapping,
    entity: PropertyMapping,
}

impl ServiceProperties {
    async fn load(svc_eid: Eid, conn: &RwLock<rusqlite::Connection>) -> Self {
        let resource =
            service_db::get_service_property_mapping(conn, svc_eid, ServicePropertyKind::Resource)
                .await
                .unwrap();
        let entity =
            service_db::get_service_property_mapping(conn, svc_eid, ServicePropertyKind::Entity)
                .await
                .unwrap();

        Self { resource, entity }
    }
}

fn main() {}
