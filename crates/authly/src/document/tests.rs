use authly_common::{document::Document, Eid};
use indoc::indoc;

use super::compiled_document::DocumentMeta;
use super::doc_compiler::compile_doc;
use crate::db::{
    document_db, entity_db, service_db,
    sqlite::{sqlite_txn, test_inmemory_db},
};

#[tokio::test]
async fn test_store_doc_trivial() {
    let db = test_inmemory_db().await;

    let doc = Document::from_toml(indoc! {
        r#"
        [authly-document]
        id = "bc9ce588-50c3-47d1-94c1-f88b21eaf299"

        [[service]]
        eid = "272878235402143010663560859986869906352"
        label = "service1"
        attributes = ["authly:role/authenticate", "authly:role/get_access_token"]
        kubernetes = { service-account = [
            { namespace = "authly-test", name = "testservice" },
        ] }

        [[service]]
        eid = "5483905438509438509358943058439058595"
        label = "service2"
        "#
    })
    .unwrap();

    let compiled_doc = compile_doc(doc, DocumentMeta::default(), &db)
        .await
        .unwrap();
    sqlite_txn(&db, document_db::document_txn_statements(compiled_doc))
        .await
        .unwrap();

    assert_eq!(
        entity_db::list_entity_attrs(&db, Eid::new(272878235402143010663560859986869906352))
            .await
            .unwrap()
            .len(),
        2,
    );

    assert_eq!(
        entity_db::list_entity_attrs(&db, Eid::new(5483905438509438509358943058439058595))
            .await
            .unwrap()
            .len(),
        0,
    );

    let eid =
        service_db::find_service_eid_by_k8s_service_account_name(&db, "authly-test", "testservice")
            .await
            .unwrap()
            .unwrap();

    assert_eq!(eid, Eid::new(272878235402143010663560859986869906352));
}
