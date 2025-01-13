use std::sync::RwLock;

use authly_common::{document::Document, Eid};
use indoc::indoc;

use super::compiled_document::DocumentMeta;
use super::doc_compiler::compile_doc;
use crate::db::{
    document_db, entity_db, service_db,
    sqlite::{sqlite_txn, test_inmemory_db},
};

async fn compile_and_apply_doc(doc: Document, conn: &RwLock<rusqlite::Connection>) {
    let compiled_doc = compile_doc(doc, DocumentMeta::default(), conn)
        .await
        .unwrap();
    sqlite_txn(conn, document_db::document_txn_statements(compiled_doc))
        .await
        .unwrap();
}

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

    compile_and_apply_doc(doc, &db).await;

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

#[tokio::test]
async fn test_doc_to_policy_engine() {
    let db = test_inmemory_db().await;
    let doc = Document::from_toml(indoc! {
        r#"
        [authly-document]
        id = "bc9ce588-50c3-47d1-94c1-f88b21eaf299"

        [[service]]
        eid = "272878235402143010663560859986869906352"
        label = "svc_a"

        [[service]]
        eid = "34343434343434343434343434343434343434"
        label = "svc_b"

        [[entity-property]]
        service = "svc_a"
        label = "trait"
        attributes = ["has_legs"]

        [[resource-property]]
        service = "svc_a"
        label = "kind"
        attributes = ["trousers"]

        [[policy]]
        service = "svc_a"
        label = "allow for legged creatures"
        allow = "Subject.trait == trait/has_legs"

        [[policy-binding]]
        service = "svc_a"
        attributes = ["kind/trousers"]
        policies = ["allow for legged creatures"]
        "#
    })
    .unwrap();

    compile_and_apply_doc(doc, &db).await;

    let svc_a_policy_engine =
        service_db::load_policy_engine(&db, Eid::new(272878235402143010663560859986869906352))
            .await
            .unwrap();

    assert_eq!(1, svc_a_policy_engine.get_policy_count());
    assert_eq!(1, svc_a_policy_engine.get_trigger_count());

    let svc_b_policy_engine =
        service_db::load_policy_engine(&db, Eid::new(34343434343434343434343434343434343434))
            .await
            .unwrap();

    assert_eq!(0, svc_b_policy_engine.get_policy_count());
    assert_eq!(0, svc_b_policy_engine.get_trigger_count());
}
