use authly::{
    ctx::GetDb,
    db::{entity_db, service_db},
};
use authly_common::document::Document;
use hexhex::hex_literal;
use indoc::indoc;

use crate::{compile_and_apply_doc, TestCtx};

#[tokio::test]
async fn test_store_doc_trivial() {
    let ctx = TestCtx::default().inmemory_db().await;
    let doc = Document::from_toml(indoc! {
        r#"
        [authly-document]
        id = "bc9ce588-50c3-47d1-94c1-f88b21eaf299"

        [[service-entity]]
        eid = "e5462a0d22b54d9f9ca37bd96e9b9d8b"
        label = "service1"
        attributes = ["authly:role/authenticate", "authly:role/get_access_token"]
        kubernetes-account = { name = "testservice", namespace = "authly-test" }

        [[service-entity]]
        eid = "015362d6655447c6b7f44865bd111c70"
        label = "service2"
        "#
    })
    .unwrap();

    compile_and_apply_doc(doc, &Default::default(), &ctx)
        .await
        .unwrap();

    assert_eq!(
        entity_db::list_entity_attrs(
            ctx.get_db(),
            hex_literal!("e5462a0d22b54d9f9ca37bd96e9b9d8b").into()
        )
        .await
        .unwrap()
        .len(),
        2,
    );

    assert_eq!(
        entity_db::list_entity_attrs(
            ctx.get_db(),
            hex_literal!("015362d6655447c6b7f44865bd111c70").into()
        )
        .await
        .unwrap()
        .len(),
        0,
    );

    let eid = service_db::find_service_eid_by_k8s_service_account_name(
        ctx.get_db(),
        "authly-test",
        "testservice",
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(eid, hex_literal!("e5462a0d22b54d9f9ca37bd96e9b9d8b").into());
}
