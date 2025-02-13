use authly_common::id::ServiceId;
use hexhex::hex_literal;
use indoc::indoc;

use crate::{
    ctx::GetDb,
    db::{entity_db, service_db},
    test_support::TestCtx,
    tests::compile_and_apply_doc,
};

#[test_log::test(tokio::test)]
async fn test_store_doc_trivial() {
    let ctx = TestCtx::new().inmemory_db().await;
    let doc = indoc! {
        r#"
        [authly-document]
        id = "bc9ce588-50c3-47d1-94c1-f88b21eaf299"

        [[service-entity]]
        eid = "s.e5462a0d22b54d9f9ca37bd96e9b9d8b"
        label = "service1"
        attributes = ["authly:role:authenticate", "authly:role:get_access_token"]
        kubernetes-account = { name = "testservice" }

        [[service-entity]]
        eid = "s.015362d6655447c6b7f44865bd111c70"
        label = "service2"
        "#
    };

    compile_and_apply_doc(doc, &ctx).await.unwrap();

    assert_eq!(
        entity_db::list_entity_attrs(
            ctx.get_db(),
            ServiceId::from(hex_literal!("e5462a0d22b54d9f9ca37bd96e9b9d8b")).upcast()
        )
        .await
        .unwrap()
        .len(),
        2,
    );

    assert_eq!(
        entity_db::list_entity_attrs(
            ctx.get_db(),
            ServiceId::from(hex_literal!("015362d6655447c6b7f44865bd111c70")).upcast()
        )
        .await
        .unwrap()
        .len(),
        0,
    );

    let eid = service_db::find_service_eid_by_k8s_local_service_account_name(
        ctx.get_db(),
        "default",
        "testservice",
    )
    .await
    .unwrap()
    .unwrap();

    assert_eq!(eid, hex_literal!("e5462a0d22b54d9f9ca37bd96e9b9d8b").into());
}
