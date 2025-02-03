use std::collections::BTreeSet;

use authly_common::id::Eid;
use hexhex::hex_literal;

use super::compile_and_apply_doc_dir;
use crate::{
    ctx::GetDb,
    db::service_db::{self, ServicePropertyKind},
    test_support::TestCtx,
};

const ULTRADB: Eid = Eid::from_raw_array(hex_literal!("ec29ba1d23cb43f89b7c73db6f177a1d"));

#[test_log::test(tokio::test)]
async fn test_ultradb() {
    let ctx = TestCtx::default().inmemory_db().await;
    compile_and_apply_doc_dir("examples/ultradb".into(), &ctx)
        .await
        .unwrap();

    let mapping = service_db::get_service_property_mapping(
        ctx.get_db(),
        ULTRADB,
        ServicePropertyKind::Resource,
    )
    .await
    .unwrap();

    let namespaces: BTreeSet<_> = mapping
        .into_iter()
        .map(|(namespace, _)| namespace)
        .collect();

    assert_eq!(
        BTreeSet::from(["pants".to_string(), "ultradb".to_string()]),
        namespaces
    );
}
