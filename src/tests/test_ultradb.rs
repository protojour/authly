use std::collections::BTreeSet;

use authly_common::{
    id::ServiceId,
    proto::service::{self as proto, authly_service_client::AuthlyServiceClient},
};
use authly_test::test_ctx::TestCtx;
use hexhex::hex_literal;

use super::{compile_and_apply_doc_dir, tonic_request};
use crate::proto::service_server::AuthlyServiceServerImpl;

const ULTRADB: ServiceId =
    ServiceId::from_raw_array(hex_literal!("ec29ba1d23cb43f89b7c73db6f177a1d"));

#[test_log::test(tokio::test)]
async fn test_ultradb() {
    let ctx = TestCtx::new().inmemory_db().await;
    compile_and_apply_doc_dir("examples/ultradb".into(), &ctx)
        .await
        .unwrap();

    let mut client = AuthlyServiceClient::new(AuthlyServiceServerImpl::new_service(ctx.clone()));

    let namespaces: BTreeSet<String> = client
        .get_resource_property_mappings(tonic_request(proto::Empty {}, ULTRADB))
        .await
        .unwrap()
        .into_inner()
        .namespaces
        .into_iter()
        .map(|ns| ns.label)
        .collect();

    assert_eq!(
        BTreeSet::from(["pants".to_string(), "ultradb".to_string()]),
        namespaces
    );
}
