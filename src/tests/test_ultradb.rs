use std::collections::BTreeSet;

use authly_common::{
    id::Eid,
    mtls_server::PeerServiceEntity,
    proto::service::{self as proto, authly_service_client::AuthlyServiceClient},
};
use hexhex::hex_literal;

use super::compile_and_apply_doc_dir;
use crate::{proto::service_server::AuthlyServiceServerImpl, test_support::TestCtx};

const ULTRADB: Eid = Eid::from_raw_array(hex_literal!("ec29ba1d23cb43f89b7c73db6f177a1d"));

fn new_request<T>(msg: T) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.extensions_mut().insert(PeerServiceEntity(ULTRADB));
    req
}

#[test_log::test(tokio::test)]
async fn test_ultradb() {
    let ctx = TestCtx::default().inmemory_db().await;
    compile_and_apply_doc_dir("examples/ultradb".into(), &ctx)
        .await
        .unwrap();

    let mut client = AuthlyServiceClient::new(AuthlyServiceServerImpl::new_service(ctx.clone()));

    let namespaces: BTreeSet<String> = client
        .get_resource_property_mappings(new_request(proto::Empty {}))
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
