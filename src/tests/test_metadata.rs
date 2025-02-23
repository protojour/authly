use authly_common::{
    id::ServiceId,
    proto::service::{
        self as proto, authly_service_client::AuthlyServiceClient,
        service_message::ServiceMessageKind,
    },
};
use authly_test::test_ctx::TestCtx;
use futures_util::StreamExt;
use hexhex::hex_literal;
use indoc::indoc;
use itertools::Itertools;
use serde_json::json;
use tracing::info;

use crate::{
    proto::service_server::AuthlyServiceServerImpl,
    tests::{compile_and_apply_doc, compile_and_apply_doc_only_once},
};

use super::tonic_request;

const SVC: ServiceId = ServiceId::from_raw_array(hex_literal!("e5462a0d22b54d9f9ca37bd96e9b9d8b"));

#[test_log::test(tokio::test)]
async fn test_svc_namespace_metadata() {
    let ctx = TestCtx::new().inmemory_db().await;
    let doc = indoc! {
        r#"
        [authly-document]
        id = "bc9ce588-50c3-47d1-94c1-f88b21eaf299"

        [[domain]]
        label = "d1"
        metadata = { some_key = "some_value" }

        [[domain]]
        label = "d2"

        [[service-entity]]
        eid = "s.e5462a0d22b54d9f9ca37bd96e9b9d8b"
        label = "svc"

        [[service-domain]]
        service = "svc"
        domain = "d1"

        [[service-domain]]
        service = "svc"
        domain = "d2"

        [[domain]]
        label = "ignore_me"
        metadata = { ingored_too = "yes, really ignore" }

        [[service-entity]]
        eid = "s.fa226c4fab3c44d1a6d96af0245d283d"
        label = "ignore_me_too"

        [[service-domain]]
        service = "ignore_me_too"
        domain = "ignore_me"
        "#
    };

    compile_and_apply_doc(doc, &ctx).await.unwrap();

    let mut client = AuthlyServiceClient::new(AuthlyServiceServerImpl::new_service(ctx.clone()));

    let mut metadata = client
        .get_metadata(tonic_request(proto::Empty {}, SVC))
        .await
        .unwrap()
        .into_inner();

    metadata.namespaces.sort_by_key(|ns| ns.label.clone());

    {
        let [d1, d2, svc] = metadata.namespaces.into_iter().collect_array().unwrap();

        assert_eq!(d1.label, "d1");
        let metadata_json = serde_json::Value::Object(authly_common::proto::proto_struct_to_json(
            d1.metadata.unwrap(),
        ));
        assert_eq!(json!({ "some_key": "some_value" }), metadata_json);

        assert_eq!(d2.label, "d2");
        assert!(d2.metadata.is_none());

        assert_eq!(svc.label, "svc");
        assert!(svc.metadata.is_none());
    }

    {
        // test that the reload_cache event is sent when reloading the document
        let mut msg_stream = client
            .messages(tonic_request(proto::Empty {}, SVC))
            .await
            .unwrap()
            .into_inner();

        compile_and_apply_doc_only_once(doc, &ctx).await.unwrap();

        let message_kind = msg_stream
            .next()
            .await
            .unwrap()
            .unwrap()
            .service_message_kind
            .unwrap();

        match message_kind {
            ServiceMessageKind::ReloadCache(_) => {
                info!("received reload cache message!");
            }
            kind => {
                panic!("received incorrect message {kind:?}");
            }
        }
    }
}
