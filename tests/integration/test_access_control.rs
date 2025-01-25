use authly::{ctx::GetDb, db::service_db};
use authly_common::{
    document::Document,
    id::{AnyId, Eid},
    policy::{code::Outcome, engine::AccessControlParams},
};
use hexhex::hex_literal;
use indoc::indoc;

use crate::{compile_and_apply_doc, ServiceProperties, TestCtx};

const SVC_A: Eid = Eid::from_array(hex_literal!("e5462a0d22b54d9f9ca37bd96e9b9d8b"));
const SVC_B: Eid = Eid::from_array(hex_literal!("015362d6655447c6b7f44865bd111c70"));

#[tokio::test]
async fn test_access_control_basic() {
    let ctx = TestCtx::default().inmemory_db().await;
    let doc = Document::from_toml(indoc! {
        r#"
        [authly-document]
        id = "bc9ce588-50c3-47d1-94c1-f88b21eaf299"

        [[service-entity]]
        eid = "e5462a0d22b54d9f9ca37bd96e9b9d8b"
        label = "svc_a"

        [[service-entity]]
        eid = "015362d6655447c6b7f44865bd111c70"
        label = "svc_b"

        [[entity-property]]
        service = "svc_a"
        label = "trait"
        attributes = ["has_legs"]

        [[resource-property]]
        service = "svc_a"
        label = "kind"
        attributes = ["trousers"]

        [[resource-property]]
        service = "svc_a"
        label = "verb"
        attributes = ["wear"]

        [[policy]]
        service = "svc_a"
        label = "allow for legged creatures"
        allow = "Subject.trait == trait/has_legs"

        [[policy-binding]]
        service = "svc_a"
        attributes = ["kind/trousers", "verb/wear"]
        policies = ["allow for legged creatures"]
        "#
    })
    .unwrap();

    compile_and_apply_doc(doc, &Default::default(), &ctx)
        .await
        .unwrap();

    {
        let engine = service_db::load_policy_engine(&ctx, SVC_A).await.unwrap();
        let props = ServiceProperties::load(SVC_A, ctx.get_db()).await;

        assert_eq!(1, engine.get_policy_count());
        assert_eq!(1, engine.get_trigger_count());

        println!("engine: {engine:#?}");

        assert_eq!(
            Outcome::Deny,
            engine
                .eval(&AccessControlParams {
                    ..Default::default()
                })
                .unwrap(),
            "no policy triggers results in Deny"
        );

        assert_eq!(
            Outcome::Deny,
            engine
                .eval(&AccessControlParams {
                    resource_attrs: FromIterator::from_iter([AnyId::from_uint(42)]),
                    ..Default::default()
                })
                .unwrap(),
            "unknown resource attr triggers nothing"
        );

        assert_eq!(
            Outcome::Deny,
            engine
                .eval(&AccessControlParams {
                    resource_attrs: props.resource.translate([("kind", "trousers")]),
                    subject_attrs: props.entity.translate([("trait", "has_legs")]),
                    ..Default::default()
                })
                .unwrap(),
            "insufficient resource environment denies"
        );

        assert_eq!(
            Outcome::Deny,
            engine
                .eval(&AccessControlParams {
                    resource_attrs: props
                        .resource
                        .translate([("kind", "trousers"), ("verb", "wear")]),
                    ..Default::default()
                })
                .unwrap(),
            "succifient entity environment allows"
        );

        assert_eq!(
            Outcome::Allow,
            engine
                .eval(&AccessControlParams {
                    resource_attrs: props
                        .resource
                        .translate([("kind", "trousers"), ("verb", "wear")]),
                    subject_attrs: props.entity.translate([("trait", "has_legs")]),
                    ..Default::default()
                })
                .unwrap(),
            "succifient resource environment allows"
        );
    }

    {
        let svc_b_policy_engine = service_db::load_policy_engine(&ctx, SVC_B).await.unwrap();
        assert_eq!(0, svc_b_policy_engine.get_policy_count());
        assert_eq!(0, svc_b_policy_engine.get_trigger_count());
    }
}
