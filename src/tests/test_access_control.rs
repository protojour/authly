use authly_common::{
    id::{AttrId, Eid},
    policy::{
        code::PolicyValue,
        engine::{AccessControlParams, NoOpPolicyTracer},
    },
};
use hexhex::hex_literal;
use indoc::indoc;

use crate::{
    ctx::GetDb,
    db::policy_db::{self, load_svc_policies_with_bindings},
    test_support::TestCtx,
    tests::{compile_and_apply_doc, ServiceProperties},
};

const SVC_A: Eid = Eid::from_raw_array(hex_literal!("e5462a0d22b54d9f9ca37bd96e9b9d8b"));
const SVC_B: Eid = Eid::from_raw_array(hex_literal!("015362d6655447c6b7f44865bd111c70"));

#[test_log::test(tokio::test)]
async fn test_access_control_basic() {
    let ctx = TestCtx::default().inmemory_db().await;
    let doc = indoc! {
        r#"
        [authly-document]
        id = "bc9ce588-50c3-47d1-94c1-f88b21eaf299"

        [[service-entity]]
        eid = "e.e5462a0d22b54d9f9ca37bd96e9b9d8b"
        label = "svc_a"

        [[service-entity]]
        eid = "e.015362d6655447c6b7f44865bd111c70"
        label = "svc_b"

        [[entity-property]]
        domain = "svc_a"
        label = "trait"
        attributes = ["has_legs"]

        [[resource-property]]
        domain = "svc_a"
        label = "kind"
        attributes = ["trousers"]

        [[resource-property]]
        domain = "svc_a"
        label = "verb"
        attributes = ["wear"]

        [[policy]]
        label = "allow for legged creatures"
        allow = "Subject.svc_a:trait == svc_a:trait:has_legs"

        [[policy-binding]]
        attributes = ["svc_a:kind:trousers", "svc_a:verb:wear"]
        policies = ["allow for legged creatures"]
        "#
    };

    compile_and_apply_doc(doc, &Default::default(), &ctx)
        .await
        .unwrap();

    {
        let engine = policy_db::load_svc_policy_engine(ctx.get_db(), SVC_A)
            .await
            .unwrap();
        let props = ServiceProperties::load(SVC_A, ctx.get_db()).await;

        assert_eq!(1, engine.get_policy_count());
        assert_eq!(1, engine.get_trigger_count());

        println!("engine: {engine:#?}");

        assert_eq!(
            PolicyValue::Deny,
            engine
                .eval(
                    &AccessControlParams {
                        ..Default::default()
                    },
                    &mut NoOpPolicyTracer
                )
                .unwrap(),
            "no policy triggers results in Deny"
        );

        assert_eq!(
            PolicyValue::Deny,
            engine
                .eval(
                    &AccessControlParams {
                        resource_attrs: FromIterator::from_iter([AttrId::from_uint(42)]),
                        ..Default::default()
                    },
                    &mut NoOpPolicyTracer
                )
                .unwrap(),
            "unknown resource attr triggers nothing"
        );

        assert_eq!(
            PolicyValue::Deny,
            engine
                .eval(
                    &AccessControlParams {
                        resource_attrs: props.resource.translate([("svc_a", "kind", "trousers")]),
                        subject_attrs: props.entity.translate([("svc_a", "trait", "has_legs")]),
                        ..Default::default()
                    },
                    &mut NoOpPolicyTracer
                )
                .unwrap(),
            "insufficient resource environment denies"
        );

        assert_eq!(
            PolicyValue::Deny,
            engine
                .eval(
                    &AccessControlParams {
                        resource_attrs: props
                            .resource
                            .translate([("svc_a", "kind", "trousers"), ("svc_a", "verb", "wear")]),
                        ..Default::default()
                    },
                    &mut NoOpPolicyTracer
                )
                .unwrap(),
            "succifient entity environment allows"
        );

        assert_eq!(
            PolicyValue::Allow,
            engine
                .eval(
                    &AccessControlParams {
                        resource_attrs: props
                            .resource
                            .translate([("svc_a", "kind", "trousers"), ("svc_a", "verb", "wear")]),
                        subject_attrs: props.entity.translate([("svc_a", "trait", "has_legs")]),
                        ..Default::default()
                    },
                    &mut NoOpPolicyTracer
                )
                .unwrap(),
            "succifient resource environment allows"
        );
    }

    {
        let svc_b_policy_engine = policy_db::load_svc_policy_engine(ctx.get_db(), SVC_B)
            .await
            .unwrap();
        assert_eq!(0, svc_b_policy_engine.get_policy_count());
        assert_eq!(0, svc_b_policy_engine.get_trigger_count());
    }
}

/// This tests the logic for determining which policy bindings (attribute matchers) are relevant
/// to a service depends correctly on the set of domains the service participates in.
#[test_log::test(tokio::test)]
async fn test_svc_domain_implied_policies() {
    let ctx = TestCtx::default().inmemory_db().await;
    let doc = indoc! {
        r#"
        [authly-document]
        id = "bc9ce588-50c3-47d1-94c1-f88b21eaf299"

        [[domain]]
        label = "foo"
        [[domain]]
        label = "bar"

        [[service-entity]]
        eid = "e.e5462a0d22b54d9f9ca37bd96e9b9d8b"
        label = "svc_a"

        [[service-entity]]
        eid = "e.015362d6655447c6b7f44865bd111c70"
        label = "svc_b"

        [[service-domain]]
        service = "svc_a"
        domain = "foo"

        [[service-domain]]
        service = "svc_b"
        domain = "foo"

        [[service-domain]]
        service = "svc_b"
        domain = "bar"

        [[resource-property]]
        domain = "foo"
        label = "fooA"
        attributes = ["fooA"]
        [[resource-property]]
        domain = "foo"
        label = "fooB"
        attributes = ["fooB"]

        [[resource-property]]
        domain = "bar"
        label = "barA"
        attributes = ["barA"]
        [[resource-property]]
        domain = "bar"
        label = "barB"
        attributes = ["barB"]

        [[policy]]
        label = "pol1"
        allow = "Subject.authly:entity == svc_a"

        [[policy]]
        label = "pol2"
        allow = "Subject.authly:entity == svc_b"

        [[policy-binding]]
        attributes = ["foo:fooA:fooA", "foo:fooB:fooB"]
        policies = ["pol1"]

        [[policy-binding]]
        attributes = ["bar:barA:barA", "bar:barB:barB"]
        policies = ["pol2"]
        "#
    };

    compile_and_apply_doc(doc, &Default::default(), &ctx)
        .await
        .unwrap();

    let pol_a = load_svc_policies_with_bindings(ctx.get_db(), SVC_A)
        .await
        .unwrap();
    assert_eq!(pol_a.policies.len(), 1);

    let pol_b = load_svc_policies_with_bindings(ctx.get_db(), SVC_B)
        .await
        .unwrap();
    assert_eq!(pol_b.policies.len(), 2);
}
