use std::collections::{BTreeSet, HashMap};

use authly_common::{
    id::ObjId,
    policy::{code::to_bytecode, engine::PolicyEngine},
    service::PropertyMapping,
};
use authly_db::{literal::Literal, param::AsParam, Db, DbError, DbResult, Row};
use hiqlite::{params, Param};
use indoc::indoc;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    id::BuiltinID,
    policy::{
        compiler::{expr::Expr, PolicyCompiler},
        PolicyOutcome,
    },
    Eid,
};

#[derive(Debug)]
pub struct ServiceProperty {
    pub id: ObjId,
    pub label: String,
    pub attributes: Vec<(ObjId, String)>,
}

pub enum ServicePropertyKind {
    Entity,
    Resource,
}

#[derive(Debug)]
pub struct ServicePolicy {
    pub id: ObjId,
    pub svc_eid: Eid,
    pub label: String,
    pub policy: PolicyPostcard,
}

/// The structure of how a policy in stored in postcard format in the database
#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyPostcard {
    pub outcome: PolicyOutcome,
    pub expr: Expr,
}

#[derive(Debug)]
pub struct ServicePolicyBinding {
    pub svc_eid: Eid,
    pub attr_matcher: BTreeSet<ObjId>,
    pub policies: BTreeSet<ObjId>,
}

pub async fn find_service_label_by_eid(deps: &impl Db, eid: Eid) -> DbResult<Option<String>> {
    let Some(mut row) = deps
        .query_raw(
            format!(
                "SELECT value FROM ent_text_attr WHERE eid = $1 AND prop_id = {prop_id}",
                prop_id = BuiltinID::PropLabel.to_obj_id().literal()
            )
            .into(),
            params!(eid.as_param()),
        )
        .await
        .map_err(|err| {
            warn!(?err, "failed to lookup service label");
            err
        })?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };

    Ok(Some(row.get_text("value")))
}

pub async fn find_service_eid_by_k8s_service_account_name(
    deps: &impl Db,
    namespace: &str,
    account_name: &str,
) -> DbResult<Option<Eid>> {
    let Some(mut row) = deps
        .query_raw(
            "SELECT eid FROM ent_text_attr WHERE prop_id = $1 AND value = $2".into(),
            params!(
                BuiltinID::PropK8sServiceAccount.to_obj_id().as_param(),
                format!("{namespace}/{account_name}")
            ),
        )
        .await
        .map_err(|err| {
            warn!(?err, "failed to lookup entity");
            err
        })?
        .into_iter()
        .next()
    else {
        return Ok(None);
    };

    Ok(Some(row.get_id("eid")))
}

pub async fn list_service_properties(
    deps: &impl Db,
    did: Eid,
    svc_eid: Eid,
    property_kind: ServicePropertyKind,
) -> DbResult<Vec<ServiceProperty>> {
    let rows = match property_kind {
        ServicePropertyKind::Entity => {
            deps.query_raw(
                indoc! {
                    "
                        SELECT p.id pid, p.label plabel, a.id attrid, a.label alabel
                        FROM svc_ent_prop p
                        JOIN svc_ent_attrlabel a ON a.prop_id = p.id
                        WHERE p.did = $1 AND p.svc_eid = $2
                        ",
                }
                .into(),
                params!(did.as_param(), svc_eid.as_param()),
            )
            .await?
        }
        ServicePropertyKind::Resource => {
            deps.query_raw(
                indoc! {
                    "
                        SELECT p.id pid, p.label plabel, a.id attrid, a.label alabel
                        FROM svc_res_prop p
                        JOIN svc_res_attrlabel a ON a.prop_id = p.id
                        WHERE p.did = $1 AND p.svc_eid = $2
                        ",
                }
                .into(),
                params!(did.as_param(), svc_eid.as_param()),
            )
            .await?
        }
    };

    let mut properties: HashMap<ObjId, ServiceProperty> = Default::default();

    for mut row in rows {
        let prop_id = row.get_id("pid");

        let property = properties
            .entry(prop_id)
            .or_insert_with(|| ServiceProperty {
                id: prop_id,
                label: row.get_text("plabel"),
                attributes: vec![],
            });

        property
            .attributes
            .push((row.get_id("attrid"), row.get_text("alabel")));
    }

    Ok(properties.into_values().collect())
}

pub async fn get_service_property_mapping(
    deps: &impl Db,
    svc_eid: Eid,
    property_kind: ServicePropertyKind,
) -> DbResult<PropertyMapping> {
    let rows = match property_kind {
        ServicePropertyKind::Entity => {
            deps.query_raw(
                indoc! {
                    "
                    SELECT p.id pid, p.label plabel, a.id attrid, a.label alabel
                    FROM svc_ent_prop p
                    JOIN svc_ent_attrlabel a ON a.prop_id = p.id
                    WHERE p.svc_eid = $1
                    ",
                }
                .into(),
                params!(svc_eid.as_param()),
            )
            .await?
        }
        ServicePropertyKind::Resource => {
            deps.query_raw(
                indoc! {
                    "
                    SELECT p.id pid, p.label plabel, a.id attrid, a.label alabel
                    FROM svc_res_prop p
                    JOIN svc_res_attrlabel a ON a.prop_id = p.id
                    WHERE p.svc_eid = $1
                    ",
                }
                .into(),
                params!(svc_eid.as_param()),
            )
            .await?
        }
    };

    let mut mapping = PropertyMapping::default();

    for mut row in rows {
        let prop_label = row.get_text("plabel");
        let attr_label = row.get_text("alabel");
        let attr_id = row.get_id("attrid");

        mapping.add(prop_label, attr_label, attr_id);
    }

    Ok(mapping)
}

pub async fn list_service_policies(
    deps: &impl Db,
    did: Eid,
    svc_eid: Eid,
) -> DbResult<Vec<ServicePolicy>> {
    let rows = deps
        .query_raw(
            "SELECT id, label, policy_pc FROM svc_policy WHERE did = $1 AND svc_eid = $2".into(),
            params!(did.as_param(), svc_eid.as_param()),
        )
        .await?;

    let mut policies = Vec::with_capacity(rows.len());

    for mut row in rows {
        let id = row.get_id("id");
        let label = row.get_text("label");

        let policy = postcard::from_bytes(&row.get_blob("policy_pc")).map_err(|err| {
            tracing::error!(?err, "policy expr postcard error");
            DbError::BinaryEncoding
        })?;

        policies.push(ServicePolicy {
            id,
            svc_eid,
            label,
            policy,
        });
    }

    Ok(policies)
}

/// Load the policy engine for a service
pub async fn load_policy_engine(deps: &impl Db, svc_eid: Eid) -> DbResult<PolicyEngine> {
    let policy_rows = deps
        .query_raw(
            "SELECT id, policy_pc FROM svc_policy WHERE svc_eid = $1".into(),
            params!(svc_eid.as_param()),
        )
        .await?;

    let mut policy_engine = PolicyEngine::default();

    for mut row in policy_rows {
        let id = row.get_id("id");

        let policy_postcard: PolicyPostcard = postcard::from_bytes(&row.get_blob("policy_pc"))
            .map_err(|err| {
                tracing::error!(?err, "policy expr postcard error");
                DbError::BinaryEncoding
            })?;

        let opcodes =
            PolicyCompiler::expr_to_opcodes(&policy_postcard.expr, policy_postcard.outcome);
        let bytecode = to_bytecode(&opcodes);

        policy_engine.add_policy(id, bytecode);
    }

    let binding_rows = deps
        .query_raw(
            "SELECT attr_matcher_pc, policy_ids_pc FROM svc_policy_binding WHERE svc_eid = $1"
                .into(),
            params!(svc_eid.as_param()),
        )
        .await?;

    for mut row in binding_rows {
        let attr_matcher_pc = row.get_blob("attr_matcher_pc");
        let policy_ids_pc = row.get_blob("policy_ids_pc");

        let attr_matcher: BTreeSet<ObjId> = postcard::from_bytes(&attr_matcher_pc).unwrap();
        let policy_ids: BTreeSet<ObjId> = postcard::from_bytes(&policy_ids_pc).unwrap();

        if policy_ids.len() > 1 {
            for policy_id in policy_ids {
                policy_engine.add_policy_trigger(
                    attr_matcher.iter().map(ObjId::to_any).collect(),
                    policy_id,
                );
            }
        } else if let Some(policy_id) = policy_ids.into_iter().next() {
            policy_engine
                .add_policy_trigger(attr_matcher.iter().map(ObjId::to_any).collect(), policy_id);
        }
    }

    Ok(policy_engine)
}
