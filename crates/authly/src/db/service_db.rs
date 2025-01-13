use std::collections::HashMap;

use authly_common::{
    policy::{code::to_bytecode, pdp::PolicyEngine},
    ObjId,
};
use hiqlite::{params, Param};
use indoc::indoc;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    policy::{
        compiler::{expr::Expr, PolicyCompiler},
        PolicyOutcome,
    },
    Eid,
};

use super::{Convert, Db, DbError, DbResult, Row};

pub async fn find_service_label_by_eid(deps: &impl Db, eid: Eid) -> DbResult<Option<String>> {
    let Some(mut row) = deps
        .query_raw(
            "SELECT svc.label FROM svc WHERE eid = $1".into(),
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

    Ok(Some(row.get_text("label")))
}

pub async fn find_service_eid_by_k8s_service_account_name(
    deps: &impl Db,
    namespace: &str,
    account_name: &str,
) -> DbResult<Option<Eid>> {
    let Some(mut row) =
        deps
        .query_raw(
            "SELECT svc_eid FROM svc_ext_k8s_service_account WHERE namespace = $1 AND account_name = $2".into(),
            params!(namespace, account_name),
        )
        .await
        .map_err(|err| {
            warn!(?err, "failed to lookup entity");
            err
        })?
        .into_iter()
        .next() else {
            return Ok(None);
        };

    Ok(Some(Eid::from_row(&mut row, "svc_eid")))
}

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

pub async fn list_service_properties(
    deps: &impl Db,
    aid: Eid,
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
                        WHERE p.aid = $1 AND p.svc_eid = $2
                        ",
                }
                .into(),
                params!(aid.as_param(), svc_eid.as_param()),
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
                        WHERE p.aid = $1 AND p.svc_eid = $2
                        ",
                }
                .into(),
                params!(aid.as_param(), svc_eid.as_param()),
            )
            .await?
        }
    };

    let mut properties: HashMap<ObjId, ServiceProperty> = Default::default();

    for mut row in rows {
        let prop_id = ObjId::from_row(&mut row, "pid");

        let property = properties
            .entry(prop_id)
            .or_insert_with(|| ServiceProperty {
                id: prop_id,
                label: row.get_text("plabel"),
                attributes: vec![],
            });

        property
            .attributes
            .push((ObjId::from_row(&mut row, "attrid"), row.get_text("alabel")));
    }

    Ok(properties.into_values().collect())
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

pub async fn list_service_policies(
    deps: &impl Db,
    aid: Eid,
    svc_eid: Eid,
) -> DbResult<Vec<ServicePolicy>> {
    let rows = deps
        .query_raw(
            "SELECT id, label, policy_pc FROM svc_policy WHERE aid = $1 AND svc_eid = $2".into(),
            params!(aid.as_param(), svc_eid.as_param()),
        )
        .await?;

    let mut policies = Vec::with_capacity(rows.len());

    for mut row in rows {
        let id = ObjId::from_row(&mut row, "id");
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
        let id = ObjId::from_row(&mut row, "id");

        let policy_postcard: PolicyPostcard = postcard::from_bytes(&row.get_blob("policy_pc"))
            .map_err(|err| {
                tracing::error!(?err, "policy expr postcard error");
                DbError::BinaryEncoding
            })?;

        let opcodes =
            PolicyCompiler::expr_to_opcodes(&policy_postcard.expr, policy_postcard.outcome);
        let bytecode = to_bytecode(&opcodes);

        policy_engine.add_policy(id.value(), bytecode);
    }

    Ok(policy_engine)
}
