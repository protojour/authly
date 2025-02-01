use std::collections::BTreeSet;

use authly_common::{
    id::{Eid, ObjId},
    policy::{code::to_bytecode, engine::PolicyEngine},
};
use authly_db::{literal::Literal, param::AsParam, Db, DbError, DbResult, Row};
use hiqlite::{params, Param};
use indoc::indoc;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::policy::{
    compiler::{expr::Expr, PolicyCompiler},
    PolicyOutcome,
};

use super::Identified;

#[derive(Debug)]
pub struct DbPolicy {
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
pub struct DbPolicyBinding {
    pub attr_matcher: BTreeSet<ObjId>,
    pub policies: BTreeSet<ObjId>,
}

#[derive(Debug)]
pub struct PoliciesWithBindings {
    pub policies: Vec<Identified<ObjId, PolicyPostcard>>,
    pub bindings: Vec<DbPolicyBinding>,
}

/// Load the policy engine for a service
pub async fn load_svc_policy_engine(deps: &impl Db, svc_eid: Eid) -> DbResult<PolicyEngine> {
    let policy_data = load_svc_policies_with_bindings(deps, svc_eid).await?;

    debug!(?policy_data, ?svc_eid, "loaded policy data!!!!");

    let mut policy_engine = PolicyEngine::default();

    for Identified(id, policy_pc) in policy_data.policies {
        let opcodes = PolicyCompiler::expr_to_opcodes(&policy_pc.expr, policy_pc.outcome);
        let bytecode = to_bytecode(&opcodes);

        policy_engine.add_policy(id, bytecode);
    }

    for DbPolicyBinding {
        attr_matcher,
        policies,
    } in policy_data.bindings
    {
        if policies.len() > 1 {
            for policy_id in policies {
                policy_engine.add_policy_trigger(
                    attr_matcher.iter().map(ObjId::to_any).collect(),
                    policy_id,
                );
            }
        } else if let Some(policy_id) = policies.into_iter().next() {
            policy_engine
                .add_policy_trigger(attr_matcher.iter().map(ObjId::to_any).collect(), policy_id);
        }
    }

    Ok(policy_engine)
}

pub async fn load_svc_policies_with_bindings(
    deps: &impl Db,
    svc_id: Eid,
) -> DbResult<PoliciesWithBindings> {
    let bindings = list_svc_implied_policy_bindings(deps, svc_id).await?;

    let policy_ids = BTreeSet::<ObjId>::from_iter(
        bindings
            .iter()
            .flat_map(|binding| binding.policies.iter().copied()),
    );

    let policies = deps
        .query_raw(
            format!(
                "SELECT id, policy_pc FROM policy WHERE id IN ({})",
                policy_ids.iter().map(|id| id.literal()).format(", ")
            )
            .into(),
            params!(),
        )
        .await?
        .into_iter()
        .map(|mut row| {
            let id = row.get_id("id");

            let policy_postcard: PolicyPostcard = postcard::from_bytes(&row.get_blob("policy_pc"))
                .map_err(|err| {
                    tracing::error!(?err, "policy expr postcard error");
                    DbError::BinaryEncoding
                })?;

            Ok(Identified(id, policy_postcard))
        })
        .collect::<Result<_, DbError>>()?;

    Ok(PoliciesWithBindings { bindings, policies })
}

async fn list_svc_implied_policy_bindings(
    deps: &impl Db,
    svc_id: Eid,
) -> DbResult<Vec<DbPolicyBinding>> {
    let rows = deps
        .query_raw(
            indoc! {
                "
                SELECT
                    CAST(group_concat(pb_am.attr_id, '') AS BLOB) attr_matcher,
                    CAST(group_concat(pb_pol.policy_id, '') AS BLOB) policies
                FROM polbind_policy pb_pol
                JOIN polbind_attr_match pb_am ON pb_am.polbind_id = pb_pol.polbind_id
                JOIN dom_res_attrlabel ra ON ra.id = pb_am.attr_id
                JOIN dom_res_prop rp ON rp.id = ra.prop_id
                JOIN svc_domain sdom ON sdom.dom_id = rp.dom_id
                WHERE sdom.svc_eid = $1
                GROUP BY pb_pol.polbind_id
                "
            }
            .into(),
            params!(svc_id.as_param()),
        )
        .await?;

    Ok(rows
        .into_iter()
        .map(|mut row| DbPolicyBinding {
            attr_matcher: BTreeSet::from_iter(row.get_ids_concatenated("attr_matcher")),
            policies: BTreeSet::from_iter(row.get_ids_concatenated("policies")),
        })
        .collect())
}
