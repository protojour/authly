use std::collections::BTreeSet;

use authly_common::{
    id::{Eid, ObjId},
    policy::{
        code::{to_bytecode, PolicyValue},
        engine::PolicyEngine,
    },
};
use authly_db::{literal::Literal, param::AsParam, Db, DbResult, FromRow, Row, TryFromRow};
use hiqlite::{params, Param};
use indoc::indoc;
use itertools::Itertools;
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::policy::compiler::{expr::Expr, PolicyCompiler};

use super::Identified;

#[derive(Debug)]
pub struct DbPolicy {
    pub label: String,
    pub policy: PolicyPostcard,
}

/// The structure of how a policy in stored in postcard format in the database
#[derive(Serialize, Deserialize, Debug)]
pub struct PolicyPostcard {
    pub class: PolicyValue,
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
        let opcodes = PolicyCompiler::expr_to_opcodes(&policy_pc.expr);
        let bytecode = to_bytecode(&opcodes);

        policy_engine.add_policy(id, policy_pc.class, bytecode);
    }

    for DbPolicyBinding {
        attr_matcher,
        policies,
    } in policy_data.bindings
    {
        policy_engine.add_trigger(
            attr_matcher
                .iter()
                .map(ObjId::to_any)
                .collect::<BTreeSet<_>>(),
            policies,
        );
    }

    Ok(policy_engine)
}

impl TryFromRow for Identified<ObjId, PolicyPostcard> {
    type Error = postcard::Error;

    fn try_from_row(row: &mut impl Row) -> Result<Self, Self::Error> {
        let id = row.get_id("id");
        let policy_postcard: PolicyPostcard = postcard::from_bytes(&row.get_blob("policy_pc"))?;

        Ok(Identified(id, policy_postcard))
    }
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
        .query_filter_map(
            format!(
                "SELECT id, policy_pc FROM policy WHERE id IN ({})",
                policy_ids.iter().map(|id| id.literal()).format(", ")
            )
            .into(),
            params!(),
        )
        .await?;

    Ok(PoliciesWithBindings { bindings, policies })
}

impl FromRow for DbPolicyBinding {
    fn from_row(row: &mut impl Row) -> Self {
        Self {
            attr_matcher: BTreeSet::from_iter(row.get_ids_concatenated("attr_matcher")),
            policies: BTreeSet::from_iter(row.get_ids_concatenated("policies")),
        }
    }
}

async fn list_svc_implied_policy_bindings(
    deps: &impl Db,
    svc_id: Eid,
) -> DbResult<Vec<DbPolicyBinding>> {
    deps.query_map(
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
    .await
}
