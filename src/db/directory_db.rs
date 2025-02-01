//! directory-oriented queries

use std::collections::HashMap;

use authly_common::id::{AnyId, ObjId};
use authly_db::{param::AsParam, Db, DbError, DbResult, Row};
use hiqlite::{params, Param};
use indoc::indoc;

use super::{
    policy_db::DbPolicy,
    service_db::{ServiceProperty, ServicePropertyKind},
    Identified,
};

pub async fn directory_list_domains(
    deps: &impl Db,
    dir_id: ObjId,
) -> DbResult<Vec<Identified<ObjId, String>>> {
    Ok(deps
        .query_raw(
            "SELECT id, label FROM domain WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
        )
        .await?
        .into_iter()
        .map(|mut row| Identified(row.get_id("id"), row.get_text("label")))
        .collect())
}

pub async fn directory_list_policies(
    deps: &impl Db,
    dir_id: ObjId,
) -> DbResult<Vec<Identified<ObjId, DbPolicy>>> {
    let rows = deps
        .query_raw(
            "SELECT id, label, policy_pc FROM policy WHERE dir_id = $1".into(),
            params!(dir_id.as_param()),
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

        policies.push(Identified(id, DbPolicy { label, policy }));
    }

    Ok(policies)
}

pub async fn list_domain_properties(
    deps: &impl Db,
    dir_id: ObjId,
    dom_id: AnyId,
    property_kind: ServicePropertyKind,
) -> DbResult<Vec<ServiceProperty>> {
    let rows = match property_kind {
        ServicePropertyKind::Entity => {
            deps.query_raw(
                indoc! {
                    "
                    SELECT p.id pid, p.label plabel, a.id attrid, a.label alabel
                    FROM dom_ent_prop p
                    JOIN dom_ent_attrlabel a ON a.prop_id = p.id
                    WHERE p.dir_id = $1 AND p.dom_id = $2
                    ",
                }
                .into(),
                params!(dir_id.as_param(), dom_id.as_param()),
            )
            .await?
        }
        ServicePropertyKind::Resource => {
            deps.query_raw(
                indoc! {
                    "
                    SELECT p.id pid, p.label plabel, a.id attrid, a.label alabel
                    FROM dom_res_prop p
                    JOIN dom_res_attrlabel a ON a.prop_id = p.id
                    WHERE p.dir_id = $1 AND p.dom_id = $2
                    ",
                }
                .into(),
                params!(dir_id.as_param(), dom_id.as_param()),
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
