use std::collections::HashMap;

use hiqlite::{params, Param};
use indoc::indoc;
use tracing::warn;

use crate::Eid;

use super::{Convert, Db, DbResult, Row};

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
    pub id: Eid,
    pub label: String,
    pub attributes: Vec<(Eid, String)>,
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

    let mut properties: HashMap<Eid, ServiceProperty> = Default::default();

    for mut row in rows {
        let prop_id = Eid::from_row(&mut row, "pid");

        let property = properties
            .entry(prop_id)
            .or_insert_with(|| ServiceProperty {
                id: prop_id,
                label: row.get_text("plabel"),
                attributes: vec![],
            });

        property
            .attributes
            .push((Eid::from_row(&mut row, "attrid"), row.get_text("alabel")));
    }

    Ok(properties.into_values().collect())
}
