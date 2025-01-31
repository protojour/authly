use authly_common::{id::ObjId, service::PropertyMapping};
use authly_db::{literal::Literal, param::AsParam, Db, DbResult, Row};
use hiqlite::{params, Param};
use indoc::indoc;
use tracing::warn;

use crate::{id::BuiltinID, Eid};

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
                    FROM dom_ent_prop p
                    JOIN dom_ent_attrlabel a ON a.prop_id = p.id
                    WHERE p.dom_id = $1
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
                    FROM dom_res_prop p
                    JOIN dom_res_attrlabel a ON a.prop_id = p.id
                    WHERE p.dom_id = $1
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
