use std::collections::HashMap;

use anyhow::anyhow;
use hiqlite::{params, Param};
use indoc::indoc;
use tracing::warn;

use crate::{AuthlyCtx, EID};

use super::Convert;

pub async fn find_service_label_by_eid(eid: EID, ctx: &AuthlyCtx) -> anyhow::Result<String> {
    let mut row = ctx
        .db
        .query_raw(
            "SELECT svc.label FROM svc WHERE eid = $1",
            params!(eid.as_param()),
        )
        .await
        .map_err(|err| {
            warn!(?err, "failed to lookup service label");
            err
        })?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("service not found"))?;

    Ok(row.get("label"))
}

pub async fn find_service_eid_by_k8s_service_account_name(
    namespace: &str,
    account_name: &str,
    ctx: &AuthlyCtx,
) -> anyhow::Result<Option<EID>> {
    let Some(mut row) = ctx
        .db
        .query_raw(
            "SELECT svc_eid FROM svc_ext_k8s_service_account WHERE namespace = $1 AND account_name = $2",
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

    Ok(Some(EID::from_row(&mut row, "svc_eid")))
}

#[derive(Debug)]
pub struct ServiceProperty {
    pub id: EID,
    pub label: String,
    pub attributes: Vec<(EID, String)>,
}

pub enum ServicePropertyKind {
    Entity,
    Resource,
}

pub async fn list_service_properties(
    aid: EID,
    svc_eid: EID,
    property_kind: ServicePropertyKind,
    ctx: &AuthlyCtx,
) -> anyhow::Result<Vec<ServiceProperty>> {
    let rows = match property_kind {
        ServicePropertyKind::Entity => {
            ctx.db
                .query_raw(
                    indoc! {
                        "
                        SELECT p.id pid, p.label plabel, a.id attrid, a.label alabel
                        FROM svc_ent_prop p
                        JOIN svc_ent_attrlabel a ON a.prop_id = p.id
                        WHERE p.aid = $1 AND p.svc_eid = $2
                        ",
                    },
                    params!(aid.as_param(), svc_eid.as_param()),
                )
                .await?
        }
        ServicePropertyKind::Resource => {
            ctx.db
                .query_raw(
                    indoc! {
                        "
                        SELECT p.id pid, p.label plabel, a.id attrid, a.label alabel
                        FROM svc_res_prop p
                        JOIN svc_res_attrlabel a ON a.prop_id = p.id
                        WHERE p.aid = $1 AND p.svc_eid = $2
                        ",
                    },
                    params!(aid.as_param(), svc_eid.as_param()),
                )
                .await?
        }
    };

    let mut properties: HashMap<EID, ServiceProperty> = Default::default();

    for mut row in rows {
        let prop_id = EID::from_row(&mut row, "pid");

        let property = properties
            .entry(prop_id)
            .or_insert_with(|| ServiceProperty {
                id: prop_id,
                label: row.get("plabel"),
                attributes: vec![],
            });

        property
            .attributes
            .push((EID::from_row(&mut row, "attrid"), row.get("alabel")));
    }

    Ok(properties.into_values().collect())
}
