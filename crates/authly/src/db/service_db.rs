use std::collections::HashMap;

use anyhow::anyhow;
use hiqlite::{params, Param};
use indoc::indoc;
use tracing::warn;

use crate::{AuthlyCtx, EID};

use super::Convert;

pub async fn find_service_name_by_eid(eid: EID, ctx: &AuthlyCtx) -> anyhow::Result<String> {
    let mut row = ctx
        .db
        .query_raw(
            "SELECT svc.name FROM svc WHERE eid = $1",
            params!(eid.as_param()),
        )
        .await
        .map_err(|err| {
            warn!(?err, "failed to lookup service credential");
            err
        })?
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("service not found"))?;

    Ok(row.get("name"))
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
    pub name: String,
    pub attributes: Vec<(EID, String)>,
}

pub enum ServicePropertyKind {
    Entity,
    Resource,
}

pub async fn list_service_properties(
    authority_id: EID,
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
                        SELECT p.id pid, p.name pname, a.id aid, a.name aname
                        FROM svc_eprop p
                        JOIN svc_etag a ON a.prop_id = p.id
                        WHERE p.authority_eid = $1 AND p.svc_eid = $2
                        ",
                    },
                    params!(authority_id.as_param(), svc_eid.as_param()),
                )
                .await?
        }
        ServicePropertyKind::Resource => {
            ctx.db
                .query_raw(
                    indoc! {
                        "
                        SELECT p.id pid, p.name pname, a.id aid, a.name aname
                        FROM svc_rprop p
                        JOIN svc_rtag a ON a.prop_id = p.id
                        WHERE p.authority_eid = $1 AND p.svc_eid = $2
                        ",
                    },
                    params!(authority_id.as_param(), svc_eid.as_param()),
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
                name: row.get("pname"),
                attributes: vec![],
            });

        property
            .attributes
            .push((EID::from_row(&mut row, "aid"), row.get("aname")));
    }

    Ok(properties.into_values().collect())
}
