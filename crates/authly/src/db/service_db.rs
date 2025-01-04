use anyhow::{anyhow, Context};
use hiqlite::{params, Param};
use serde::Deserialize;
use tracing::{info, warn};

use crate::{AuthlyCtx, EID};

#[derive(Deserialize)]
pub struct SvcDef {
    name: String,
    entity_props: Vec<SvcEntityProp>,
    resource_props: Vec<SvcResourceProp>,
    #[serde(default)]
    k8s_ext: SvcK8SExtension,
}

#[derive(Deserialize)]
struct SvcEntityProp {
    name: String,
    tags: Vec<String>,
}

#[derive(Deserialize)]
struct SvcResourceProp {
    name: String,
    tags: Vec<String>,
}

#[derive(Default, Deserialize)]
struct SvcK8SExtension {
    #[serde(default)]
    service_accounts: Vec<SvcK8SServiceAccount>,
}

#[derive(Deserialize)]
struct SvcK8SServiceAccount {
    namespace: String,
    account_name: String,
}

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

pub async fn store_service(ctx: &AuthlyCtx, svc_eid: EID, svc_def: SvcDef) -> anyhow::Result<()> {
    let _ = ctx
        .db
        .execute(
            "INSERT INTO svc (eid, name) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            params!(svc_eid.as_param(), svc_def.name),
        )
        .await?;

    // entity props
    for eprop in svc_def.entity_props {
        let mut row = ctx.db
            .execute_returning_one(
                "INSERT INTO svc_eprop (id, svc_eid, name) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE SET name = $3 RETURNING id",
                params!(EID::random().as_param(), svc_eid.as_param(), &eprop.name),
            )
            .await
            .context("upsert eprop")?;
        let eprop_id = EID::from_row(&mut row, "id");

        info!("eprop `{}` id={:?}", eprop.name, eprop_id);

        for tag_name in eprop.tags {
            ctx.db
                .execute(
                    "INSERT INTO svc_etag (id, prop_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    params!(EID::random().as_param(), eprop_id.as_param(), tag_name),
                )
                .await?;
        }
    }

    // resource props
    for rprop in svc_def.resource_props {
        let mut row = ctx.db
            .execute_returning_one(
                "INSERT INTO svc_rprop (id, svc_eid, name) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE set name = $3 RETURNING id",
                params!(EID::random().as_param(), svc_eid.as_param(), &rprop.name),
            )
            .await
            .context("upsert rprop")?;
        let rprop_id = EID::from_row(&mut row, "id");

        info!("rprop `{}` id={:?}", rprop.name, rprop_id);

        for tag_name in rprop.tags {
            ctx.db
                .execute(
                    "INSERT INTO svc_rtag (id, prop_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    params!(EID::random().as_param(), rprop_id.as_param(), tag_name),
                )
                .await?;
        }
    }

    // k8s service account
    for k8s_service_account in svc_def.k8s_ext.service_accounts {
        ctx.db.execute(
            "INSERT INTO svc_ext_k8s_service_account (svc_eid, namespace, account_name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
            params!(svc_eid.as_param(), k8s_service_account.namespace, k8s_service_account.account_name),
        )
        .await?;
    }

    Ok(())
}
