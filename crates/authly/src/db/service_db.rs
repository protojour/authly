use anyhow::{anyhow, Context};
use hiqlite::{params, Param};
use serde::Deserialize;
use tracing::{info, warn};

use crate::{AuthlyCtx, EID};

use super::entity_db::{self, EntitySecretHash};

#[derive(Deserialize)]
pub struct SvcDef {
    name: String,
    secret: String,
    entity_props: Vec<SvcEntityProp>,
    resource_props: Vec<SvcResourceProp>,
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

pub async fn find_service_secret_hash_by_service_name(
    svc_name: &str,
    ctx: &AuthlyCtx,
) -> anyhow::Result<EntitySecretHash> {
    let (eid, secret_hash): (EID, String) = {
        let mut row = ctx
            .db
            .query_raw(
                "SELECT svc.eid, entity_credential.secret_hash FROM svc JOIN entity_credential ON entity_credential.eid = svc.eid WHERE svc.name = $1",
                params!(svc_name),
            )
            .await
            .map_err(|err| {
                warn!(?err, "failed to lookup service credential");
                err
            })?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("credential not found"))?;

        (EID::from_row(&mut row, "eid"), row.get("secret_hash"))
    };

    Ok(EntitySecretHash { eid, secret_hash })
}

pub async fn store_service(ctx: &AuthlyCtx, svc_eid: EID, svc_def: SvcDef) -> anyhow::Result<()> {
    let _ = ctx
        .db
        .execute(
            "INSERT INTO svc (eid, name) VALUES ($1, $2) ON CONFLICT DO NOTHING",
            params!(svc_eid.as_param(), svc_def.name),
        )
        .await?;

    entity_db::try_insert_entity_credentials(svc_eid, None, svc_def.secret, ctx).await?;

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

    Ok(())
}
