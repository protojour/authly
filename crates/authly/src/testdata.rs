use anyhow::Context;
use hiqlite::{params, Param};
use serde::Deserialize;
use serde_json::json;
use tracing::{debug, info, warn};

use crate::{
    user::{try_register_user, user_count},
    AuthlyCtx, EID,
};

pub async fn try_init_testdata(ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let register_result =
        try_register_user("testuser".to_string(), "secret".to_string(), ctx.clone()).await;

    if let Err(err) = register_result {
        debug!(?err, "failed to register user");
    }

    let user_count = user_count(ctx.clone()).await?;

    info!("There are {user_count} users");

    if let Err(e) = make_service(
        ctx,
        EID(272878235402143010663560859986869906352),
        testservice_def(),
    )
    .await
    {
        warn!(?e, "failed to make service");
    }

    Ok(())
}

#[derive(Deserialize)]
struct SvcDef {
    name: String,
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

fn testservice_def() -> SvcDef {
    serde_json::from_value(json!({
        "name": "testservice",
        "entity_props": [
            {
                "name": "role",
                "tags": ["ui_user", "ui_admin"],
            }
        ],
        "resource_props": [
            {
                "name": "name",
                "tags": ["ontology", "storage"],
            },
            {
                "name": "ontology_action",
                "tags": ["read", "deploy", "stop"],
            },
            {
                "name": "buckets.action",
                "tags": ["read"],
            },
            {
                "name": "bucket.action",
                "tags": ["read", "create", "delete"],
            },
            {
                "name": "object.action",
                "tags": ["read", "create", "delete"],
            }
        ],
    }))
    .unwrap()
}

async fn make_service(ctx: &AuthlyCtx, svc_eid: EID, svc_def: SvcDef) -> anyhow::Result<()> {
    let _ = ctx
        .db
        .execute(
            "INSERT INTO svc (eid, name) VALUES ($1, $2)",
            params!(svc_eid.as_param(), svc_def.name),
        )
        .await;

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
            let _ = ctx.db
                .execute(
                    "INSERT INTO svc_etag (id, prop_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    params!(EID::random().as_param(), eprop_id.as_param(), tag_name),
                )
                .await;
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
            let _ = ctx.db
                .execute(
                    "INSERT INTO svc_rtag (id, prop_id, name) VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
                    params!(EID::random().as_param(), rprop_id.as_param(), tag_name),
                )
                .await;
        }
    }

    Ok(())
}
