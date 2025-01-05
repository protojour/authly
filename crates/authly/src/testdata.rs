use authly_domain::EID;
use serde_json::json;
use tracing::{debug, info, warn};

use crate::{
    db::{
        entity_db,
        service_db::{self, SvcDef},
    },
    AuthlyCtx,
};

pub async fn try_init_testdata(ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let register_result = entity_db::try_insert_entity_credentials(
        EID::random(),
        "testuser".to_string(),
        "secret".to_string(),
        ctx,
    )
    .await;

    if let Err(err) = register_result {
        debug!(?err, "failed to register user");
    }

    let entity_count = entity_db::entity_count(ctx.clone()).await?;

    info!("there are {entity_count} entities");

    if let Err(e) = service_db::store_service(
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
        "k8s_ext": {
            "service_accounts": [{
                "namespace": "authly-test",
                "account_name": "testservice"
            }]
        }
    }))
    .unwrap()
}
