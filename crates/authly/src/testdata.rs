use authly_domain::EID;
use tracing::{debug, info};

use crate::{db::entity_db, AuthlyCtx};

const AUTHORITY_ID: EID = EID(659846869547698465789657494);

pub async fn try_init_users(ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let register_result = entity_db::try_insert_entity_credentials(
        AUTHORITY_ID,
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

    Ok(())
}
