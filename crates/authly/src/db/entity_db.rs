use anyhow::anyhow;
use argon2::{password_hash::SaltString, Argon2};
use authly_domain::EID;
use hiqlite::{params, Param};
use tracing::warn;

use crate::AuthlyCtx;

use super::Convert;

pub struct EntityPasswordHash {
    pub eid: EID,
    pub secret_hash: String,
}

#[expect(unused)]
pub async fn try_insert_entity_credentials(
    aid: EID,
    eid: EID,
    ident: String,
    secret: String,
    ctx: &AuthlyCtx,
) -> anyhow::Result<EID> {
    let secret_hash = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let salt = SaltString::generate(rand::thread_rng());
        Ok(
            argon2::PasswordHash::generate(Argon2::default(), secret, &salt)
                .map_err(|e| anyhow::anyhow!("failed to generate password hash: {}", e))?
                .to_string()
                .into(),
        )
    })
    .await??;

    ctx.db
        .execute(
            "INSERT INTO entity_password (aid, eid, hash) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE SET hash = $3",
            params!(aid.as_param(), eid.as_param(), secret_hash),
        )
        .await?;

    Ok(eid)
}

pub async fn find_local_authority_entity_password_hash_by_credential_ident(
    ident_kind: &str,
    ident: &str,
    ctx: &AuthlyCtx,
) -> anyhow::Result<EntityPasswordHash> {
    let (eid, hash): (EID, String) = {
        let mut row = ctx
            .db
            .query_raw(
                "SELECT p.eid, p.hash FROM ent_ident i JOIN ent_password p ON i.eid = p.eid WHERE i.kind = $1 AND i.ident = $2",
                params!(ident_kind, ident),
            )
            .await
            .map_err(|err| {
                warn!(?err, "failed to lookup entity");
                err
            })?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("credential not found"))?;

        (EID::from_row(&mut row, "eid"), row.get("hash"))
    };

    Ok(EntityPasswordHash {
        eid,
        secret_hash: hash,
    })
}
