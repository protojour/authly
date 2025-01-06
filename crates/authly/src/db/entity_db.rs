use anyhow::anyhow;
use argon2::{password_hash::SaltString, Argon2};
use authly_domain::EID;
use hiqlite::{params, Param};
use tracing::warn;

use crate::AuthlyCtx;

use super::Convert;

pub struct EntitySecretHash {
    pub eid: EID,
    pub secret_hash: String,
}

pub async fn try_insert_entity_credentials(
    authority_eid: EID,
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
            "INSERT INTO entity_credential (authority_eid, eid, ident, secret_hash) VALUES ($1, $2, $3, $4) ON CONFLICT DO UPDATE SET ident = $3, secret_hash = $4",
            params!(authority_eid.as_param(), eid.as_param(), ident, secret_hash),
        )
        .await?;

    Ok(eid)
}

pub async fn find_local_authority_entity_secret_hash_by_credential_ident(
    ident: &str,
    ctx: &AuthlyCtx,
) -> anyhow::Result<EntitySecretHash> {
    let (eid, secret_hash): (EID, String) = {
        let mut row = ctx
            .db
            .query_raw(
                "SELECT eid, secret_hash FROM entity_credential WHERE ident = $1",
                params!(ident),
            )
            .await
            .map_err(|err| {
                warn!(?err, "failed to lookup entity");
                err
            })?
            .into_iter()
            .next()
            .ok_or_else(|| anyhow!("credential not found"))?;

        (EID::from_row(&mut row, "eid"), row.get("secret_hash"))
    };

    Ok(EntitySecretHash { eid, secret_hash })
}

pub async fn entity_count(ctx: AuthlyCtx) -> anyhow::Result<usize> {
    let mut row = ctx
        .db
        .query_raw_one("SELECT count(*) AS count FROM entity_credential", params!())
        .await?;

    let count: i64 = row.get("count");
    Ok(count as usize)
}
