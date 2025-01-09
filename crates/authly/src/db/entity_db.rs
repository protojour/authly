use std::collections::HashSet;

use argon2::{password_hash::SaltString, Argon2};
use authly_domain::Eid;
use hiqlite::{params, Param};

use super::{Convert, Db, DbResult, Row};

pub struct EntityPasswordHash {
    pub eid: Eid,
    pub secret_hash: String,
}

pub async fn list_entity_attrs(deps: &impl Db, eid: Eid) -> DbResult<HashSet<Eid>> {
    Ok(deps
        .query_raw(
            "SELECT attrid FROM ent_attr WHERE eid = $1".into(),
            params!(eid.as_param()),
        )
        .await?
        .into_iter()
        .map(|mut row| Eid::from_row(&mut row, "attrid"))
        .collect())
}

pub async fn find_local_authority_entity_password_hash_by_credential_ident(
    deps: &impl Db,
    ident_kind: &str,
    ident: &str,
) -> DbResult<Option<EntityPasswordHash>> {
    let (eid, hash): (Eid, String) = {
        let Some(mut row) =
            deps
            .query_raw(
                "SELECT p.eid, p.hash FROM ent_ident i JOIN ent_password p ON i.eid = p.eid WHERE i.kind = $1 AND i.ident = $2".into(),
                params!(ident_kind, ident),
            )
            .await?
            .into_iter()
            .next() else {
                return Ok(None);
            };

        (Eid::from_row(&mut row, "eid"), row.get_text("hash"))
    };

    Ok(Some(EntityPasswordHash {
        eid,
        secret_hash: hash,
    }))
}

#[expect(unused)]
pub async fn try_insert_entity_credentials(
    deps: &impl Db,
    aid: Eid,
    eid: Eid,
    ident: String,
    secret: String,
) -> anyhow::Result<Eid> {
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

    deps
        .execute(
            "INSERT INTO entity_password (aid, eid, hash) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE SET hash = $3".into(),
            params!(aid.as_param(), eid.as_param(), secret_hash),
        )
        .await?;

    Ok(eid)
}
