use argon2::{password_hash::SaltString, Argon2};
use authly_common::id::{Eid, ObjId};
use fnv::FnvHashSet;
use hiqlite::{params, Param};
use indoc::indoc;

use crate::id::BuiltinID;

use super::{AsParam, Db, DbResult, Row};

pub struct EntityPasswordHash {
    pub eid: Eid,
    pub secret_hash: String,
}

pub async fn list_entity_attrs(deps: &impl Db, eid: Eid) -> DbResult<FnvHashSet<ObjId>> {
    Ok(deps
        .query_raw(
            "SELECT attrid FROM ent_attr WHERE eid = $1".into(),
            params!(eid.as_param()),
        )
        .await?
        .into_iter()
        .map(|mut row| row.get_id("attrid"))
        .collect())
}

pub async fn find_local_directory_entity_password_hash_by_entity_ident(
    deps: &impl Db,
    ident_prop_id: ObjId,
    ident_fingerprint: &[u8],
) -> DbResult<Option<EntityPasswordHash>> {
    let (eid, hash): (Eid, String) = {
        let Some(mut row) = deps
            .query_raw(
                indoc! {
                    "
                    SELECT ta.eid, ta.value FROM ent_text_attr ta
                    JOIN ent_ident i ON ta.eid = i.eid
                    WHERE i.prop_id = $1 AND i.fingerprint = $2 AND ta.prop_id = $3
                    ",
                }
                .into(),
                params!(
                    ident_prop_id.as_param(),
                    ident_fingerprint,
                    BuiltinID::PropPasswordHash.to_obj_id().as_param()
                ),
            )
            .await?
            .into_iter()
            .next()
        else {
            return Ok(None);
        };

        (row.get_id("eid"), row.get_text("value"))
    };

    Ok(Some(EntityPasswordHash {
        eid,
        secret_hash: hash,
    }))
}

#[expect(unused)]
pub async fn try_insert_entity_credentials(
    deps: &impl Db,
    did: Eid,
    eid: Eid,
    ident: String,
    secret: String,
) -> anyhow::Result<Eid> {
    let secret_hash = tokio::task::spawn_blocking(move || -> anyhow::Result<String> {
        let salt = SaltString::generate(rand::thread_rng());
        Ok(
            argon2::PasswordHash::generate(Argon2::default(), secret, &salt)
                .map_err(|e| anyhow::anyhow!("failed to generate password hash: {}", e))?
                .to_string(),
        )
    })
    .await??;

    deps
        .execute(
            "INSERT INTO entity_password (did, eid, hash) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE SET hash = $3".into(),
            params!(did.as_param(), eid.as_param(), secret_hash),
        )
        .await?;

    Ok(eid)
}
