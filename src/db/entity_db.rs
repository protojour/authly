use argon2::{password_hash::SaltString, Argon2};
use authly_common::id::{Eid, ObjId};
use authly_db::{param::AsParam, Db, DbResult, FromRow, Row};
use fnv::FnvHashSet;
use hiqlite::{params, Param};
use indoc::indoc;

use crate::id::BuiltinID;

pub struct EntityPasswordHash {
    pub eid: Eid,
    pub secret_hash: String,
}

pub struct EntityAttrs(pub FnvHashSet<ObjId>);

pub async fn list_entity_attrs(deps: &impl Db, eid: Eid) -> DbResult<FnvHashSet<ObjId>> {
    struct EntityAttr(ObjId);

    impl FromRow for EntityAttr {
        fn from_row(row: &mut impl Row) -> Self {
            Self(row.get_id("attrid"))
        }
    }

    Ok(deps
        .query_map::<EntityAttr>(
            "SELECT attrid FROM ent_attr WHERE eid = $1".into(),
            params!(eid.as_param()),
        )
        .await?
        .into_iter()
        .map(|attr| attr.0)
        .collect())
}

impl FromRow for EntityPasswordHash {
    fn from_row(row: &mut impl Row) -> Self {
        Self {
            eid: row.get_id("obj_id"),
            secret_hash: row.get_text("value"),
        }
    }
}

pub async fn find_local_directory_entity_password_hash_by_entity_ident(
    deps: &impl Db,
    ident_prop_id: ObjId,
    ident_fingerprint: &[u8],
) -> DbResult<Option<EntityPasswordHash>> {
    deps.query_map_opt(
        indoc! {
            "
            SELECT ta.obj_id, ta.value FROM obj_text_attr ta
            JOIN ent_ident i ON i.eid = ta.obj_id
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
    .await
}

#[expect(unused)]
pub async fn try_insert_entity_credentials(
    deps: &impl Db,
    dir_id: Eid,
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
            "INSERT INTO entity_password (dir_id, eid, hash) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE SET hash = $3".into(),
            params!(dir_id.as_param(), eid.as_param(), secret_hash),
        )
        .await?;

    Ok(eid)
}
