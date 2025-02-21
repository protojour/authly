use argon2::{password_hash::SaltString, Argon2};
use authly_common::id::{AttrId, EntityId, PersonaId, PropId};
use authly_db::{param::AsParam, Db, DbResult, DidInsert, FromRow, Row};
use fnv::FnvHashSet;
use hiqlite::{params, Param};
use indoc::indoc;

use crate::{directory::DirKey, id::BuiltinProp};

pub struct EntityPasswordHash {
    pub eid: PersonaId,
    pub secret_hash: String,
}

pub struct EntityAttrs(pub FnvHashSet<AttrId>);

pub async fn list_entity_attrs(deps: &impl Db, eid: EntityId) -> DbResult<FnvHashSet<AttrId>> {
    struct EntityAttr(AttrId);

    impl FromRow for EntityAttr {
        fn from_row(row: &mut impl Row) -> Self {
            Self(row.get_id("attrid"))
        }
    }

    Ok(deps
        .query_map::<EntityAttr>(
            indoc! {
                "
                SELECT attr.id AS attrid
                FROM ent_attr
                JOIN attr ON attr.key = ent_attr.attr_key
                WHERE ent_attr.eid = $1"
            }
            .into(),
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
    ident_prop_id: PropId,
    ident_fingerprint: &[u8],
) -> DbResult<Option<EntityPasswordHash>> {
    deps.query_map_opt(
        indoc! {
            "
            SELECT ta.obj_id, ta.value FROM obj_text_attr ta
            JOIN obj_ident i ON i.obj_id = ta.obj_id
            WHERE i.prop_id = $1 AND i.fingerprint = $2 AND ta.prop_id = $3
            ",
        }
        .into(),
        params!(
            ident_prop_id.as_param(),
            ident_fingerprint,
            PropId::from(BuiltinProp::PasswordHash).as_param()
        ),
    )
    .await
}

#[expect(unused)]
pub async fn try_insert_entity_credentials(
    deps: &impl Db,
    dir_key: DirKey,
    eid: PersonaId,
    ident: String,
    secret: String,
) -> anyhow::Result<PersonaId> {
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
            "INSERT INTO entity_password (dir_key, eid, hash) VALUES ($1, $2, $3) ON CONFLICT DO UPDATE SET hash = $3".into(),
            params!(dir_key.0, eid.as_param(), secret_hash),
        )
        .await?;

    Ok(eid)
}

pub struct OverwritePersonaId(pub bool);

pub async fn upsert_link_foreign_persona(
    deps: &impl Db,
    dir_key: DirKey,
    persona_id: PersonaId,
    overwrite_persona_id: OverwritePersonaId,
    foreign_id: Vec<u8>,
    now: time::OffsetDateTime,
) -> DbResult<(PersonaId, DidInsert)> {
    struct TypedRow {
        id: PersonaId,
        overwritten: bool,
    }

    impl FromRow for TypedRow {
        fn from_row(row: &mut impl Row) -> Self {
            Self {
                id: row.get_id("obj_id"),
                overwritten: row.get_int("overwritten") != 0,
            }
        }
    }

    let row = deps
        .execute_map::<TypedRow>(
            if overwrite_persona_id.0 {
                indoc! {
                    "
                    INSERT INTO obj_foreign_dir_link (dir_key, upd, overwritten, foreign_id, obj_id)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT DO UPDATE SET upd = $2, obj_id = $5, overwritten = 1
                    RETURNING obj_id, overwritten
                    "
                }
            } else {
                indoc! {
                    "
                    INSERT INTO obj_foreign_dir_link (dir_key, upd, overwritten, foreign_id, obj_id)
                    VALUES ($1, $2, $3, $4, $5)
                    ON CONFLICT DO UPDATE SET upd = $2, overwritten = 1
                    RETURNING obj_id, overwritten
                    "
                }
            }
            .into(),
            params!(
                dir_key.0,
                now.unix_timestamp(),
                0,
                foreign_id,
                persona_id.as_param()
            ),
        )
        .await?
        .into_iter()
        .next()
        .unwrap()
        .unwrap();

    Ok((row.id, DidInsert(!row.overwritten)))
}
