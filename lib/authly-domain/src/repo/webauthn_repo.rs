use authly_common::id::{PersonaId, PropId};
use authly_db::{param::ToBlob, params, Db, DbError, DbResult, TryFromRow};
use indoc::indoc;
use webauthn_rs::prelude::{CredentialID, Passkey};

pub struct PasskeyRow {
    pub eid: PersonaId,
    pub passkey: Passkey,
    pub created: time::OffsetDateTime,
    pub last_used: Option<time::OffsetDateTime>,
}

impl TryFromRow for PasskeyRow {
    type Error = anyhow::Error;

    fn try_from_row(row: &mut impl authly_db::Row) -> Result<Self, Self::Error> {
        Ok(PasskeyRow {
            eid: row.get_id("eid"),
            passkey: serde_json::from_str(&row.get_text("pk_json"))?,
            created: row.get_datetime("created_at")?,
            last_used: row.get_opt_datetime("last_used")?,
        })
    }
}

pub async fn list_passkeys_by_entity_ident(
    deps: &impl Db,
    ident_prop_id: PropId,
    ident_fingerprint: &[u8],
) -> DbResult<Vec<PasskeyRow>> {
    deps.query_filter_map::<PasskeyRow>(
        indoc! {
            "
            SELECT pk.eid, pk.pk_json, pk.created_at, pk.last_used FROM ent_passkey pk
            JOIN obj_ident i ON i.obj_id = pk.eid
            WHERE i.prop_key = (SELECT key FROM prop WHERE id = $1)
                AND i.fingerprint = $2
            ",
        }
        .into(),
        params!(ident_prop_id.to_blob(), ident_fingerprint.to_blob()),
    )
    .await
}

pub async fn list_passkeys_by_entity_id(
    deps: &impl Db,
    eid: PersonaId,
) -> DbResult<Vec<PasskeyRow>> {
    deps.query_filter_map::<PasskeyRow>(
        "SELECT eid, pk_json, created_at, last_used FROM ent_passkey pk WHERE pk.eid = $1".into(),
        params!(eid.to_blob()),
    )
    .await
}

pub async fn insert_passkey(
    deps: &impl Db,
    persona_id: PersonaId,
    passkey: &Passkey,
    now: time::OffsetDateTime,
) -> DbResult<()> {
    deps.execute(
        "INSERT INTO ent_passkey (eid, cred_id, pk_json, created_at, last_used) VALUES ($1, $2, $3, $4, $4)".into(),
        params!(
            persona_id.to_blob(),
            passkey.cred_id().to_vec(),
            serde_json::to_string(passkey)
                .map_err(|err| { DbError::Other(format!("{err:?}").into()) })?,
            now.unix_timestamp()
        ),
    )
    .await?;
    Ok(())
}

pub async fn update_passkey(
    deps: &impl Db,
    persona_id: PersonaId,
    passkey: &Passkey,
    now: time::OffsetDateTime,
) -> DbResult<()> {
    let row_count = deps
        .execute(
            "UPDATE ent_passkey SET pk_json = $1, last_used = $2 WHERE eid = $3 AND cred_id = $4"
                .into(),
            params!(
                serde_json::to_string(passkey)
                    .map_err(|err| { DbError::Other(format!("{err:?}").into()) })?,
                now.unix_timestamp(),
                persona_id.to_blob(),
                passkey.cred_id().to_vec()
            ),
        )
        .await?;

    if row_count != 1 {
        return Err(DbError::Other(
            format!("passkey not updated (row_count = {row_count})").into(),
        ));
    }

    Ok(())
}

pub async fn update_passkey_last_used(
    deps: &impl Db,
    persona_id: PersonaId,
    credential_id: &CredentialID,
    now: time::OffsetDateTime,
) -> DbResult<()> {
    let row_count = deps
        .execute(
            "UPDATE ent_passkey SET last_used = $1 WHERE eid = $2 AND cred_id = $3".into(),
            params!(
                now.unix_timestamp(),
                persona_id.to_blob(),
                credential_id.to_vec()
            ),
        )
        .await?;

    if row_count != 1 {
        return Err(DbError::Other(
            format!("passkey not updated (row_count = {row_count})").into(),
        ));
    }

    Ok(())
}
