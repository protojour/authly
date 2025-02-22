use authly_common::id::PersonaId;
use authly_db::{DbError, DidInsert};
use authly_domain::{ctx::GetDb, directory::DirKey, id::BuiltinProp};
use tracing::info;

use crate::{
    ctx::GetDecryptedDeks,
    db::{
        cryptography_db::EncryptedObjIdent,
        entity_db::{self, OverwritePersonaId},
        object_db,
    },
};

// A persona whose source is a 3rd-party directory (OAuth/LDAP/etc)
pub struct ForeignPersona {
    pub foreign_id: Vec<u8>,
    pub email: String,
}

#[derive(thiserror::Error, Debug)]
pub enum ForeignLinkError {
    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("encryption error: {0}")]
    Encryption(anyhow::Error),

    #[error("other: {0}")]
    Other(&'static str),
}

/// Link or re-link a foreign persona to get an Authly PersonaId
pub async fn link_foreign_persona(
    deps: &(impl GetDb + GetDecryptedDeks),
    persona_dir_key: DirKey,
    foreign: ForeignPersona,
) -> Result<(PersonaId, DidInsert), ForeignLinkError> {
    let email = EncryptedObjIdent::encrypt(
        BuiltinProp::Email.into(),
        &foreign.email,
        &deps.get_decrypted_deks(),
    )
    .map_err(ForeignLinkError::Encryption)?;
    let now = time::OffsetDateTime::now_utc();

    info!("email fingerprint: {}", hexhex::hex(&email.fingerprint));

    // I've tried doing both the "link" and the "email upsert" in the same DB statement,
    // but have given up temporarily.
    // FIXME: Ideally these should be performed in one transaction. If not it will be possible
    // to register/link a persona but then the "set email" can fail.

    // allocate random mapped PersonaId or retrieve the previously mapped one
    let (persona_id, did_insert) = entity_db::upsert_link_foreign_persona(
        deps.get_db(),
        persona_dir_key,
        PersonaId::random(),
        OverwritePersonaId(false),
        foreign.foreign_id.clone(),
        now,
    )
    .await?;

    match email
        .clone()
        .insert(
            deps.get_db(),
            persona_dir_key.0,
            persona_id.upcast(),
            now.unix_timestamp(),
        )
        .await
    {
        Ok(()) => Ok((persona_id, did_insert)),
        Err(db_err) => {
            info!(?db_err, "email constraint violation");

            // two scenarios
            if let Some(obj_id) = object_db::find_obj_id_by_ident_fingerprint(
                deps.get_db(),
                BuiltinProp::Email.into(),
                &email.fingerprint,
            )
            .await?
            {
                // 1. the email already exists for another entity

                let owner_id = PersonaId::try_from(obj_id)
                    .map_err(|_| ForeignLinkError::Other("email address owned by non-persona"))?;

                info!("writing new persona link for {owner_id}");

                // update the old link to the persona owning the email address
                let (persona_id, _) = entity_db::upsert_link_foreign_persona(
                    deps.get_db(),
                    persona_dir_key,
                    owner_id,
                    OverwritePersonaId(true),
                    foreign.foreign_id,
                    now,
                )
                .await?;

                Ok((persona_id, did_insert))
            } else {
                // 2. the persona id already has another email address

                // BUG: the new address should not be written unconditionally,
                // especially if that directory is not the "manager" of the email address.
                email
                    .clone()
                    .upsert(
                        deps.get_db(),
                        persona_dir_key.0,
                        persona_id.upcast(),
                        now.unix_timestamp(),
                    )
                    .await?;

                Ok((persona_id, did_insert))
            }
        }
    }
}
