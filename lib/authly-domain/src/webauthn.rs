use authly_common::id::PersonaId;
use authly_db::DbError;
use hexhex::Hex;
use http::Uri;
use thiserror::Error;
use time::Duration;
use tracing::info;
use uuid::Uuid;
pub use webauthn_rs::prelude::{
    CreationChallengeResponse, Passkey, PasskeyAuthentication, PasskeyRegistration,
    PublicKeyCredential, RegisterPublicKeyCredential, RequestChallengeResponse, Webauthn,
    WebauthnBuilder,
};

use crate::{
    ctx::{GetDb, GetDecryptedDeks, WebAuthn},
    encryption::CryptoError,
    id::BuiltinProp,
    repo::{crypto_repo, webauthn_repo},
    session::{init_session, Session},
};

#[derive(Error, Debug)]
pub enum WebauthnError {
    #[error("Webauthn not supported")]
    NotSupported,
    #[error("NoSession")]
    NoSession,
    /// NB: This should not be directly exposed in the Auth UI
    #[error("Username not found")]
    UsernameNotFound,
    #[error("db")]
    Db(#[from] DbError),
    #[error("webauthn")]
    Webauthn(#[from] webauthn_rs::prelude::WebauthnError),
    #[error("cryptography")]
    Crypto(#[from] CryptoError),
}

pub async fn webauthn_start_registration(
    deps: &(impl GetDb + WebAuthn + GetDecryptedDeks),
    public_uri: &Uri,
    persona_id: PersonaId,
    session_ttl: Duration,
) -> Result<CreationChallengeResponse, WebauthnError> {
    let uuid = Uuid::from_bytes(persona_id.to_raw_array());
    let already_registered_credentials = vec![];

    let deks = deps.load_decrypted_deks();
    let username = crypto_repo::load_decrypt_obj_ident(
        deps.get_db(),
        persona_id.upcast(),
        BuiltinProp::Username.into(),
        &deks,
    )
    .await?
    .ok_or_else(|| WebauthnError::UsernameNotFound)?;

    let (challenge_response, passkey_registration) =
        deps.get_webauthn(public_uri)?.start_passkey_registration(
            uuid,
            &username,
            &username,
            Some(already_registered_credentials),
        )?;

    deps.cache_passkey_registration(persona_id, passkey_registration, session_ttl)
        .await;

    Ok(challenge_response)
}

pub async fn webauthn_finish_registration(
    deps: &(impl GetDb + WebAuthn),
    public_uri: &Uri,
    persona_id: PersonaId,
    body: RegisterPublicKeyCredential,
) -> Result<(), WebauthnError> {
    let Some(passkey_registration) = deps.yank_passkey_registration(persona_id).await else {
        return Err(WebauthnError::NoSession);
    };

    let passkey = deps
        .get_webauthn(public_uri)?
        .finish_passkey_registration(&body, &passkey_registration)?;

    webauthn_repo::insert_passkey(
        deps.get_db(),
        persona_id,
        &passkey,
        time::OffsetDateTime::now_utc(),
    )
    .await?;

    Ok(())
}

pub async fn webauthn_start_authentication(
    deps: &(impl GetDb + WebAuthn + GetDecryptedDeks),
    public_uri: &Uri,
    login_session_id: Uuid,
    username: &str,
    session_ttl: Duration,
) -> Result<RequestChallengeResponse, WebauthnError> {
    let ident_fingerprint = {
        let deks = deps.get_decrypted_deks();
        let dek = deks.get(BuiltinProp::Username.into()).unwrap();

        dek.fingerprint(username.as_bytes())
    };

    let passkey_rows = webauthn_repo::list_passkeys_by_entity_ident(
        deps.get_db(),
        BuiltinProp::Username.into(),
        &ident_fingerprint,
    )
    .await?;

    let eid = passkey_rows.first().map(|row| row.eid);
    let passkeys: Vec<Passkey> = passkey_rows.into_iter().map(|row| row.passkey).collect();

    let (challenge_response, passkey_authentication) = deps
        .get_webauthn(public_uri)?
        .start_passkey_authentication(&passkeys)?;

    // If there were any passkeys for the user, store the authentication session in the cache.
    // This helps concealing internal state when the username is not associated with any passkeys..
    if let Some(persona_id) = eid {
        deps.cache_passkey_authentication(
            login_session_id,
            (persona_id, passkey_authentication),
            session_ttl,
        )
        .await;
    }

    Ok(challenge_response)
}

pub async fn webauthn_finish_authentication(
    deps: &(impl GetDb + WebAuthn),
    public_uri: &Uri,
    login_session_id: Uuid,
    credential: PublicKeyCredential,
) -> Result<(PersonaId, Session), WebauthnError> {
    let Some((persona_id, passkey_authentication)) =
        deps.yank_passkey_authentication(login_session_id).await
    else {
        return Err(WebauthnError::NoSession);
    };

    let auth_result = deps
        .get_webauthn(public_uri)?
        .finish_passkey_authentication(&credential, &passkey_authentication)?;

    for mut row in webauthn_repo::list_passkeys_by_entity_id(deps.get_db(), persona_id).await? {
        match row.passkey.update_credential(&auth_result) {
            Some(true) => {
                info!(
                    "auth successful, updating passkey {}",
                    Hex::new(row.passkey.cred_id())
                );
                webauthn_repo::update_passkey(
                    deps.get_db(),
                    persona_id,
                    &row.passkey,
                    time::OffsetDateTime::now_utc(),
                )
                .await?;
            }
            Some(false) => {
                info!(
                    "auth successful, updating passkey last_used {}",
                    Hex::new(row.passkey.cred_id())
                );
                webauthn_repo::update_passkey_last_used(
                    deps.get_db(),
                    persona_id,
                    row.passkey.cred_id(),
                    time::OffsetDateTime::now_utc(),
                )
                .await?;
            }
            None => {}
        }
    }

    let session = init_session(deps, persona_id.upcast()).await?;

    Ok((persona_id, session))
}
