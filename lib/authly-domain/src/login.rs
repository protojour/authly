//! traditional username/password login

use argon2::Argon2;
use authly_common::{id::PersonaId, mtls_server::PeerServiceEntity};
use authly_db::DbError;
use tracing::warn;

use crate::{
    access_control::{authorize_peer_service, SvcAccessControlError},
    ctx::{GetBuiltins, GetDb, GetDecryptedDeks},
    dev::IsDev,
    id::{BuiltinAttr, BuiltinProp},
    repo::entity_repo::{self, EntityPasswordHash},
    session::{init_session, Session},
};

pub enum LoginError {
    UnprivilegedService,
    Credentials,
    Db(DbError),
}

impl From<DbError> for LoginError {
    fn from(value: DbError) -> Self {
        Self::Db(value)
    }
}

impl From<SvcAccessControlError> for LoginError {
    fn from(value: SvcAccessControlError) -> Self {
        match value {
            SvcAccessControlError::Denied => Self::UnprivilegedService,
            SvcAccessControlError::Db(db_error) => Self::Db(db_error),
        }
    }
}

#[derive(Default)]
pub struct LoginOptions {
    disable_peer_service_auth: bool,
}

impl LoginOptions {
    pub fn dev(mut self, is_dev: IsDev) -> Self {
        if is_dev.0 {
            self.disable_peer_service_auth = true;
        }
        self
    }
}

pub async fn try_username_password_login(
    deps: &(impl GetDb + GetBuiltins + GetDecryptedDeks),
    PeerServiceEntity(peer_svc_eid): PeerServiceEntity,
    username: String,
    password: String,
    options: LoginOptions,
) -> Result<(PersonaId, Session), LoginError> {
    if !options.disable_peer_service_auth {
        authorize_peer_service(deps, peer_svc_eid, &[BuiltinAttr::AuthlyRoleAuthenticate]).await?;
    }

    let ident_fingerprint = {
        let deks = deps.get_decrypted_deks();
        let dek = deks.get(BuiltinProp::Username.into()).unwrap();

        dek.fingerprint(username.as_bytes())
    };

    let ehash = entity_repo::find_local_directory_entity_password_hash_by_entity_ident(
        deps.get_db(),
        BuiltinProp::Username.into(),
        &ident_fingerprint,
        deps.get_builtins(),
    )
    .await?
    .ok_or_else(|| LoginError::Credentials)?;

    let persona_id = verify_secret(ehash, password).await?;
    let session = init_session(deps, persona_id.upcast()).await?;

    Ok((persona_id, session))
}

async fn verify_secret(ehash: EntityPasswordHash, secret: String) -> Result<PersonaId, LoginError> {
    // check Argon2 hash
    tokio::task::spawn_blocking(move || -> Result<(), LoginError> {
        use argon2::password_hash::PasswordHash;
        let hash = PasswordHash::new(&ehash.secret_hash).map_err(|err| {
            warn!(?err, "invalid secret hash");
            LoginError::Credentials
        })?;

        hash.verify_password(&[&Argon2::default()], secret)
            .map_err(|err| match err {
                argon2::password_hash::Error::Password => LoginError::Credentials,
                _ => {
                    warn!(?err, "failed to verify secret hash");
                    LoginError::Credentials
                }
            })
    })
    .await
    .map_err(|err| {
        warn!(?err, "failed to join");
        LoginError::Credentials
    })??;

    Ok(ehash.eid)
}
