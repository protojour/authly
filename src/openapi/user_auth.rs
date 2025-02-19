use argon2::Argon2;
use authly_common::{id::PersonaId, mtls_server::PeerServiceEntity};
use authly_db::DbError;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    access_control::{authorize_peer_service, SvcAccessControlError},
    ctx::GetDb,
    db::entity_db::{self, EntityPasswordHash},
    id::{BuiltinAttr, BuiltinProp},
    session::init_session,
    AuthlyCtx,
};

pub enum AuthError {
    UnprivilegedService,
    UserAuthFailed,
    Db(DbError),
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::UnprivilegedService => StatusCode::FORBIDDEN.into_response(),
            Self::UserAuthFailed => StatusCode::UNAUTHORIZED.into_response(),
            Self::Db(err) => {
                warn!(?err, "auth db error");
                StatusCode::UNAUTHORIZED.into_response()
            }
        }
    }
}

impl From<DbError> for AuthError {
    fn from(err: DbError) -> Self {
        Self::Db(err)
    }
}

impl From<SvcAccessControlError> for AuthError {
    fn from(value: SvcAccessControlError) -> Self {
        match value {
            SvcAccessControlError::Denied => Self::UnprivilegedService,
            SvcAccessControlError::Db(db_error) => Self::Db(db_error),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum AuthenticateRequest {
    #[serde(rename_all = "camelCase")]
    User { username: String, password: String },
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthenticateResponse {
    token: Vec<u8>,
    entity_id: PersonaId,
    authenticated: bool,
    mfa_needed: u64,
    mfa_done: Vec<String>,
    authenticate_url: String,
    authenticator_url: String,
    hotp_validate_next: u64,
    #[serde(with = "time::serde::rfc3339")]
    expires: time::OffsetDateTime,
}

pub async fn authenticate(
    State(ctx): State<AuthlyCtx>,
    Extension(PeerServiceEntity(peer_svc_eid)): Extension<PeerServiceEntity>,
    Json(body): Json<AuthenticateRequest>,
) -> Result<axum::response::Response, AuthError> {
    authorize_peer_service(&ctx, peer_svc_eid, &[BuiltinAttr::AuthlyRoleAuthenticate]).await?;

    // BUG: figure this out:
    let _mfa_needed = false;
    // TODO: directory selection?

    let (ehash, secret) = match body {
        AuthenticateRequest::User { username, password } => {
            let prop_id = BuiltinProp::Username.into();

            let ident_fingerprint = {
                let deks = ctx.deks.load_full();
                let dek = deks.get(prop_id).unwrap();

                dek.fingerprint(username.as_bytes())
            };

            let ehash = entity_db::find_local_directory_entity_password_hash_by_entity_ident(
                ctx.get_db(),
                BuiltinProp::Username.into(),
                &ident_fingerprint,
            )
            .await?
            .ok_or_else(|| AuthError::UserAuthFailed)?;
            (ehash, password)
        }
    };

    let persona_id = verify_secret(ehash, secret).await?;
    let session = init_session(&ctx, persona_id.upcast()).await?;

    Ok((
        CookieJar::new().add(session.to_cookie()),
        Json(AuthenticateResponse {
            token: session.token.0,
            entity_id: persona_id,
            authenticated: true,
            mfa_needed: 0,
            mfa_done: vec![],
            authenticate_url: "".to_string(),
            authenticator_url: "".to_string(),
            hotp_validate_next: 0,
            expires: session.expires_at,
        }),
    )
        .into_response())
}

async fn verify_secret(ehash: EntityPasswordHash, secret: String) -> Result<PersonaId, AuthError> {
    // check Argon2 hash
    tokio::task::spawn_blocking(move || -> Result<(), AuthError> {
        use argon2::password_hash::PasswordHash;
        let hash = PasswordHash::new(&ehash.secret_hash).map_err(|err| {
            warn!(?err, "invalid secret hash");
            AuthError::UserAuthFailed
        })?;

        hash.verify_password(&[&Argon2::default()], secret)
            .map_err(|err| match err {
                argon2::password_hash::Error::Password => AuthError::UserAuthFailed,
                _ => {
                    warn!(?err, "failed to verify secret hash");
                    AuthError::UserAuthFailed
                }
            })
    })
    .await
    .map_err(|err| {
        warn!(?err, "failed to join");
        AuthError::UserAuthFailed
    })??;

    Ok(ehash.eid)
}
