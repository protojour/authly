use argon2::Argon2;
use authly_domain::BuiltinID;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use axum_extra::extract::{
    cookie::{Cookie, Expiration, SameSite},
    CookieJar,
};
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    access_control::{svc_access_control, SvcAccessControlError},
    db::{
        entity_db::{self, EntityPasswordHash},
        session_db, DbError,
    },
    mtls::PeerServiceEID,
    session::{Session, SessionToken, SESSION_TTL},
    AuthlyCtx, Eid,
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
                StatusCode::INTERNAL_SERVER_ERROR.into_response()
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
    entity_id: u128,
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
    Extension(PeerServiceEID(peer_svc_eid)): Extension<PeerServiceEID>,
    Json(body): Json<AuthenticateRequest>,
) -> Result<axum::response::Response, AuthError> {
    svc_access_control(peer_svc_eid, &[BuiltinID::AttrAuthlyRoleAuthenticate], &ctx).await?;

    // BUG: figure this out:
    let _mfa_needed = false;
    // TODO: authority selection?

    let (ehash, secret) = match body {
        AuthenticateRequest::User { username, password } => {
            let ehash = entity_db::find_local_authority_entity_password_hash_by_credential_ident(
                &ctx, "username", &username,
            )
            .await?
            .ok_or_else(|| AuthError::UserAuthFailed)?;
            (ehash, password)
        }
    };

    let eid = verify_secret(ehash, secret).await?;

    let session = init_session(eid, &ctx).await?;

    Ok((
        CookieJar::new().add(make_session_cookie(&session)),
        Json(AuthenticateResponse {
            token: session.token.0,
            entity_id: eid.0,
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

async fn init_session(eid: Eid, ctx: &AuthlyCtx) -> Result<Session, AuthError> {
    let session = Session {
        token: SessionToken::new_random(),
        eid,
        expires_at: time::OffsetDateTime::now_utc() + SESSION_TTL,
    };

    session_db::store_session(ctx, &session).await?;

    Ok(session)
}

fn make_session_cookie(session: &Session) -> Cookie<'static> {
    let mut cookie = Cookie::new(
        "session-cookie",
        format!("{}", hexhex::hex(&session.token.0)),
    );
    cookie.set_path("/");
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie.set_expires(Expiration::DateTime(session.expires_at));
    cookie.set_same_site(SameSite::Strict);
    cookie
}

async fn verify_secret(ehash: EntityPasswordHash, secret: String) -> Result<Eid, AuthError> {
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
