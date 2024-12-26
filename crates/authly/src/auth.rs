use std::time::Duration;

use argon2::Argon2;
use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_extra::extract::{
    cookie::{Cookie, Expiration, SameSite},
    CookieJar,
};
use hiqlite::{params, Param};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{AuthlyCtx, EID};

pub enum AuthError {
    AuthFailed,
    Internal,
}

const TOKEN_WIDTH: usize = 20;
const SESSION_TTL: Duration = Duration::from_secs(60 * 60);

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::AuthFailed => StatusCode::UNAUTHORIZED.into_response(),
            Self::Internal => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        }
    }
}

#[derive(Deserialize)]
#[serde(untagged, rename_all = "camelCase")]
pub enum AuthenticateRequest {
    Service {
        service_name: String,
        service_secret: String,
    },
    User {
        username: String,
        password: String,
    },
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
    Json(body): Json<AuthenticateRequest>,
) -> Result<axum::response::Response, AuthError> {
    // BUG: figure this out:
    let mfa_needed = false;
    // TODO: authority selection?

    let eid: EID = match body {
        AuthenticateRequest::Service {
            service_name,
            service_secret,
        } => todo!(),
        AuthenticateRequest::User { username, password } => {
            check_local_authority_user_credentials(username, password, &ctx).await?
        }
    };

    let (token, expires_at) = init_session(eid, &ctx).await?;

    Ok((
        CookieJar::new().add(make_session_cookie(&token, expires_at)),
        Json(AuthenticateResponse {
            token: token.0,
            entity_id: eid.0,
            authenticated: true,
            mfa_needed: 0,
            mfa_done: vec![],
            authenticate_url: "".to_string(),
            authenticator_url: "".to_string(),
            hotp_validate_next: 0,
            expires: expires_at,
        }),
    )
        .into_response())
}

async fn init_session(
    eid: EID,
    ctx: &AuthlyCtx,
) -> Result<(Token, time::OffsetDateTime), AuthError> {
    let token = Token::new_random();
    let expires_at = time::OffsetDateTime::now_utc() + SESSION_TTL;

    ctx.db
        .execute(
            "INSERT INTO session (token, eid, expires_at) VALUES ($1, $2, $3)",
            params!(token.0.clone(), eid.as_param(), expires_at.unix_timestamp()),
        )
        .await
        .map_err(|_| AuthError::AuthFailed)?;

    Ok((token, expires_at))
}

fn make_session_cookie(token: &Token, expires_at: time::OffsetDateTime) -> Cookie<'static> {
    let mut cookie = Cookie::new("session-cookie", hex::encode(&token.0));
    cookie.set_path("/");
    cookie.set_secure(true);
    cookie.set_http_only(true);
    cookie.set_expires(Expiration::DateTime(expires_at));
    cookie.set_same_site(SameSite::Strict);
    cookie
}

async fn check_local_authority_user_credentials(
    username: String,
    password: String,
    ctx: &AuthlyCtx,
) -> Result<EID, AuthError> {
    let (eid, password_hash): (EID, String) = {
        let mut row = ctx
            .db
            .query_raw(
                "SELECT eid, password_hash FROM user_auth WHERE username = $1",
                params!(username),
            )
            .await
            .map_err(|err| {
                warn!(?err, "failed to lookup user");
                AuthError::AuthFailed
            })?
            .into_iter()
            .next()
            .ok_or(AuthError::AuthFailed)?;

        (EID::from_row(&mut row, "eid"), row.get("password_hash"))
    };

    // check Argon2 hash
    tokio::task::spawn_blocking(move || -> Result<(), AuthError> {
        use argon2::password_hash::PasswordHash;
        let hash = PasswordHash::new(&password_hash).map_err(|err| {
            warn!(?err, "invalid password hash");
            AuthError::AuthFailed
        })?;

        hash.verify_password(&[&Argon2::default()], password)
            .map_err(|err| match err {
                argon2::password_hash::Error::Password => AuthError::AuthFailed,
                _ => {
                    warn!(?err, "failed to verify password hash");
                    AuthError::AuthFailed
                }
            })
    })
    .await
    .map_err(|err| {
        warn!(?err, "failed to join");
        AuthError::AuthFailed
    })??;

    Ok(eid)
}

struct Token(Vec<u8>);

impl Token {
    fn new_random() -> Self {
        Self(rand::thread_rng().gen::<[u8; TOKEN_WIDTH]>().to_vec())
    }
}
