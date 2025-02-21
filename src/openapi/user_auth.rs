use authly_common::{id::PersonaId, mtls_server::PeerServiceEntity};
use axum::{extract::State, http::StatusCode, response::IntoResponse, Extension, Json};
use axum_extra::extract::CookieJar;
use serde::{Deserialize, Serialize};
use tracing::warn;

use crate::{
    login::{try_username_password_login, LoginError},
    AuthlyCtx,
};

pub struct AuthError(LoginError);

impl From<LoginError> for AuthError {
    fn from(value: LoginError) -> Self {
        Self(value)
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> axum::response::Response {
        match self.0 {
            LoginError::UnprivilegedService => StatusCode::FORBIDDEN.into_response(),
            LoginError::Credentials => StatusCode::UNAUTHORIZED.into_response(),
            LoginError::Db(err) => {
                warn!(?err, "auth db error");
                StatusCode::UNAUTHORIZED.into_response()
            }
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
    Extension(peer_svc): Extension<PeerServiceEntity>,
    Json(body): Json<AuthenticateRequest>,
) -> Result<axum::response::Response, AuthError> {
    // BUG: figure this out:
    let _mfa_needed = false;
    // TODO: directory selection?

    let (persona_id, session) = match body {
        AuthenticateRequest::User { username, password } => {
            try_username_password_login(&ctx, peer_svc, username, password).await?
        }
    };

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
