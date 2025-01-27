//! An access token represents a verified user of services.
//!
//! Authly itself is such a service.
//!
//! The access token is implemented as a JSON Web Token.
//! The access token is used directly when doing access control.
//!

use authly_common::{
    access_token::{Authly, AuthlyAccessTokenClaims},
    id::ObjId,
};
use axum::RequestPartsExt;
use axum_extra::{
    headers::{authorization::Bearer, Authorization},
    TypedHeader,
};
use fnv::FnvHashSet;
use http::{request::Parts, StatusCode};

use crate::{instance::AuthlyInstance, session::Session, AuthlyCtx};

const EXPIRATION: time::Duration = time::Duration::days(365);

#[derive(Debug)]
pub enum AccessTokenError {
    EncodeError,

    Unverified(anyhow::Error),
}

/// An access token is created from scratch every time.
///
/// This is likely to be pretty "hot", request wise, consider caching the JWT in memory based on the session token.
/// There's a benchmark for it which reveals it runs in about 30 µs on my development machine.
pub fn create_access_token(
    session: &Session,
    user_attributes: FnvHashSet<ObjId>,
    instance: &AuthlyInstance,
) -> Result<String, AccessTokenError> {
    let jwt_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    let now = time::OffsetDateTime::now_utc();
    let expiration = now + EXPIRATION;

    let claims = AuthlyAccessTokenClaims {
        iat: now.unix_timestamp(),
        exp: expiration.unix_timestamp(),
        authly: Authly {
            entity_id: session.eid,
            entity_attributes: user_attributes,
        },
    };

    jsonwebtoken::encode(&jwt_header, &claims, &instance.local_jwt_encoding_key())
        .map_err(|_| AccessTokenError::EncodeError)
}

pub fn verify_access_token(
    access_token: &str,
    instance: &AuthlyInstance,
) -> Result<AuthlyAccessTokenClaims, AccessTokenError> {
    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    let token_data = jsonwebtoken::decode::<AuthlyAccessTokenClaims>(
        access_token,
        instance.local_jwt_decoding_key(),
        &validation,
    )
    .map_err(|err| AccessTokenError::Unverified(err.into()))?;

    Ok(token_data.claims)
}

/// Axum extension for verified access token
pub struct VerifiedAccessToken {
    pub claims: AuthlyAccessTokenClaims,
}

#[axum::async_trait]
impl axum::extract::FromRequestParts<AuthlyCtx> for VerifiedAccessToken {
    type Rejection = (StatusCode, &'static str);

    /// Perform the extraction.
    async fn from_request_parts(
        parts: &mut Parts,
        ctx: &AuthlyCtx,
    ) -> Result<Self, Self::Rejection> {
        let authorization = parts
            .extract::<TypedHeader<Authorization<Bearer>>>()
            .await
            .map_err(|_| (StatusCode::UNAUTHORIZED, "no access token"))?;

        let claims = verify_access_token(authorization.token(), &ctx.instance)
            .map_err(|_| (StatusCode::UNAUTHORIZED, "invalid access token"))?;

        Ok(Self { claims })
    }
}
