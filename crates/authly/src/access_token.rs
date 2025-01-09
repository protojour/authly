use authly_domain::access_token::{Authly, AuthlyAccessTokenClaims};

use crate::{session::Session, AuthlyCtx};

const EXPIRATION: time::Duration = time::Duration::days(365);

pub enum AccessTokenError {
    EncodeError,
}

/// An access token is created from scratch every time.
///
/// This is likely to be pretty hot, consider caching the JWT in memory based on the session token.
pub fn create_access_token(session: &Session, ctx: &AuthlyCtx) -> Result<String, AccessTokenError> {
    let jwt_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    let expiration = time::OffsetDateTime::now_utc() + EXPIRATION;

    let claims = AuthlyAccessTokenClaims {
        exp: expiration.unix_timestamp(),
        authly: Authly {
            user_eid: session.eid,
        },
    };
    let encoding_key =
        jsonwebtoken::EncodingKey::from_ec_der(ctx.dynamic_config.local_ca.key.serialized_der());

    jsonwebtoken::encode(&jwt_header, &claims, &encoding_key)
        .map_err(|_| AccessTokenError::EncodeError)
}
