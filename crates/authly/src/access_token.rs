use authly_common::{
    access_token::{Authly, AuthlyAccessTokenClaims},
    ObjId,
};
use fnv::FnvHashSet;

use crate::{session::Session, DynamicConfig};

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
    dynamic_config: &DynamicConfig,
) -> Result<String, AccessTokenError> {
    let jwt_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    let now = time::OffsetDateTime::now_utc();
    let expiration = time::OffsetDateTime::now_utc() + EXPIRATION;

    let claims = AuthlyAccessTokenClaims {
        iat: now.unix_timestamp(),
        exp: expiration.unix_timestamp(),
        authly: Authly {
            user_eid: session.eid,
            attributes: user_attributes,
        },
    };
    let encoding_key =
        jsonwebtoken::EncodingKey::from_ec_der(dynamic_config.local_ca.key.serialized_der());

    jsonwebtoken::encode(&jwt_header, &claims, &encoding_key)
        .map_err(|_| AccessTokenError::EncodeError)
}

pub fn verify_access_token(
    access_token: &str,
    dynamic_config: &DynamicConfig,
) -> Result<AuthlyAccessTokenClaims, AccessTokenError> {
    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    let token_data = jsonwebtoken::decode::<AuthlyAccessTokenClaims>(
        access_token,
        &dynamic_config.jwt_decoding_key,
        &validation,
    )
    .map_err(|err| AccessTokenError::Unverified(err.into()))?;

    Ok(token_data.claims)
}
