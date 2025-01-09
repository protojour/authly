use authly_domain::access_token::{Authly, AuthlyAccessTokenClaims};

use crate::{session::Session, AuthlyCtx};

pub enum AccessTokenError {
    EncodeError,
}

pub fn create_access_token(session: &Session, ctx: &AuthlyCtx) -> Result<String, AccessTokenError> {
    let jwt_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    let claims = AuthlyAccessTokenClaims {
        authly: Authly {
            user_eid: session.eid,
        },
    };
    let encoding_key =
        jsonwebtoken::EncodingKey::from_ec_der(ctx.dynamic_config.local_ca.key.serialized_der());

    jsonwebtoken::encode(&jwt_header, &claims, &encoding_key)
        .map_err(|_| AccessTokenError::EncodeError)
}
