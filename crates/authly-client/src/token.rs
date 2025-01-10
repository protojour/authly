use authly_common::access_token::AuthlyAccessTokenClaims;

pub struct AccessToken {
    /// The access token in JWT format
    pub token: String,

    /// The decoded/verified token claims
    pub claims: AuthlyAccessTokenClaims,
}
