pub struct AccessToken {
    /// The access token in JWT format
    pub token: String,

    /// The user that the access token represents
    pub user_eid: String,
}
