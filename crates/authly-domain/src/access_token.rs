use serde::{Deserialize, Serialize};

use crate::Eid;

/// Claims for the Authly Access Token JWT
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthlyAccessTokenClaims {
    pub authly: Authly,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Authly {
    pub user_eid: Eid,
}
