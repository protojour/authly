use fnv::FnvHashSet;
use serde::{Deserialize, Serialize};

use crate::id::{Eid, ObjId};

/// Claims for the Authly Access Token JWT
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthlyAccessTokenClaims {
    /// Issued at.
    ///
    /// Authly may publish a Reset event which invalidates all tokens issued in the past.
    pub iat: i64,

    /// Expiration time
    pub exp: i64,

    /// Authy claims
    pub authly: Authly,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Authly {
    pub user_eid: Eid,

    pub attributes: FnvHashSet<ObjId>,
}
