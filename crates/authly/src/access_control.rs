use authly_common::{BuiltinID, Eid, ObjId};
use fnv::FnvHashSet;

use crate::{
    db::{entity_db, DbError},
    AuthlyCtx,
};

pub enum SvcAccessControlError {
    Denied,
    Db(DbError),
}

pub struct AuthorizedPeerService {
    pub eid: Eid,

    pub attributes: FnvHashSet<ObjId>,
}

pub trait AuthlyRole {
    fn role() -> BuiltinID;
}

/// Typed roles
pub mod role {
    use authly_common::BuiltinID;

    use super::AuthlyRole;

    pub struct ApplyDocument;

    impl AuthlyRole for ApplyDocument {
        fn role() -> BuiltinID {
            BuiltinID::AttrAuthlyRoleApplyDocument
        }
    }
}

pub trait VerifyAuthlyRole {
    fn verify_roles(attributes: &FnvHashSet<ObjId>) -> bool;
}

impl VerifyAuthlyRole for () {
    fn verify_roles(_attributes: &FnvHashSet<ObjId>) -> bool {
        true
    }
}

impl<T: AuthlyRole> VerifyAuthlyRole for T {
    fn verify_roles(attributes: &FnvHashSet<ObjId>) -> bool {
        attributes.contains(&T::role().to_obj_id())
    }
}

/// Access control the given service trying to perform some Authly action.
///
/// This currently does not use policies, it only checks whether the service is assigned the required attribute.
pub async fn authorize_peer_service(
    svc_eid: Eid,
    required_authly_roles: &[BuiltinID],
    ctx: &AuthlyCtx,
) -> Result<AuthorizedPeerService, SvcAccessControlError> {
    let attributes = entity_db::list_entity_attrs(ctx, svc_eid)
        .await
        .map_err(SvcAccessControlError::Db)?;

    for role in required_authly_roles {
        if !attributes.contains(&role.to_obj_id()) {
            return Err(SvcAccessControlError::Denied);
        }
    }

    Ok(AuthorizedPeerService {
        eid: svc_eid,
        attributes,
    })
}
