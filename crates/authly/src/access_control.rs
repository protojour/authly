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

    #[expect(unused)]
    pub attributes: FnvHashSet<ObjId>,
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
