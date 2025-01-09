use authly_domain::{BuiltinID, EID};

use crate::{
    db::{entity_db, DbError},
    AuthlyCtx,
};

pub enum SvcAccessControlError {
    Denied,
    Db(DbError),
}

/// Access control the given service trying to perform some Authly action.
///
/// This currently does not use policies, it only checks whether the service is assigned the required attribute.
pub async fn svc_access_control(
    svc_eid: EID,
    required_authly_roles: &[BuiltinID],
    ctx: &AuthlyCtx,
) -> Result<(), SvcAccessControlError> {
    if required_authly_roles.is_empty() {
        return Ok(());
    }

    let attributes = entity_db::list_entity_attrs(svc_eid, ctx)
        .await
        .map_err(SvcAccessControlError::Db)?;

    for role in required_authly_roles {
        if !attributes.contains(&role.to_eid()) {
            return Err(SvcAccessControlError::Denied);
        }
    }

    Ok(())
}
