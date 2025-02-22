use authly_common::id::{AttrId, ServiceId};
use authly_db::DbError;
use authly_domain::{ctx::GetDb, id::BuiltinAttr};
use fnv::FnvHashSet;

use crate::db::entity_db;

pub enum SvcAccessControlError {
    Denied,
    Db(DbError),
}

pub struct AuthorizedPeerService {
    pub eid: ServiceId,

    #[expect(unused)]
    pub attributes: FnvHashSet<AttrId>,
}

pub trait AuthlyRole {
    fn role() -> BuiltinAttr;
}

/// Typed roles
pub mod role {
    use authly_domain::id::BuiltinAttr;

    use super::AuthlyRole;

    pub struct ApplyDocument;

    impl AuthlyRole for ApplyDocument {
        fn role() -> BuiltinAttr {
            BuiltinAttr::AuthlyRoleApplyDocument
        }
    }

    pub struct GrantMandate;

    impl AuthlyRole for GrantMandate {
        fn role() -> BuiltinAttr {
            BuiltinAttr::AuthlyRoleGrantMandate
        }
    }
}

pub trait VerifyAuthlyRole {
    fn verify_roles(attributes: &FnvHashSet<AttrId>) -> bool;
}

impl VerifyAuthlyRole for () {
    fn verify_roles(_attributes: &FnvHashSet<AttrId>) -> bool {
        true
    }
}

impl<T: AuthlyRole> VerifyAuthlyRole for T {
    fn verify_roles(attributes: &FnvHashSet<AttrId>) -> bool {
        attributes.contains(&AttrId::from(T::role()))
    }
}

/// Access control the given service trying to perform some Authly action.
///
/// This currently does not use policies, it only checks whether the service is assigned the required attribute.
pub async fn authorize_peer_service(
    deps: &impl GetDb,
    svc_eid: ServiceId,
    required_authly_roles: &[BuiltinAttr],
) -> Result<AuthorizedPeerService, SvcAccessControlError> {
    let attributes = entity_db::list_entity_attrs(deps.get_db(), svc_eid.upcast())
        .await
        .map_err(SvcAccessControlError::Db)?;

    for role in required_authly_roles {
        if !attributes.contains(&AttrId::from(*role)) {
            return Err(SvcAccessControlError::Denied);
        }
    }

    Ok(AuthorizedPeerService {
        eid: svc_eid,
        attributes,
    })
}
