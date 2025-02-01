use authly_common::id::{Id128, ObjId};
use int_enum::IntEnum;

/// Builtin Object IDs
#[derive(Clone, Copy, Eq, PartialEq, Hash, IntEnum, Debug)]
#[repr(u32)]
pub enum BuiltinID {
    /// Id representing Authly itself
    Authly = 0,
    /// The entity property
    PropEntity = 1,
    /// The built-in authly:role for authly internal access control
    PropAuthlyRole = 2,
    /// A service role for getting an access token
    AttrAuthlyRoleGetAccessToken = 3,
    /// A service role for authenticating users
    AttrAuthlyRoleAuthenticate = 4,
    /// A user role for applying documents
    AttrAuthlyRoleApplyDocument = 5,
    /// The entity membership relation
    RelEntityMembership = 6,
    /// The username ident property
    PropUsername = 7,
    /// The email ident property
    PropEmail = 8,
    /// The password_hash text property
    PropPasswordHash = 9,
    /// The label text property
    PropLabel = 10,
    /// The kubernetes service account name property.
    /// The value format is `{namespace}/{account_name}`.
    PropK8sServiceAccount = 11,
    /// The Authly instance property
    PropAuthlyInstance = 12,
    /// A user role for granting mandates to authority
    AttrAuthlyRoleGrantMandate = 13,
}

impl BuiltinID {
    /// Convert to an [ObjId].
    pub const fn to_obj_id(self) -> ObjId {
        Id128::from_uint(self as u128)
    }

    pub fn iter() -> impl Iterator<Item = Self> {
        (0..u32::MAX)
            .map(Self::try_from)
            .scan((), |_, item| item.ok())
    }

    /// Get an optional label for this builtin ID.
    pub const fn label(self) -> Option<&'static str> {
        match self {
            Self::Authly => None,
            Self::PropEntity => Some("entity"),
            Self::PropAuthlyRole => Some("role"),
            Self::AttrAuthlyRoleGetAccessToken => Some("get_access_token"),
            Self::AttrAuthlyRoleAuthenticate => Some("authenticate"),
            Self::AttrAuthlyRoleApplyDocument => Some("apply_document"),
            Self::PropUsername => None,
            Self::PropEmail => None,
            Self::RelEntityMembership => None,
            Self::PropPasswordHash => None,
            Self::PropLabel => None,
            Self::PropK8sServiceAccount => None,
            Self::PropAuthlyInstance => None,
            Self::AttrAuthlyRoleGrantMandate => Some("grant_mandate"),
        }
    }

    /// Whether the property is encrypted
    pub const fn is_encrypted_prop(self) -> bool {
        match self {
            Self::Authly
            | Self::PropEntity
            | Self::PropAuthlyRole
            | Self::AttrAuthlyRoleGetAccessToken
            | Self::AttrAuthlyRoleAuthenticate
            | Self::AttrAuthlyRoleApplyDocument
            | Self::AttrAuthlyRoleGrantMandate
            | Self::RelEntityMembership => false,
            Self::PropUsername => true,
            Self::PropEmail => true,
            Self::PropPasswordHash => true,
            Self::PropLabel => false,
            Self::PropK8sServiceAccount => true,
            Self::PropAuthlyInstance => true,
        }
    }

    /// List attributes for an ID, in case it represents a builtin-in property.
    pub const fn attributes(self) -> &'static [BuiltinID] {
        match self {
            Self::PropAuthlyRole => &[
                Self::AttrAuthlyRoleGetAccessToken,
                Self::AttrAuthlyRoleAuthenticate,
                Self::AttrAuthlyRoleApplyDocument,
                Self::AttrAuthlyRoleGrantMandate,
            ],
            _ => &[],
        }
    }
}
