use authly_common::id::{AttrId, PropId};
use int_enum::IntEnum;

#[derive(Clone, Copy, Eq, PartialEq, Hash, IntEnum, Debug)]
#[repr(u32)]
pub enum BuiltinEntity {
    /// Entity referring to the local Authly instance
    LocalAuthly = 0,
}

#[derive(Clone, Copy, Eq, PartialEq, Hash, IntEnum, Debug)]
#[repr(u32)]
pub enum BuiltinProp {
    /// The entity property
    Entity = 0,
    /// The built-in authly:role for authly internal access control
    AuthlyRole = 1,
    /// The Authly instance property
    AuthlyInstance = 2,
    /// The username ident property
    Username = 3,
    /// The email ident property
    Email = 4,
    /// The password_hash text property
    PasswordHash = 5,
    /// The kubernetes service account name of a service, as seen documents,
    /// The value format is `{namespace}/{account_name}`.
    /// If namespace is not defined, it will be rendered as `*`
    K8sConfiguredServiceAccount = 6,
    /// A relation property representing "membership" relation
    RelEntityMembership = 7,
    /// The `metadata` property from documents. Stored as a JSON-encoded text property.
    Metadata = 8,
    /// The kubernetes service account actually used by this authly instance.
    /// The namespace will be resolved to authly's namespace if it's a wildcard in configuration.
    K8sLocalServiceAccount = 9,
}

#[expect(clippy::enum_variant_names)]
#[derive(Clone, Copy, Eq, PartialEq, Hash, IntEnum, Debug)]
#[repr(u32)]
pub enum BuiltinAttr {
    /// A service role for getting an access token
    AuthlyRoleGetAccessToken = 0,
    /// A service role for authenticating users
    AuthlyRoleAuthenticate = 1,
    /// A user role for applying documents
    AuthlyRoleApplyDocument = 2,
    /// A user role for granting mandates to authority
    AuthlyRoleGrantMandate = 3,
}

impl From<BuiltinProp> for PropId {
    fn from(value: BuiltinProp) -> PropId {
        PropId::from_uint(value as u128)
    }
}

impl BuiltinProp {
    pub fn iter() -> impl Iterator<Item = Self> {
        (0..u32::MAX)
            .map(Self::try_from)
            .scan((), |_, item| item.ok())
    }

    /// Get an optional label for this builtin ID.
    pub const fn label(self) -> Option<&'static str> {
        match self {
            Self::Entity => Some("entity"),
            Self::AuthlyRole => Some("role"),
            Self::Username => None,
            Self::Email => None,
            Self::PasswordHash => None,
            Self::K8sConfiguredServiceAccount | Self::K8sLocalServiceAccount => None,
            Self::AuthlyInstance => None,
            Self::RelEntityMembership => None,
            Self::Metadata => None,
        }
    }

    pub const fn is_encrypted(self) -> bool {
        match self {
            Self::Entity | Self::AuthlyRole | Self::RelEntityMembership | Self::Metadata => false,
            Self::Username => true,
            Self::Email => true,
            Self::PasswordHash => false,
            Self::K8sConfiguredServiceAccount | Self::K8sLocalServiceAccount => true,
            Self::AuthlyInstance => true,
        }
    }

    pub const fn attributes(self) -> &'static [BuiltinAttr] {
        match self {
            Self::AuthlyRole => &[
                BuiltinAttr::AuthlyRoleGetAccessToken,
                BuiltinAttr::AuthlyRoleAuthenticate,
                BuiltinAttr::AuthlyRoleApplyDocument,
                BuiltinAttr::AuthlyRoleGrantMandate,
            ],
            _ => &[],
        }
    }
}

impl From<BuiltinAttr> for AttrId {
    fn from(value: BuiltinAttr) -> AttrId {
        AttrId::from_uint(value as u128)
    }
}

impl BuiltinAttr {
    pub const fn label(self) -> Option<&'static str> {
        match self {
            Self::AuthlyRoleGetAccessToken => Some("get_access_token"),
            Self::AuthlyRoleAuthenticate => Some("authenticate"),
            Self::AuthlyRoleApplyDocument => Some("apply_document"),
            Self::AuthlyRoleGrantMandate => Some("grant_mandate"),
        }
    }
}
