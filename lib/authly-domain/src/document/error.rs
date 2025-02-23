use std::ops::Range;

use authly_db::DbError;

use crate::policy::error::PolicyCompileErrorKind;

/// DocError includes problems related with the document contents,
/// as well as problems with writing it to the database.
#[derive(Debug)]
pub enum DocError {
    LocalSettingNotFound,
    InvalidSettingValue(String),
    NameDefinedMultipleTimes(Range<usize>, String),
    UnresolvedDomain,
    UnresolvedNamespace,
    UnresolvedEntity,
    UnresolvedProfile,
    UnresolvedGroup,
    UnresolvedService,
    UnresolvedProperty,
    UnresolvedAttribute,
    UnresolvedPolicy,
    MustBeAServiceId,
    PolicyBodyMissing,
    AmbiguousPolicyOutcome,
    MetadataNotSupported,
    Policy(PolicyCompileErrorKind),
    /// Error from transaction:
    ConstraintViolation,
    Db(String),
}

impl From<DbError> for DocError {
    fn from(value: DbError) -> Self {
        Self::Db(value.to_string())
    }
}
