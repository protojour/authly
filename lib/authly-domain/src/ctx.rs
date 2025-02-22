use authly_db::Db;

use crate::builtins::Builtins;

/// Trait for getting the "database".
///
/// This trait can be used with in "entrait-pattern" style dependency injection.
pub trait GetDb {
    type Db: Db;

    fn get_db(&self) -> &Self::Db;
}

pub trait GetBuiltins {
    fn get_builtins(&self) -> &Builtins;
}
