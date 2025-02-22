use authly_db::Db;

/// Trait for getting the "database".
///
/// This trait can be used with in "entrait-pattern" style dependency injection.
pub trait GetDb {
    type Db: Db;

    fn get_db(&self) -> &Self::Db;
}
