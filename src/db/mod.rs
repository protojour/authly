pub mod authority_mandate_db;
pub mod cryptography_db;
pub mod directory_db;
pub mod document_db;
pub mod entity_db;
pub mod policy_db;
pub mod service_db;
pub mod session_db;
pub mod settings_db;

#[derive(Debug)]
pub struct Identified<I, D>(pub I, pub D);

impl<I, D> Identified<I, D> {
    pub fn id(&self) -> &I {
        &self.0
    }

    pub fn data(&self) -> &D {
        &self.1
    }

    pub fn data_mut(&mut self) -> &mut D {
        &mut self.1
    }

    pub fn into_data(self) -> D {
        self.1
    }
}
