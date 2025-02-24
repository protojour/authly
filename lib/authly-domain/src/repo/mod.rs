pub mod crypto_repo;
pub mod directory_repo;
pub mod document_repo;
pub mod entity_repo;
pub mod init_repo;
pub mod oauth_repo;
pub mod object_repo;
pub mod policy_repo;
pub mod service_repo;
pub mod session_repo;
pub mod settings_repo;

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

pub struct TextLabel(pub String);
