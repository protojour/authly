use authly_common::id::DirectoryId;
use authly_db::{FromRow, Row};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DirKey(pub i64);

impl FromRow for DirKey {
    fn from_row(row: &mut impl Row) -> Self {
        Self(row.get_int("key"))
    }
}

pub struct DirForeignKey(pub DirKey);

impl FromRow for DirForeignKey {
    fn from_row(row: &mut impl Row) -> Self {
        Self(DirKey(row.get_int("dir_key")))
    }
}

#[derive(Clone, Debug)]
pub enum PersonaDirectory {
    OAuth(OAuthDirectory),
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OAuthDirectory {
    pub dir_key: DirKey,
    pub dir_id: DirectoryId,
    pub client_id: String,
    pub client_secret: String,

    pub auth_url: String,
    pub auth_req_scope: Option<String>,
    pub auth_req_client_id_field: Option<String>,
    pub auth_req_nonce_field: Option<String>,
    pub auth_res_code_path: Option<String>,

    pub token_url: String,
    pub token_req_client_id_field: Option<String>,
    pub token_req_client_secret_field: Option<String>,
    pub token_req_code_field: Option<String>,
    pub token_req_callback_url_field: Option<String>,
    pub token_res_access_token_field: Option<String>,

    pub user_url: String,
    pub user_res_id_path: Option<String>,
    pub user_res_email_path: Option<String>,
}
