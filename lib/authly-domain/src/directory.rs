use std::{collections::HashMap, fmt::Display};

use authly_common::id::DirectoryId;
use authly_db::{Db, DbError, FromRow, Row};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};

use crate::{
    bus::BusError,
    encryption::{CryptoError, DecryptedDeks},
    id::BuiltinProp,
    repo::{
        crypto_repo,
        directory_repo::DbDirectory,
        document_repo::DocumentDbTxnError,
        oauth_repo::{self, OAuthRow},
    },
};

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

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DirectoryKind {
    Document,
    Persona,
}

impl Display for DirectoryKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.serialize(f)
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

#[derive(thiserror::Error, Debug)]
pub enum DirectoryError {
    // #[error("db error: {0}")]
    // Db(#[from] DbError),
    #[error("bus error: {0}")]
    Bus(#[from] BusError),

    #[error("db error: {0}")]
    Db(#[from] DbError),

    #[error("cryptography error: {0}")]
    Crypto(#[from] CryptoError),

    #[error("document txn error: {0}")]
    DocumentDbTxn(#[from] DocumentDbTxnError),

    #[error("missing secret")]
    MissingSecret,
}

pub async fn load_persona_directories(
    db: &impl Db,
    deks: &DecryptedDeks,
) -> Result<IndexMap<String, PersonaDirectory>, DirectoryError> {
    let directories = DbDirectory::query_by_kind(db, DirectoryKind::Persona).await?;
    let mut oauth_dirs: HashMap<DirKey, OAuthDirectory> = oauth_repo::oauth_query(db)
        .await?
        .into_iter()
        .map(|OAuthRow(dir)| (dir.dir_key, dir))
        .collect();

    let mut persona_dirs: Vec<(String, PersonaDirectory)> = vec![];

    for dir in directories {
        let Some(label) = dir.label else {
            continue;
        };

        if let Some(mut oauth) = oauth_dirs.remove(&dir.key) {
            let Some(client_secret) = crypto_repo::load_decrypt_obj_ident(
                db,
                dir.id.upcast(),
                BuiltinProp::OAuthClientSecret.into(),
                deks,
            )
            .await
            .map_err(DirectoryError::Crypto)?
            else {
                return Err(DirectoryError::MissingSecret);
            };

            oauth.client_secret = client_secret;

            persona_dirs.push((label, PersonaDirectory::OAuth(oauth)));
        }
    }

    persona_dirs.sort_by_key(|(label, _)| label.clone());

    Ok(persona_dirs.into_iter().collect())
}
