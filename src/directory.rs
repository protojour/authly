use std::{any::Any, collections::HashMap, fmt::Display, fs};

use authly_common::id::{DirectoryId, ServiceId};
use authly_db::{param::AsParam, Db, DbError};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{
    audit::Actor,
    bus::{message::ClusterMessage, BusError},
    cert::{client_cert, CertificateParamsExt},
    ctx::{ClusterBus, GetDb, GetDecryptedDeks, GetInstance},
    db::{
        cryptography_db::{self, CrDbError},
        directory_db::DbDirectory,
        document_db::{DocumentDbTxnError, DocumentTransaction},
    },
    document::compiled_document::CompiledDocument,
    encryption::DecryptedDeks,
    id::BuiltinProp,
    AuthlyCtx,
};

#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub struct DirKey(pub i64);

impl AsParam for DirKey {
    fn as_param(&self) -> hiqlite::Param {
        self.0.into()
    }
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
    Crypto(#[from] CrDbError),

    #[error("document txn error: {0}")]
    DocumentDbTxn(#[from] DocumentDbTxnError),

    #[error("missing secret")]
    MissingSecret,
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

/// Apply (write or overwrite) a document directory, publish change message
pub async fn apply_document(
    deps: &(impl GetDb + GetDecryptedDeks + ClusterBus + Any),
    compiled_doc: CompiledDocument,
    actor: Actor,
) -> Result<(), DirectoryError> {
    let dir_id = compiled_doc.dir_id;

    let service_ids: Vec<_> = compiled_doc.data.services.keys().copied().collect();

    let deks = deps.load_decrypted_deks();

    DocumentTransaction::new(compiled_doc, actor)
        .execute(deps.get_db(), &deks)
        .await?;

    if let Some(authly_ctx) = (deps as &dyn Any).downcast_ref::<AuthlyCtx>() {
        if authly_ctx.export_tls_to_etc {
            for svc_eid in service_ids {
                if let Err(err) = export_service_identity(svc_eid, authly_ctx) {
                    error!(?err, ?svc_eid, "unable to export identity");
                }
            }
        }
    }

    deps.broadcast_to_cluster(ClusterMessage::DirectoryChanged { dir_id })
        .await?;

    Ok(())
}

pub async fn load_persona_directories(
    db: &impl Db,
    deks: &DecryptedDeks,
) -> Result<IndexMap<String, PersonaDirectory>, DirectoryError> {
    let directories = DbDirectory::query_by_kind(db, DirectoryKind::Persona).await?;
    let mut oauth_dirs: HashMap<DirKey, OAuthDirectory> = OAuthDirectory::query(db)
        .await?
        .into_iter()
        .map(|o| (o.dir_key, o))
        .collect();

    let mut persona_dirs: Vec<(String, PersonaDirectory)> = vec![];

    for dir in directories {
        let Some(label) = dir.label else {
            continue;
        };

        if let Some(mut oauth) = oauth_dirs.remove(&dir.key) {
            let Some(client_secret) = cryptography_db::load_decrypt_obj_ident(
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

fn export_service_identity(svc_eid: ServiceId, ctx: &AuthlyCtx) -> anyhow::Result<()> {
    let pem = ctx
        .get_instance()
        .sign_with_local_ca(
            client_cert("service", svc_eid, time::Duration::days(7)).with_new_key_pair(),
        )
        .certificate_and_key_pem();

    let path = ctx.etc_dir.join(format!("service/{svc_eid}/identity.pem"));
    fs::create_dir_all(path.parent().unwrap())?;

    std::fs::write(path, pem)?;

    Ok(())
}
