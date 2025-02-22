use std::{any::Any, collections::HashMap, fmt::Display, fs};

use authly_common::id::ServiceId;
use authly_db::{Db, DbError};
use authly_domain::{
    bus::{BusError, ClusterMessage},
    cert::{client_cert, CertificateParamsExt},
    ctx::{ClusterBus, GetDb, GetDecryptedDeks, GetInstance},
    directory::{DirKey, OAuthDirectory, PersonaDirectory},
    encryption::DecryptedDeks,
    id::BuiltinProp,
};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{
    audit::Actor,
    db::{
        cryptography_db::{self, CrDbError},
        directory_db::DbDirectory,
        document_db::{DocumentDbTxnError, DocumentTransaction},
        oauth_db::{self, OAuthRow},
    },
    document::compiled_document::CompiledDocument,
    AuthlyCtx,
};

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
    let mut oauth_dirs: HashMap<DirKey, OAuthDirectory> = oauth_db::oauth_query(db)
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
