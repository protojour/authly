use std::{fs, os::unix::ffi::OsStrExt};

use anyhow::anyhow;
use authly_common::{document::Document, Eid};
use sha2::Digest;
use tracing::info;

use crate::{
    authority,
    db::document_db::{self, DocumentAuthority},
    document::{compiled_document::DocumentMeta, doc_compiler::compile_doc},
    AuthlyCtx, EnvConfig,
};

/// Load documents from file
pub(crate) async fn load_cfg_documents(
    env_config: &EnvConfig,
    ctx: &AuthlyCtx,
) -> anyhow::Result<()> {
    let doc_authorities = document_db::get_documents(ctx).await?;

    for dir_path in &env_config.document_path {
        let Ok(entries) = fs::read_dir(dir_path) else {
            tracing::error!(?dir_path, "document path could not be scanned");
            continue;
        };

        let mut file_paths: Vec<_> = entries
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            // files only
            .filter(|path| path.is_file())
            // only files ending with .toml
            .filter(|path| path.extension().map(OsStrExt::as_bytes) == Some(b"toml"))
            .collect();
        file_paths.sort();

        for path in file_paths {
            let path = std::path::absolute(path).unwrap();

            let source = fs::read_to_string(&path)
                .map_err(|_| anyhow!("document {path:?} failed to load"))?;

            let document = Document::from_toml(&source)?;

            let meta = DocumentMeta {
                url: format!("file://{}", path.to_str().unwrap()),
                hash: {
                    let mut hasher = sha2::Sha256::new();
                    hasher.update(&source);
                    hasher.finalize().into()
                },
            };

            let aid = Eid::new(document.authly_document.id.get_ref().as_u128());

            if should_process(aid, &meta, &doc_authorities) {
                info!(?path, "load");

                let compiled_doc = match compile_doc(document, meta, ctx).await {
                    Ok(doc) => doc,
                    Err(errors) => {
                        for error in errors {
                            tracing::error!("doc error: {error:?}");
                        }
                        return Err(anyhow!("document error"));
                    }
                };

                authority::apply_document(compiled_doc, ctx).await?;
            } else {
                info!(?path, "unchanged");
            }
        }
    }

    Ok(())
}

fn should_process(aid: Eid, meta: &DocumentMeta, doc_authorities: &[DocumentAuthority]) -> bool {
    for auth in doc_authorities {
        if auth.aid != aid {
            continue;
        }

        if auth.hash == meta.hash {
            return false;
        }
    }

    true
}
