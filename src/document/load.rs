use std::{fs, os::unix::ffi::OsStrExt};

use anyhow::anyhow;
use authly_common::{document::Document, id::DirectoryId};
use tracing::info;

use crate::{
    ctx::GetDb,
    db::document_db::{self, DocumentDirectory},
    directory,
    document::{compiled_document::DocumentMeta, doc_compiler::compile_doc},
    AuthlyCtx, EnvConfig,
};

/// Load documents from file
pub(crate) async fn load_cfg_documents(
    env_config: &EnvConfig,
    ctx: &AuthlyCtx,
) -> anyhow::Result<()> {
    let doc_authorities = document_db::get_documents(ctx.get_db()).await?;

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
                    let mut hasher = blake3::Hasher::new();
                    hasher.update(source.as_bytes());
                    hasher.finalize().into()
                },
            };

            let dir_id = DirectoryId::from_uint(document.authly_document.id.get_ref().as_u128());

            if should_process(dir_id, &meta, &doc_authorities) {
                info!(?path, "load");

                let compiled_doc = match compile_doc(document, meta, ctx.get_db()).await {
                    Ok(doc) => doc,
                    Err(errors) => {
                        for error in errors {
                            tracing::error!("doc error: {error:?}");
                        }
                        return Err(anyhow!("document error"));
                    }
                };

                directory::apply_document(ctx, compiled_doc).await?;
            } else {
                info!(?path, "unchanged");
            }
        }
    }

    Ok(())
}

fn should_process(
    dir_id: DirectoryId,
    meta: &DocumentMeta,
    doc_directories: &[DocumentDirectory],
) -> bool {
    for dir in doc_directories {
        if dir.dir_id != dir_id {
            continue;
        }

        if dir.hash == meta.hash {
            return false;
        }
    }

    true
}
