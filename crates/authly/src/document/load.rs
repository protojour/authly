use std::{fs, os::unix::ffi::OsStrExt};

use anyhow::anyhow;
use authly_domain::document::Document;
use tracing::info;

use crate::{db::document_db, document::doc_compiler::compile_doc, AuthlyCtx, EnvConfig};

/// Load documents from file
pub async fn load_cfg_documents(env_config: &EnvConfig, ctx: &AuthlyCtx) -> anyhow::Result<()> {
    for path in &env_config.document_path {
        let Ok(entries) = fs::read_dir(path) else {
            tracing::error!(?path, "document path could not be scanned");
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

        for file_path in file_paths {
            info!(?file_path, "load document");
            let source = fs::read_to_string(&file_path)
                .map_err(|_| anyhow!("document {file_path:?} failed to load"))?;
            let document = Document::from_toml(&source)?;
            let compiled_doc = match compile_doc(document, ctx).await {
                Ok(doc) => doc,
                Err(errors) => {
                    for error in errors {
                        tracing::error!("doc error: {error:?}");
                    }
                    return Err(anyhow!("document error"));
                }
            };

            document_db::store_document(ctx, compiled_doc).await?;
        }
    }

    Ok(())
}
