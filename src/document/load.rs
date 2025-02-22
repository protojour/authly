use std::{fs, os::unix::ffi::OsStrExt};

use anyhow::anyhow;
use authly_common::{
    document::Document,
    id::{DirectoryId, ServiceId},
};
use authly_domain::ctx::GetDb;
use tracing::info;

use crate::{
    audit::Actor,
    db::directory_db::DbDirectory,
    directory::{self, DirectoryKind},
    document::{compiled_document::DocumentMeta, doc_compiler::compile_doc},
    AuthlyCtx, EnvConfig,
};

/// Load documents from file
pub(crate) async fn load_cfg_documents(
    env_config: &EnvConfig,
    ctx: &AuthlyCtx,
) -> anyhow::Result<()> {
    let doc_directories = DbDirectory::query_by_kind(ctx.get_db(), DirectoryKind::Document).await?;

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

            if should_process(dir_id, &meta, &doc_directories) {
                info!(?path, "load");

                let compiled_doc = match compile_doc(ctx, document, meta).await {
                    Ok(doc) => doc,
                    Err(errors) => {
                        for error in errors {
                            tracing::error!("doc error: {error:?}");
                        }
                        return Err(anyhow!("document error"));
                    }
                };

                directory::apply_document(
                    ctx,
                    compiled_doc,
                    Actor(ServiceId::from_uint(0).upcast()),
                )
                .await?;
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
    doc_directories: &[DbDirectory],
) -> bool {
    for dir in doc_directories {
        if dir.id != dir_id {
            continue;
        }

        if dir.hash == meta.hash {
            return false;
        }
    }

    true
}
