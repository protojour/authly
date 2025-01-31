use std::{collections::HashMap, sync::Arc};

use anyhow::anyhow;
use authly::{
    cert::Cert,
    ctx::GetDb,
    db::{
        document_db,
        service_db::{self, ServicePropertyKind},
    },
    document::{compiled_document::DocumentMeta, doc_compiler::compile_doc},
    encryption::DecryptedDeks,
    test_ctx::TestCtx,
};
use authly_common::{
    document::Document, id::Eid, proto::connect::authly_connect_server::AuthlyConnectServer,
    service::PropertyMapping,
};
use authly_connect::{
    server::{AuthlyConnectServerImpl, ConnectService},
    TunnelSecurity,
};
use authly_db::{sqlite_handle::SqliteHandle, Db};
use rcgen::KeyPair;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
use tokio_util::sync::{CancellationToken, DropGuard};

mod end2end;
mod test_access_control;
mod test_authly_connect;
mod test_authority_mandate;
mod test_document;
mod test_tls;

async fn compile_and_apply_doc(
    toml: &str,
    deks: &DecryptedDeks,
    ctx: &TestCtx,
) -> anyhow::Result<()> {
    let doc = Document::from_toml(toml)?;
    let compiled_doc = compile_doc(doc, DocumentMeta::default(), ctx.get_db())
        .await
        .map_err(|errors| {
            for error in errors {
                println!("{error:?}: `{}`", &toml[error.span()])
            }

            anyhow!("doc compile error)")
        })?;
    for (idx, result) in ctx
        .get_db()
        .transact(document_db::document_txn_statements(compiled_doc, deks)?)
        .await
        .unwrap()
        .into_iter()
        .enumerate()
    {
        if let Err(err) = result {
            panic!("apply doc stmt {idx}: {err:?}");
        }
    }

    Ok(())
}

fn rustls_server_config_no_client_auth(
    server_cert_chain: &[&Cert<KeyPair>],
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let private_key_der =
        PrivateKeyDer::try_from(server_cert_chain.first().unwrap().key.serialize_der()).unwrap();

    let mut config = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            server_cert_chain
                .iter()
                .map(|cert| cert.der.clone())
                .collect(),
            private_key_der,
        )?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    Ok(Arc::new(config))
}

fn rustls_server_config_mtls(
    server_cert_chain: &[&Cert<KeyPair>],
    root_ca: &CertificateDer,
) -> anyhow::Result<Arc<rustls::ServerConfig>> {
    let _ = rustls::crypto::ring::default_provider().install_default();

    let private_key_der =
        PrivateKeyDer::try_from(server_cert_chain.first().unwrap().key.serialize_der()).unwrap();

    let mut root_cert_store = RootCertStore::empty();
    root_cert_store.add(root_ca.clone())?;

    let mut config = rustls::server::ServerConfig::builder()
        .with_client_cert_verifier(WebPkiClientVerifier::builder(root_cert_store.into()).build()?)
        .with_single_cert(
            server_cert_chain
                .iter()
                .map(|cert| cert.der.clone())
                .collect(),
            private_key_der,
        )?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec(), b"http/1.0".to_vec()];
    Ok(Arc::new(config))
}

/// Returns URL and drop guard
#[expect(unused)]
async fn spawn_test_server(service: axum::Router) -> (String, DropGuard) {
    let cancel = CancellationToken::new();
    let url = spawn_test_server_cancellable(service, cancel.clone()).await;
    (url, cancel.drop_guard())
}

// Spawn a server with Authly Connect service
async fn spawn_test_connect_server(
    tls_config: Arc<ServerConfig>,
    security: TunnelSecurity,
    service: axum::Router,
) -> (String, DropGuard) {
    let cancel = CancellationToken::new();
    let url = spawn_test_server_cancellable(
        tonic::service::Routes::default()
            .add_service(AuthlyConnectServer::new(AuthlyConnectServerImpl {
                services: HashMap::from([(
                    security,
                    ConnectService {
                        tls_server_config: tls_config,
                        service: service.clone(),
                    },
                )]),
                cancel: cancel.clone(),
            }))
            .into_axum_router(),
        cancel.clone(),
    )
    .await;

    (url, cancel.drop_guard())
}

async fn spawn_test_server_cancellable(service: axum::Router, cancel: CancellationToken) -> String {
    let server = tower_server::Builder::new("0.0.0.0:0".parse().unwrap())
        .with_graceful_shutdown(cancel.clone())
        .bind()
        .await
        .unwrap();
    let port = server.local_addr().unwrap().port();

    tokio::spawn(server.serve(service));

    format!("http://localhost:{port}")
}

struct ServiceProperties {
    resource: PropertyMapping,
    entity: PropertyMapping,
}

impl ServiceProperties {
    async fn load(svc_eid: Eid, conn: &SqliteHandle) -> Self {
        let resource =
            service_db::get_service_property_mapping(conn, svc_eid, ServicePropertyKind::Resource)
                .await
                .unwrap();
        let entity =
            service_db::get_service_property_mapping(conn, svc_eid, ServicePropertyKind::Entity)
                .await
                .unwrap();

        Self { resource, entity }
    }
}

fn main() {}
