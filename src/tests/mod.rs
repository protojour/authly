use std::{collections::HashMap, path::PathBuf, sync::Arc};

use authly_common::{
    document::Document,
    id::{PersonaId, ServiceId},
    mtls_server::PeerServiceEntity,
    proto::connect::authly_connect_server::AuthlyConnectServer,
    service::NamespacePropertyMapping,
};
use authly_connect::{
    server::{AuthlyConnectServerImpl, ConnectService},
    TunnelSecurity,
};
use authly_domain::{audit::Actor, cert::Cert};
use authly_sqlite::SqlitePool;
use rcgen::KeyPair;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore, ServerConfig,
};
use serde_spanned::Spanned;
use tokio_util::sync::{CancellationToken, DropGuard};
use tracing::{info_span, Instrument};

use crate::{
    db::{
        document_db::DocumentDbTxnError,
        service_db::{self, PropertyKind},
    },
    directory::DirectoryError,
    document::{compiled_document::DocumentMeta, doc_compiler::compile_doc, error::DocError},
    test_support::TestCtx,
    util::remote_addr::RemoteAddr,
};

mod end2end;
mod test_access_control;
mod test_authly_connect;
mod test_authority_mandate;
mod test_demo;
mod test_docs_clause_examples;
mod test_docs_full_example;
mod test_document;
mod test_metadata;
mod test_oauth;
mod test_tls;
mod test_ultradb;

#[derive(Debug)]
pub enum TestDocError {
    Doc(Vec<Spanned<DocError>>),
    #[expect(unused)]
    Other(anyhow::Error),
}

async fn compile_and_apply_doc_dir(dir: PathBuf, ctx: &TestCtx) -> Result<(), TestDocError> {
    let mut doc_files: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|result| {
            let path = result.unwrap().path();
            let doc = std::fs::read_to_string(&path).unwrap();
            (path, doc)
        })
        .collect();
    doc_files.sort_by_key(|(path, _)| path.clone());

    for (_, doc) in doc_files {
        compile_and_apply_doc(&doc, ctx).await?;
    }

    Ok(())
}

async fn compile_and_apply_doc(toml: &str, ctx: &TestCtx) -> Result<(), TestDocError> {
    // For testing purposes, do this twice for each document, the second time will be a "no-op" re-application:

    compile_and_apply_doc_only_once(toml, ctx)
        .instrument(info_span!("initial apply"))
        .await?;

    compile_and_apply_doc_only_once(toml, ctx)
        .instrument(info_span!("re-apply"))
        .await?;

    Ok(())
}

/// "only once" version, don't use this directly unless testing event propagation
async fn compile_and_apply_doc_only_once(toml: &str, ctx: &TestCtx) -> Result<(), TestDocError> {
    let doc = Document::from_toml(toml).map_err(TestDocError::Other)?;
    let compiled_doc = compile_doc(ctx, doc, DocumentMeta::default())
        .await
        .map_err(TestDocError::Doc)?;

    crate::directory::apply_document(ctx, compiled_doc, Actor(PersonaId::random().upcast()))
        .await
        .map_err(|err| {
            if let DirectoryError::DocumentDbTxn(DocumentDbTxnError::Transaction(doc_errors)) = err
            {
                TestDocError::Doc(doc_errors)
            } else {
                TestDocError::Other(err.into())
            }
        })?;

    Ok(())
}

fn tonic_request<T>(msg: T, eid: ServiceId) -> tonic::Request<T> {
    let mut req = tonic::Request::new(msg);
    req.extensions_mut().insert(PeerServiceEntity(eid));
    req.extensions_mut()
        .insert(RemoteAddr("127.0.0.1:1337".parse().unwrap()));
    req
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
    resource: NamespacePropertyMapping,
    entity: NamespacePropertyMapping,
}

impl ServiceProperties {
    async fn load(svc_eid: ServiceId, conn: &SqlitePool) -> Self {
        let resource =
            service_db::get_service_property_mapping(conn, svc_eid, PropertyKind::Resource)
                .await
                .unwrap();
        let entity = service_db::get_service_property_mapping(conn, svc_eid, PropertyKind::Entity)
            .await
            .unwrap();

        Self { resource, entity }
    }
}
