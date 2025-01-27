use authly::{
    cert::Cert,
    ctx::test::TestCtx,
    db::{
        document_db,
        service_db::{self, ServicePropertyKind},
    },
    document::{compiled_document::DocumentMeta, doc_compiler::compile_doc},
    encryption::DecryptedDeks,
};
use authly_common::{document::Document, id::Eid, service::PropertyMapping};
use authly_db::{sqlite_handle::SqliteHandle, Db};
use rcgen::KeyPair;
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    server::WebPkiClientVerifier,
    RootCertStore,
};

mod end2end;
mod test_access_control;
mod test_authly_connect;
mod test_authority_mandate;
mod test_document;
mod test_tls;

async fn compile_and_apply_doc(
    doc: Document,
    deks: &DecryptedDeks,
    ctx: &TestCtx,
) -> anyhow::Result<()> {
    let compiled_doc = compile_doc(doc, DocumentMeta::default(), ctx)
        .await
        .unwrap();
    ctx.txn(document_db::document_txn_statements(compiled_doc, deks)?)
        .await
        .unwrap();

    Ok(())
}

fn rustls_server_config_no_client_auth(
    server_cert_chain: &[&Cert<KeyPair>],
) -> anyhow::Result<rustls::ServerConfig> {
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
    Ok(config)
}

fn rustls_server_config_mtls(
    server_cert_chain: &[&Cert<KeyPair>],
    root_ca: &CertificateDer,
) -> anyhow::Result<rustls::ServerConfig> {
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
    Ok(config)
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
