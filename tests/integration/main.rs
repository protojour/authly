use std::sync::{Arc, RwLock};

use authly::{
    cert::{key_pair, Cert, MakeSigningRequest},
    ctx::{GetDb, GetTlsParams},
    db::{
        document_db,
        service_db::{self, ServicePropertyKind},
        sqlite::sqlite_txn,
    },
    document::{compiled_document::DocumentMeta, doc_compiler::compile_doc},
    encryption::DecryptedDeks,
    TlsParams,
};
use authly_common::{document::Document, id::Eid, service::PropertyMapping};
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

#[derive(Default)]
struct TestCtx {
    db: Option<RwLock<rusqlite::Connection>>,
    identity: Option<Eid>,
    tls_params: Option<Arc<TlsParams>>,
}

impl TestCtx {
    pub async fn inmemory_db(mut self) -> Self {
        use authly::Migrations;

        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        sqlite_migrate::<Migrations>(&mut conn).await;

        self.db = Some(RwLock::new(conn));
        self
    }

    fn gen_tls_params(mut self) -> Self {
        let ca = key_pair().authly_ca().self_signed();
        let eid = Eid::random();
        let identity = ca.sign(
            KeyPair::generate()
                .unwrap()
                .client_cert(&eid.to_string(), time::Duration::hours(1)),
        );
        self.identity = Some(eid);
        self.tls_params = Some(Arc::new(TlsParams::from_keys(ca, identity)));
        self
    }
}

impl GetDb for TestCtx {
    type Db = RwLock<rusqlite::Connection>;

    #[track_caller]
    fn get_db(&self) -> &Self::Db {
        self.db.as_ref().expect("TestCtx has no database")
    }
}

impl GetTlsParams for TestCtx {
    #[track_caller]
    fn get_tls_params(&self) -> &Arc<TlsParams> {
        self.tls_params.as_ref().expect("TestCtx has no TlsParams")
    }
}

async fn sqlite_migrate<T: rust_embed::RustEmbed>(conn: &mut rusqlite::Connection) {
    let mut files: Vec<_> = T::iter().collect();
    files.sort();

    let txn = conn.transaction().unwrap();

    for file in files {
        let migration = T::get(&file).unwrap();
        txn.execute_batch(std::str::from_utf8(&migration.data).unwrap())
            .unwrap();
    }

    txn.commit().unwrap();
}

async fn compile_and_apply_doc(
    doc: Document,
    deks: &DecryptedDeks,
    ctx: &TestCtx,
) -> anyhow::Result<()> {
    let compiled_doc = compile_doc(doc, DocumentMeta::default(), ctx)
        .await
        .unwrap();
    sqlite_txn(
        ctx.get_db(),
        document_db::document_txn_statements(compiled_doc, deks)?,
    )
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
    async fn load(svc_eid: Eid, conn: &RwLock<rusqlite::Connection>) -> Self {
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
