use std::sync::Arc;

use anyhow::anyhow;
use authly_domain::{
    cert::{server_cert, CertificateParamsExt},
    ctx::GetInstance,
};
use futures_util::StreamExt;
use rustls::{pki_types::PrivateKeyDer, server::WebPkiClientVerifier, RootCertStore, ServerConfig};
use tracing::info;

use crate::{AuthlyCtx, AuthlyInstance};

pub fn init_tls_ring() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

pub(super) async fn main_service_tls_configurer(
    hostname: String,
    ctx: AuthlyCtx,
) -> anyhow::Result<impl tower_server::tls::TlsConfigurer> {
    // The root cert store is currently not changing
    let root_cert_store = {
        let mut store = RootCertStore::empty();
        store.add(ctx.get_instance().trust_root_ca().der.clone())?;
        Arc::new(store)
    };

    info!("generating server certificate for hostname={hostname}");

    // The first TLS config is produced immediately
    let initial = futures_util::stream::iter([generate_mutual_tls_server_config(
        &hostname,
        ctx.clone(),
        ctx.settings.load().server_cert_rotation_rate,
        root_cert_store.clone(),
    )?]);

    // The following configs are produced after delay
    let rotation_stream = futures_util::stream::unfold((), move |_| {
        let hostname = hostname.clone();
        let ctx = ctx.clone();
        let root_cert_store = root_cert_store.clone();
        async move {
            // TODO: reset this when settings change
            tokio::time::sleep(ctx.settings.load().server_cert_rotation_rate).await;

            let server_config = generate_mutual_tls_server_config(
                &hostname,
                ctx.clone(),
                ctx.settings.load().server_cert_rotation_rate,
                root_cert_store,
            )
            .expect("unable to regenerate server TLS config");

            Some((server_config, ()))
        }
    });

    Ok(initial.chain(rotation_stream).boxed())
}

fn generate_mutual_tls_server_config(
    hostname: &str,
    ctx: AuthlyCtx,
    rotation_rate: std::time::Duration,
    root_cert_store: Arc<RootCertStore>,
) -> anyhow::Result<Arc<ServerConfig>> {
    // Make the certificate valid for twice the rotation rate
    let not_after = time::Duration::try_from(rotation_rate)? * 2;

    let server_cert = ctx.get_instance().sign_with_local_ca(
        server_cert("authly", vec![hostname.to_string()], not_after)?.with_new_key_pair(),
    );

    let server_private_key_der = PrivateKeyDer::try_from(server_cert.key.serialize_der())
        .map_err(|err| anyhow!("server private key: {err}"))?;

    let mut config = rustls::server::ServerConfig::builder()
        .with_client_cert_verifier(WebPkiClientVerifier::builder(root_cert_store).build()?)
        .with_single_cert(vec![server_cert.der], server_private_key_der)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

pub fn generate_tls_server_config(
    hostname: &str,
    instance: &AuthlyInstance,
    rotation_rate: std::time::Duration,
) -> anyhow::Result<Arc<ServerConfig>> {
    // Make the certificate valid for twice the rotation rate
    let not_after = time::Duration::try_from(rotation_rate)? * 2;

    let server_cert = instance.sign_with_local_ca(
        server_cert("authly", vec![hostname.to_string()], not_after)?.with_new_key_pair(),
    );

    let server_private_key_der = PrivateKeyDer::try_from(server_cert.key.serialize_der())
        .map_err(|err| anyhow!("server private key: {err}"))?;

    let mut config = rustls::server::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![server_cert.der], server_private_key_der)?;

    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}
