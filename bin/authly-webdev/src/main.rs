use authly_common::{id::ServiceId, mtls_server::PeerServiceEntity};
use authly_domain::dev::IsDev;
use authly_test::{test_ctx::TestCtx, util::compile_and_apply_doc_dir};
use tower_server::Scheme;
use tracing::{info, level_filters::LevelFilter};
use tracing_subscriber::EnvFilter;

const PORT: u16 = 12345;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_level(true)
        .with_env_filter(EnvFilter::from_env("AUTHLY_LOG").add_directive(LevelFilter::INFO.into()))
        .init();

    info!("serving on http://localhost:{PORT}");

    let shutdown = tower_server::signal::termination_signal();
    let test_ctx = TestCtx::new().inmemory_db().await.supreme_instance().await;

    compile_and_apply_doc_dir("examples/demo".into(), &test_ctx)
        .await
        .unwrap();

    tokio::spawn(
        tower_server::Builder::new(format!("0.0.0.0:{PORT}").parse()?)
            .with_scheme(Scheme::Http)
            .with_graceful_shutdown(shutdown.clone())
            .with_connection_middleware(|req, _| {
                req.extensions_mut()
                    .insert(PeerServiceEntity(ServiceId::from_uint(1)));
                req.extensions_mut().insert(IsDev(true));
            })
            .bind()
            .await?
            .serve(authly_web::router().with_state(test_ctx)),
    );

    shutdown.cancelled().await;

    Ok(())
}
