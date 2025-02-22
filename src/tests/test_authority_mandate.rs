use authly_common::id::PersonaId;
use authly_connect::TunnelSecurity;
use authly_domain::{
    cert::{server_cert, CertificateParamsExt},
    ctx::GetInstance,
};
use itertools::Itertools;
use rcgen::CertificateSigningRequestParams;
use test_log::test;
use tracing::info;

use crate::{
    audit::Actor,
    authority_mandate::submission::{
        authority::{
            authority_fulfill_submission, authority_generate_submission_token, PreissuedCode,
        },
        mandate::{
            mandate_decode_submission_token, mandate_execute_submission,
            mandate_identity_signing_request,
        },
    },
    proto::mandate_submission::AuthlyMandateSubmissionServerImpl,
    tests::{rustls_server_config_no_client_auth, spawn_test_connect_server, TestCtx},
};

#[test(tokio::test)]
async fn test_mandate_registration_failure() {
    let a_ctx = TestCtx::new().inmemory_db().await.supreme_instance().await;
    let m_ctx = TestCtx::new().inmemory_db().await.supreme_instance().await;

    let actor = Actor(PersonaId::random().upcast());
    let token = authority_generate_submission_token(
        &a_ctx,
        "http://localhost".to_string(),
        actor,
        Some(PreissuedCode(b"INVALID CODE".to_vec())),
    )
    .await
    .unwrap();
    let submission_claims = mandate_decode_submission_token(&m_ctx, &token).unwrap();
    let csr = mandate_identity_signing_request(&m_ctx, submission_claims.authly.mandate_entity_id)
        .unwrap();

    assert!(authority_fulfill_submission(
        &a_ctx,
        &token,
        CertificateSigningRequestParams::from_der(csr.der()).unwrap(),
    )
    .await
    .is_err());
}

#[test(tokio::test)]
async fn test_mandate_registration() {
    let authority_ctx = TestCtx::new().inmemory_db().await.supreme_instance().await;
    // Two mandate wannabes:
    let m_ctxs = [
        TestCtx::new().inmemory_db().await.supreme_instance().await,
        TestCtx::new().inmemory_db().await.supreme_instance().await,
    ];

    let (server_connect_uri, _drop) = spawn_test_connect_server(
        rustls_server_config_no_client_auth(&[&authority_ctx.get_instance().sign_with_local_ca(
            server_cert(
                "authly",
                vec!["localhost".to_string()],
                time::Duration::hours(1),
            )
            .unwrap()
            .with_new_key_pair(),
        )])
        .unwrap(),
        TunnelSecurity::Secure,
        tonic::service::Routes::default()
            .add_service(AuthlyMandateSubmissionServerImpl::new_service(
                authority_ctx.clone(),
            ))
            .into_axum_router(),
    )
    .await;

    let actor = Actor(PersonaId::random().upcast());
    let mut tokens = vec![];
    let mut claims = vec![];

    // Generate tokens for each of the mandates
    for m_ctx in &m_ctxs {
        let token = authority_generate_submission_token(
            &authority_ctx,
            server_connect_uri.clone(),
            actor,
            None,
        )
        .await
        .unwrap();

        claims.push(mandate_decode_submission_token(m_ctx, &token).unwrap());

        info!("token: {}", token);

        tokens.push(token);
    }

    // Execute submission in each of the mandates
    for (m_ctx, token) in m_ctxs.iter().zip_eq(&tokens) {
        mandate_execute_submission(m_ctx, token.to_string())
            .await
            .unwrap();

        assert!(
            mandate_execute_submission(m_ctx, token.to_string())
                .await
                .unwrap_err()
                .to_string()
                .contains("message: \"submission failed\""),
            "replay is not possible"
        );
    }

    // Verify instance reloaded
    for (m_ctx, claim) in m_ctxs.iter().zip_eq(&claims) {
        let reloaded_instance = m_ctx.get_instance();

        let expected_eid = claim.authly.mandate_entity_id;

        assert_eq!(reloaded_instance.authly_eid(), expected_eid);
    }
}
