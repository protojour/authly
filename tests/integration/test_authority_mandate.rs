use authly::{
    audit::Actor,
    authority_mandate::submission::{
        authority::{
            authority_fulfill_submission, authority_generate_submission_code,
            authority_generate_submission_token,
        },
        mandate::{mandate_decode_submission_token, mandate_identity_signing_request},
    },
};
use authly_common::id::Eid;
use rcgen::CertificateSigningRequestParams;
use test_log::test;
use tracing::info;

use crate::TestCtx;

#[test(tokio::test)]
async fn test_mandate_registration_failure() {
    let a_ctx = TestCtx::default().inmemory_db().await.gen_tls_params();
    let m_ctx = TestCtx::default().inmemory_db().await.gen_tls_params();

    let token = authority_generate_submission_token(&a_ctx, b"INVALID CODE".to_vec())
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
    let a_ctx = TestCtx::default().inmemory_db().await.gen_tls_params();
    // Two mandates:
    let m_ctxs = [
        TestCtx::default().inmemory_db().await.gen_tls_params(),
        TestCtx::default().inmemory_db().await.gen_tls_params(),
    ];

    let actor = Actor(Eid::random());
    let mut tokens = vec![];

    // Generate tokens for each of the mandates
    for _ in &m_ctxs {
        let code = authority_generate_submission_code(&a_ctx, actor)
            .await
            .unwrap();
        let token = authority_generate_submission_token(&a_ctx, code)
            .await
            .unwrap();

        info!("token: {}", token);

        tokens.push(token);
    }

    let mut mandate_identities = vec![];

    for (token, m_ctx) in tokens.iter().zip(&m_ctxs) {
        let submission_claims = mandate_decode_submission_token(m_ctx, token).unwrap();
        let csr =
            mandate_identity_signing_request(m_ctx, submission_claims.authly.mandate_entity_id)
                .unwrap();

        mandate_identities.push(
            authority_fulfill_submission(
                &a_ctx,
                token,
                CertificateSigningRequestParams::from_der(csr.der()).unwrap(),
            )
            .await
            .unwrap(),
        );

        assert!(
            authority_fulfill_submission(
                &a_ctx,
                token,
                CertificateSigningRequestParams::from_der(csr.der()).unwrap()
            )
            .await
            .is_err(),
            "cannot reuse token code"
        );
    }
}
