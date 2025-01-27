use authly::{
    audit::Actor,
    authority_mandate::submission::{
        authority::{
            authority_fulfill_submission, authority_generate_submission_code,
            authority_generate_submission_token,
        },
        mandate::{
            mandate_decode_submission_token, mandate_fulfill_submission_txn_statements,
            mandate_identity_signing_request,
        },
        MandateSubmissionData,
    },
    ctx::{GetDb, GetInstance},
    db::cryptography_db::load_authly_instance,
};
use authly_common::id::Eid;
use authly_db::{sqlite_txn, IsLeaderDb};
use rcgen::CertificateSigningRequestParams;
use test_log::test;
use tracing::info;

use crate::TestCtx;

#[test(tokio::test)]
async fn test_mandate_registration_failure() {
    let a_ctx = TestCtx::default()
        .inmemory_db()
        .await
        .supreme_instance()
        .await;
    let m_ctx = TestCtx::default()
        .inmemory_db()
        .await
        .supreme_instance()
        .await;

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
    let a_ctx = TestCtx::default()
        .inmemory_db()
        .await
        .supreme_instance()
        .await;
    // Two mandate wannabes:
    let m_ctxs = [
        TestCtx::default()
            .inmemory_db()
            .await
            .supreme_instance()
            .await,
        TestCtx::default()
            .inmemory_db()
            .await
            .supreme_instance()
            .await,
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

    let mut certified_mandates = vec![];

    for (token, m_ctx) in tokens.iter().zip(&m_ctxs) {
        let submission_claims = mandate_decode_submission_token(m_ctx, token).unwrap();
        let csr =
            mandate_identity_signing_request(m_ctx, submission_claims.authly.mandate_entity_id)
                .unwrap();

        certified_mandates.push(
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

    for (certified_mandate, m_ctx) in certified_mandates.into_iter().zip(m_ctxs) {
        let mandate_eid = certified_mandate.mandate_eid;

        let data = MandateSubmissionData {
            certified_mandate,
            upstream_ca_chain: vec![a_ctx.get_instance().trust_root_ca().clone()],
        };

        // update mandate database
        let stmts = mandate_fulfill_submission_txn_statements(data);
        sqlite_txn(m_ctx.get_db(), stmts).await.unwrap();

        // reload instance
        let deks = m_ctx.get_decrypted_deks();
        let authly_instance = load_authly_instance(IsLeaderDb(true), m_ctx.get_db(), &deks)
            .await
            .unwrap();

        assert_eq!(authly_instance.authly_eid(), mandate_eid);
    }
}
