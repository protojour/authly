//! Submission, mandate side

use std::{borrow::Cow, sync::Arc};

use authly_common::{
    id::ServiceId,
    proto::mandate_submission::{
        self as proto, authly_mandate_submission_client::AuthlyMandateSubmissionClient,
    },
};
use authly_connect::{
    client::new_authly_connect_grpc_client_service, no_trust_verifier::NoTrustVerifier,
    TunnelSecurity,
};
use authly_db::{param::ToBlob, params, Db};
use authly_domain::{
    bus::{BusError, ClusterMessage},
    cert::client_cert_csr,
    ctx::{ClusterBus, GetDb, GetDecryptedDeks, GetInstance, SetInstance},
    repo::crypto_repo,
};
use bytes::Bytes;
use rcgen::{CertificateParams, CertificateSigningRequest, DnType, KeyUsagePurpose};
use rustls::ClientConfig;
use tracing::error;

use super::{MandateSubmissionData, SubmissionClaims};

/// Errors that may occur on the mandate/client side when submitting
#[derive(thiserror::Error, Debug)]
pub enum MandateSubmissionError {
    #[error("invalid token: {0}")]
    InvalidToken(jsonwebtoken::errors::Error),

    #[error("connect error: {0}")]
    Connect(anyhow::Error),

    #[error("csr error: {0}")]
    Csr(rcgen::Error),

    #[error("submission protocol error: {0}")]
    Protocol(tonic::Status),

    #[error("protobuf error: {0}")]
    Protobuf(anyhow::Error),

    #[error("local database error")]
    Db,

    #[error("broadcast error, unable to notify the cluster: {0}")]
    Broadcast(#[from] BusError),
}

/// Perform submission to authority, mandate side.
/// Talks to Authority through Authly Connect tunnel, using the AuthlyMandateSubmission protocol.
pub async fn mandate_execute_submission(
    deps: &(impl GetDb + GetInstance + SetInstance + GetDecryptedDeks + ClusterBus),
    token: String,
) -> Result<(), MandateSubmissionError> {
    // read URL from token
    let claims = mandate_decode_submission_token(deps, &token)?;

    // open connection
    let mut submission_grpc_client = AuthlyMandateSubmissionClient::new(
        new_authly_connect_grpc_client_service(
            Bytes::from(claims.authly.authority_url.as_bytes().to_vec()),
            TunnelSecurity::Secure,
            Arc::new(
                ClientConfig::builder()
                    .dangerous()
                    .with_custom_certificate_verifier(Arc::new(NoTrustVerifier))
                    .with_no_client_auth(),
            ),
            Default::default(),
        )
        .await
        .map_err(MandateSubmissionError::Connect)?,
    );

    // Ask the authority to sign a identity certificate.
    // The private key never leaves the mandate.
    // The certificate will be used in subsequent communication with the authority.
    let identity_csr = client_cert_csr(
        "authly",
        claims.authly.mandate_entity_id,
        time::Duration::days(365 * 100),
    )
    .serialize_request(deps.get_instance().private_key())
    .map_err(MandateSubmissionError::Csr)?;

    let response = submission_grpc_client
        .submit(proto::SubmissionRequest {
            token,
            identity_csr_der: identity_csr.der().to_vec(),
        })
        .await
        .map_err(MandateSubmissionError::Protocol)?
        .into_inner();

    let mandate_submission_data =
        MandateSubmissionData::try_from(response).map_err(MandateSubmissionError::Protobuf)?;
    let stmts = mandate_fulfill_submission_txn_statements(deps.get_db(), mandate_submission_data);
    deps.get_db().transact(stmts).await.map_err(|err| {
        error!(?err, "submission transaction error");
        MandateSubmissionError::Db
    })?;

    // notify ourselves and the rest of the cluster
    deps.broadcast_to_cluster(ClusterMessage::InstanceChanged)
        .await?;

    Ok(())
}

/// unverified decode of submission token, mandate side
pub fn mandate_decode_submission_token(
    deps: &dyn GetInstance,
    token: &str,
) -> Result<SubmissionClaims, MandateSubmissionError> {
    let mut no_validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    no_validation.insecure_disable_signature_validation();

    Ok(jsonwebtoken::decode(
        token,
        deps.get_instance().local_jwt_decoding_key(),
        &no_validation,
    )
    .map_err(MandateSubmissionError::InvalidToken)?
    .claims)
}

pub fn mandate_identity_signing_request(
    deps: &dyn GetInstance,
    mandate_eid: ServiceId,
) -> anyhow::Result<CertificateSigningRequest> {
    let common_name = mandate_eid.to_string();
    let params = {
        let mut params = CertificateParams::new(vec![common_name.to_string()])?;
        params
            .distinguished_name
            .push(DnType::CommonName, common_name);
        params.use_authority_key_identifier_extension = false;
        params.key_usages.push(KeyUsagePurpose::DigitalSignature);
        params
            .extended_key_usages
            .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);

        let now = time::OffsetDateTime::now_utc();
        params.not_before = now;

        // A default timeout that is one year.
        // FIXME(rotation) What happens to the server after the certificate expires?
        // No other services would then be able to connect to it, but it wouldn't itself understand that it's broken.
        params.not_after = now.checked_add(time::Duration::days(365)).unwrap();
        params
    };

    Ok(params.serialize_request(deps.get_instance().private_key())?)
}

pub fn mandate_fulfill_submission_txn_statements<D: Db>(
    _db: &D,
    data: MandateSubmissionData,
) -> Vec<(Cow<'static, str>, Vec<<D as Db>::Param>)> {
    let mut stmts: Vec<(Cow<'static, str>, Vec<<D as Db>::Param>)> = vec![];

    stmts.push((
        "UPDATE authly_instance SET eid = $1".into(),
        params!(data.certified_mandate.mandate_eid.to_blob()),
    ));

    // Remove all TLS certs
    stmts.push(("DELETE FROM tls_cert".into(), params!()));

    // Repopulate TLS certs
    for authly_cert in [data.certified_mandate.mandate_local_ca]
        .into_iter()
        .chain(data.upstream_ca_chain)
    {
        stmts.push(crypto_repo::save_tls_cert_sql::<D>(&authly_cert));
    }

    stmts
}
