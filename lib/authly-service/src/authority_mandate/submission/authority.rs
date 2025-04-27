//! Submission, authority side

use authly_common::id::ServiceId;
use authly_domain::{
    audit::Actor,
    cert::authly_ca,
    ctx::{GetDb, GetInstance},
    serde_util::UrlSafeBase64,
    tls::{AuthlyCert, AuthlyCertKind},
};
use rand::{rngs::OsRng, Rng};
use rcgen::{CertificateParams, CertificateSigningRequestParams, DnValue, PublicKeyData};
use tracing::warn;

use crate::repo::authority_mandate_repo::{self, AmDbError};

use super::{Authly, CertifiedMandate, SubmissionClaims, SUBMISSION_CODE_EXPIRATION};

/// Errors that may occur on the authority/server side
#[derive(thiserror::Error, Debug)]
pub enum AuthoritySubmissionError {
    #[error("token generation problem: {0}")]
    Token(#[from] jsonwebtoken::errors::Error),

    #[error("csr missing entity ID")]
    CsrMissingEntityId,

    #[error("csr entity ID mismatch")]
    CsrEntityIdMismatch,

    #[error("csr error: {0}")]
    CsrOther(rcgen::Error),

    #[error("database error")]
    Db(#[from] AmDbError),
}

pub struct PreissuedCode(pub Vec<u8>);

pub async fn authority_generate_submission_token(
    deps: &(impl GetDb + GetInstance),
    self_url: String,
    actor: Actor,
    preissued_code: Option<PreissuedCode>,
) -> Result<String, AuthoritySubmissionError> {
    let submission_code = match preissued_code {
        Some(PreissuedCode(code)) => code,
        None => save_new_submission_code(deps, actor).await?,
    };

    let now = time::OffsetDateTime::now_utc();
    let expiration = now + SUBMISSION_CODE_EXPIRATION;

    // Assign new Entity ID to mandate
    let mandate_entity_id = ServiceId::random();

    let claims = SubmissionClaims {
        iat: now.unix_timestamp(),
        exp: expiration.unix_timestamp(),
        authly: Authly {
            authority_url: self_url,
            code: UrlSafeBase64(submission_code),
            mandate_entity_id,
        },
    };

    let jwt_header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::ES256);
    Ok(jsonwebtoken::encode(
        &jwt_header,
        &claims,
        &deps.get_instance().local_jwt_encoding_key(),
    )?)
}

async fn save_new_submission_code(
    deps: &impl GetDb,
    created_by: Actor,
) -> Result<Vec<u8>, AuthoritySubmissionError> {
    let mut code: Vec<u8> = vec![0; 128];
    OsRng.fill(code.as_mut_slice());

    authority_mandate_repo::insert_mandate_submission_code(
        deps.get_db(),
        blake3::hash(&code).as_bytes().to_vec(),
        created_by,
    )
    .await?;

    Ok(code.to_vec())
}

pub async fn authority_fulfill_submission(
    deps: &(impl GetDb + GetInstance),
    token: &str,
    csr_params: CertificateSigningRequestParams,
) -> Result<CertifiedMandate, AuthoritySubmissionError> {
    let instance = deps.get_instance();

    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    let token_data = jsonwebtoken::decode::<SubmissionClaims>(
        token,
        instance.local_jwt_decoding_key(),
        &validation,
    )?;
    let claims = token_data.claims.authly;

    let code_created_by = authority_mandate_repo::verify_then_invalidate_submission_code(
        deps.get_db(),
        blake3::hash(&claims.code.0).as_bytes().to_vec(),
    )
    .await?;

    let mandate_eid = claims.mandate_entity_id;

    {
        let entity_id = csr_params
            .params
            .distinguished_name
            .get(&rcgen::DnType::CustomDnType(
                authly_common::certificate::oid::ENTITY_UNIQUE_IDENTIFIER.to_vec(),
            ))
            .and_then(|eid| match eid {
                DnValue::Utf8String(eid) => Some(eid),
                _ => None,
            })
            .ok_or_else(|| AuthoritySubmissionError::CsrMissingEntityId)?;

        if entity_id != &mandate_eid.to_string() {
            return Err(AuthoritySubmissionError::CsrEntityIdMismatch);
        }
    };

    let mandate_local_ca = authly_ca()
        .signed_by(
            &csr_params.public_key,
            &instance.local_ca().params,
            instance.private_key(),
        )
        .map_err(|err| {
            warn!(?err, "unable to sign mandate CA");
            AuthoritySubmissionError::CsrOther(err)
        })?;

    let mandate_public_key = csr_params.public_key.der_bytes().to_vec();

    let mandate_identity = csr_params
        .signed_by(&instance.local_ca().params, instance.private_key())
        .map_err(|err| {
            warn!(?err, "unable to sign mandate identity");
            AuthoritySubmissionError::CsrOther(err)
        })?;

    authority_mandate_repo::insert_authority_mandate(
        deps.get_db(),
        mandate_eid,
        code_created_by,
        mandate_public_key,
        "subject",
    )
    .await?;

    Ok(CertifiedMandate {
        mandate_eid,
        mandate_identity: AuthlyCert {
            kind: AuthlyCertKind::Identity,
            certifies: mandate_eid,
            signed_by: instance.authly_eid(),
            params: CertificateParams::from_ca_cert_der(mandate_identity.der())
                .map_err(AuthoritySubmissionError::CsrOther)?,
            der: mandate_identity.der().clone(),
        },
        mandate_local_ca: AuthlyCert {
            kind: AuthlyCertKind::Ca,
            certifies: mandate_eid,
            signed_by: instance.authly_eid(),
            params: CertificateParams::from_ca_cert_der(mandate_local_ca.der())
                .map_err(AuthoritySubmissionError::CsrOther)?,
            der: mandate_local_ca.der().clone(),
        },
    })
}
