//! Submission, authority side

use anyhow::anyhow;
use authly_common::id::Eid;
use rand::{rngs::OsRng, Rng};
use rcgen::{Certificate, CertificateSigningRequestParams, DnValue, PublicKeyData};
use tracing::warn;

use crate::{
    audit::Actor,
    ctx::GetInstance,
    db::{authority_mandate_db, Db},
    serde_util::Hex,
};

use super::{Authly, SubmissionClaims, SUBMISSION_CODE_EXPIRATION};

pub struct CertifiedMandate {
    pub mandate_eid: Eid,
    pub certificate: Certificate,
}

pub async fn authority_generate_submission_code(
    deps: &impl Db,
    created_by: Actor,
) -> anyhow::Result<Vec<u8>> {
    let mut code: Vec<u8> = vec![0; 256];
    OsRng.fill(code.as_mut_slice());

    authority_mandate_db::insert_mandate_submission_code(
        deps,
        blake3::hash(&code).as_bytes().to_vec(),
        created_by,
    )
    .await?;

    Ok(code.to_vec())
}

pub async fn authority_generate_submission_token(
    deps: &impl GetInstance,
    submission_code: Vec<u8>,
) -> anyhow::Result<String> {
    let now = time::OffsetDateTime::now_utc();
    let expiration = now + SUBMISSION_CODE_EXPIRATION;

    // Assign new Entity ID to mandate
    let mandate_entity_id = Eid::random();

    let claims = SubmissionClaims {
        iat: now.unix_timestamp(),
        exp: expiration.unix_timestamp(),
        authly: Authly {
            // FIXME: Proper URL
            authority_url: "https://authly-internet.com".to_string(),
            code: Hex(submission_code),
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

pub async fn authority_fulfill_submission(
    deps: &(impl Db + GetInstance),
    token: &str,
    csr_params: CertificateSigningRequestParams,
) -> anyhow::Result<CertifiedMandate> {
    let instance = deps.get_instance();

    let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    let token_data = jsonwebtoken::decode::<SubmissionClaims>(
        token,
        instance.local_jwt_decoding_key(),
        &validation,
    )?;
    let claims = token_data.claims.authly;

    let code_created_by = authority_mandate_db::verify_then_invalidate_submission_code(
        deps,
        blake3::hash(&claims.code.0).as_bytes().to_vec(),
    )
    .await?;

    let mandate_eid = claims.mandate_entity_id;

    {
        let common_name = csr_params
            .params
            .distinguished_name
            .get(&rcgen::DnType::CommonName)
            .and_then(|cn| match cn {
                DnValue::Utf8String(cn) => Some(cn),
                _ => None,
            })
            .ok_or_else(|| anyhow!("No common name in CSR"))?;

        if common_name != &mandate_eid.to_string() {
            return Err(anyhow!("Common name in CSR does not match mandate EID"));
        }
    };

    let mandate_public_key = csr_params.public_key.der_bytes().to_vec();

    let identity_certificate = csr_params
        .signed_by(&instance.local_ca().params, instance.private_key())
        .map_err(|err| {
            warn!(?err, "unable to sign mandate identity");
            anyhow!("Certificate signing problem")
        })?;

    authority_mandate_db::insert_authority_mandate(
        deps,
        mandate_eid,
        code_created_by,
        mandate_public_key,
        "subject",
    )
    .await?;

    Ok(CertifiedMandate {
        mandate_eid,
        certificate: identity_certificate,
    })
}
