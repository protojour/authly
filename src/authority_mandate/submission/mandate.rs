//! Submission, mandate side

use authly_common::id::Eid;
use rcgen::{CertificateParams, CertificateSigningRequest, DnType, KeyUsagePurpose};

use crate::ctx::GetInstance;

use super::SubmissionClaims;

/// unverified decode of submission token, mandate side
pub fn mandate_decode_submission_token(
    deps: &impl GetInstance,
    token: &str,
) -> anyhow::Result<SubmissionClaims> {
    let mut no_validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
    no_validation.insecure_disable_signature_validation();

    Ok(jsonwebtoken::decode(
        token,
        deps.get_instance().local_jwt_decoding_key(),
        &no_validation,
    )?
    .claims)
}

pub fn mandate_identity_signing_request(
    deps: &impl GetInstance,
    mandate_eid: Eid,
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
