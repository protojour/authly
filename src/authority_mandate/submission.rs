use anyhow::anyhow;
use authly_common::{
    id::Eid,
    proto::mandate_submission::{self as proto},
};
use rcgen::CertificateParams;
use rustls::pki_types::CertificateDer;
use serde::{Deserialize, Serialize};

use crate::{
    serde_util::Hex,
    tls::{AuthlyCert, AuthlyCertKind},
};

pub mod authority;
pub mod mandate;

/// How long a submission code is valid
pub const SUBMISSION_CODE_EXPIRATION: time::Duration = time::Duration::hours(3);

/// Submission claim issued by the authority
#[derive(Serialize, Deserialize)]
pub struct SubmissionClaims {
    /// Issued at.
    pub iat: i64,

    /// Expiration time
    pub exp: i64,

    /// Authy claims
    pub authly: Authly,
}

#[derive(Serialize, Deserialize)]
pub struct Authly {
    /// The public URL of the authority
    pub authority_url: String,

    /// Submission code
    pub code: Hex,

    /// The entity ID handed by the authority to the mandate
    pub mandate_entity_id: Eid,
}

pub struct CertifiedMandate {
    pub mandate_eid: Eid,
    pub mandate_identity: AuthlyCert,
    pub mandate_local_ca: AuthlyCert,
}

pub struct MandateSubmissionData {
    pub certified_mandate: CertifiedMandate,
    pub upstream_ca_chain: Vec<AuthlyCert>,
}

impl TryFrom<proto::SubmissionResponse> for MandateSubmissionData {
    type Error = anyhow::Error;

    fn try_from(value: proto::SubmissionResponse) -> Result<Self, Self::Error> {
        let mut proto_ca_chain = value.ca_chain.into_iter();
        let proto_local_ca = proto_ca_chain
            .next()
            .ok_or_else(|| anyhow!("No local CA"))?;

        Ok(MandateSubmissionData {
            certified_mandate: CertifiedMandate {
                mandate_eid: read_id(&value.mandate_entity_id)?,
                mandate_identity: value
                    .mandate_identity_cert
                    .ok_or_else(|| anyhow!("no identity cert"))
                    .and_then(|cert| (cert, AuthlyCertKind::Identity).try_into())?,
                mandate_local_ca: (proto_local_ca, AuthlyCertKind::Ca).try_into()?,
            },
            upstream_ca_chain: proto_ca_chain
                .map(|cert| (cert, AuthlyCertKind::Ca).try_into())
                .collect::<Result<_, _>>()?,
        })
    }
}

impl TryFrom<(proto::AuthlyCertificate, AuthlyCertKind)> for AuthlyCert {
    type Error = anyhow::Error;

    fn try_from(
        (proto, kind): (proto::AuthlyCertificate, AuthlyCertKind),
    ) -> Result<Self, Self::Error> {
        let der = CertificateDer::from(proto.der);
        let params = CertificateParams::from_ca_cert_der(&der)?;

        Ok(AuthlyCert {
            kind,
            certifies: read_id(&proto.certifies_entity_id)?,
            signed_by: read_id(&proto.signed_by_entity_id)?,
            params,
            der,
        })
    }
}

fn read_id(bytes: &[u8]) -> anyhow::Result<Eid> {
    Eid::from_bytes(bytes).ok_or_else(|| anyhow!("invalid ID"))
}
