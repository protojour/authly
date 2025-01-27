use authly_common::id::Eid;
use serde::{Deserialize, Serialize};

use crate::{serde_util::Hex, tls::AuthlyCert};

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
