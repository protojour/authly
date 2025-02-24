use std::{fmt::Display, str::FromStr};

use anyhow::anyhow;
use authly_common::id::ServiceId;
use authly_db::{Row, TryFromRow};
use pem::{EncodeConfig, Pem};
use rcgen::CertificateParams;
use rustls::pki_types::CertificateDer;

#[derive(Clone, Debug)]
pub struct AuthlyCert {
    pub kind: AuthlyCertKind,
    pub certifies: ServiceId,
    pub signed_by: ServiceId,
    pub params: CertificateParams,
    pub der: CertificateDer<'static>,
}

impl AuthlyCert {
    pub fn certificate_pem(&self) -> String {
        pem::encode_config(
            &Pem::new("CERTIFICATE", self.der.to_vec()),
            EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum AuthlyCertKind {
    Ca,
    Identity,
}

impl Display for AuthlyCertKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ca => write!(f, "CA"),
            Self::Identity => write!(f, "identity"),
        }
    }
}

impl FromStr for AuthlyCertKind {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "CA" => Ok(Self::Ca),
            "identity" => Ok(Self::Identity),
            _ => Err(()),
        }
    }
}

impl TryFromRow for AuthlyCert {
    type Error = anyhow::Error;

    fn try_from_row(row: &mut impl Row) -> Result<Self, Self::Error> {
        let kind = row.get_text("kind");
        let Ok(kind) = AuthlyCertKind::from_str(&kind) else {
            return Err(anyhow!("invalid cert kind: {kind}"));
        };
        let cert_der = CertificateDer::from(row.get_blob("der"));
        Ok(Self {
            kind,
            certifies: row.get_id("certifies_eid"),
            signed_by: row.get_id("signed_by_eid"),
            params: CertificateParams::from_ca_cert_der(&cert_der)?,
            der: cert_der,
        })
    }
}
