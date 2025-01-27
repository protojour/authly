use std::ops::Deref;

use authly_common::id::Eid;
use rcgen::{KeyPair, PublicKeyData};

use crate::{
    cert::{Cert, SigningRequest},
    tls::{AuthlyCert, AuthlyCertKind},
};

/// Instance data, related to this installation of Authly
pub struct AuthlyInstance {
    authly_id: AuthlyId,
    certs: Vec<AuthlyCert>,
    local_jwt_decoding_key: jsonwebtoken::DecodingKey,
}

/// IDs of the authly instance.
/// Consists of Entity ID and key pair.
pub struct AuthlyId {
    pub eid: Eid,
    pub private_key: KeyPair,
}

impl AuthlyInstance {
    pub fn new(id: AuthlyId, certs: Vec<AuthlyCert>) -> Self {
        let _trust_root_ca = certs
            .iter()
            .find(|cert| {
                matches!(cert.kind, AuthlyCertKind::Ca) && cert.certifies == cert.signed_by
            })
            .expect("trust root not provided");

        let _trust_root_ca = certs
            .iter()
            .find(|cert| matches!(cert.kind, AuthlyCertKind::Identity) && cert.certifies == id.eid)
            .expect("Self TLS identity not found");

        let local_ca = certs
            .iter()
            .find(|cert| matches!(cert.kind, AuthlyCertKind::Ca) && cert.certifies == id.eid)
            .expect("self CA not provided");

        let local_jwt_decoding_key = {
            let (_, x509_cert) = x509_parser::parse_x509_certificate(&local_ca.der).unwrap();

            // Assume that EC is always used
            jsonwebtoken::DecodingKey::from_ec_der(&x509_cert.public_key().subject_public_key.data)
        };

        Self {
            authly_id: id,
            certs,
            local_jwt_decoding_key,
        }
    }

    pub fn local_jwt_decoding_key(&self) -> &jsonwebtoken::DecodingKey {
        &self.local_jwt_decoding_key
    }

    pub fn local_jwt_encoding_key(&self) -> jsonwebtoken::EncodingKey {
        jsonwebtoken::EncodingKey::from_ec_der(self.private_key().serialized_der())
    }

    pub fn private_key(&self) -> &KeyPair {
        &self.authly_id.private_key
    }

    pub fn trust_root_ca(&self) -> &AuthlyCert {
        self.certs
            .iter()
            .find(|cert| {
                matches!(cert.kind, AuthlyCertKind::Ca) && cert.certifies == cert.signed_by
            })
            .unwrap()
    }

    pub fn local_ca(&self) -> &AuthlyCert {
        self.certs
            .iter()
            .find(|cert| {
                matches!(cert.kind, AuthlyCertKind::Ca) && cert.certifies == self.authly_id.eid
            })
            .unwrap()
    }

    /// NB: local CA might be an intermediate cert
    pub fn sign_with_local_ca<'a, K: PublicKeyData>(
        &self,
        request: SigningRequest<'a, K>,
    ) -> Cert<'a, K> {
        let local_ca = self.local_ca();

        let certificate = request
            .params
            .signed_by(request.key.deref(), &local_ca.params, self.private_key())
            .unwrap();

        Cert {
            params: certificate.params().clone(),
            der: certificate.der().clone(),
            key: request.key,
        }
    }
}
