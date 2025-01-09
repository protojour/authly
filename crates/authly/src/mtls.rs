use hyper::body::Incoming;
use x509_parser::prelude::{FromDer, X509Certificate};

/// A Request extension that stores the verified peer common name
#[derive(Clone)]
pub struct PeerSubjectCommonName(pub String);

/// A middleware for mTLS
#[derive(Clone)]
pub struct MTLSMiddleware;

#[derive(Default)]
pub struct MTLSConnectionData {
    peer_subject_common_name: Option<String>,
}

impl tower_server::tls::TlsConnectionMiddleware for MTLSMiddleware {
    type Data = Option<MTLSConnectionData>;

    fn data(&self, connection: &rustls::ServerConnection) -> Self::Data {
        let peer_der = connection.peer_certificates()?.first()?;
        let (_, peer_cert) = X509Certificate::from_der(&peer_der).ok()?;

        let mut data = MTLSConnectionData::default();

        for rdn in peer_cert.subject.iter() {
            for attr in rdn.iter() {
                if attr.attr_type() == &x509_parser::oid_registry::OID_X509_COMMON_NAME {
                    if let Ok(value) = attr.attr_value().as_str() {
                        data.peer_subject_common_name = Some(value.to_string());
                    }
                }
            }
        }

        Some(data)
    }

    fn call(&self, req: &mut axum::http::Request<Incoming>, data: &Self::Data) {
        let Some(data) = data else {
            return;
        };
        if let Some(peer_subject_common_name) = &data.peer_subject_common_name {
            req.extensions_mut()
                .insert(PeerSubjectCommonName(peer_subject_common_name.clone()));
        }
    }
}
