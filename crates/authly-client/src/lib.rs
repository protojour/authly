use std::borrow::Cow;

use authly_domain::{access_token::AuthlyAccessTokenClaims, Eid};
use authly_proto::service as proto;
use authly_proto::service::authly_service_client::AuthlyServiceClient;
use http::header::{AUTHORIZATION, COOKIE};
use identity::Identity;
use pem::{EncodeConfig, Pem};
use rcgen::KeyPair;
use token::AccessToken;
use tonic::Request;

pub mod identity;
pub mod token;

const K8S_SA_TOKENFILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("private key gen error")]
    PrivateKeyGen,

    #[error("Authly CA error: {0}")]
    AuthlyCA(&'static str),

    #[error("identity error: {0}")]
    Identity(&'static str),

    #[error("environment not inferrable")]
    EnvironmentNotInferrable,

    #[error("unauthorized: {0}")]
    Unauthorized(anyhow::Error),

    #[error("network error: {0}")]
    Network(anyhow::Error),

    #[error("invalid access token: {0}")]
    InvalidAccessToken(anyhow::Error),

    #[error("unclassified error: {0}")]
    Unclassified(anyhow::Error),
}

mod err {
    use super::*;

    pub fn unclassified(err: impl std::error::Error + Send + Sync + 'static) -> Error {
        Error::Unclassified(anyhow::Error::from(err))
    }

    pub fn tonic(err: tonic::Status) -> Error {
        match err.code() {
            tonic::Code::Unauthenticated => Error::Unauthorized(err.into()),
            tonic::Code::PermissionDenied => Error::Unauthorized(err.into()),
            _ => Error::Network(err.into()),
        }
    }

    pub fn network(err: impl std::error::Error + Send + Sync + 'static) -> Error {
        Error::Unauthorized(anyhow::Error::from(err))
    }

    pub fn unauthorized(err: impl std::error::Error + Send + Sync + 'static) -> Error {
        Error::Unauthorized(anyhow::Error::from(err))
    }
}

pub struct Client {
    client: AuthlyServiceClient<tonic::transport::Channel>,
    jwt_decoding_key: jsonwebtoken::DecodingKey,
}

pub struct ClientBuilder {
    authly_local_ca: Option<Vec<u8>>,
    identity: Option<Identity>,
    jwt_decoding_key: Option<jsonwebtoken::DecodingKey>,
    url: Cow<'static, str>,
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder {
            authly_local_ca: None,
            identity: None,
            jwt_decoding_key: None,
            url: Cow::Borrowed("https://authly"),
        }
    }

    /// The eid of this client
    pub async fn eid(&self) -> Result<String, Error> {
        let mut client = self.client.clone();
        let metadata = client
            .get_metadata(proto::Empty::default())
            .await
            .map_err(err::tonic)?
            .into_inner();

        Ok(metadata.eid)
    }

    /// The name of this client
    pub async fn label(&self) -> Result<String, Error> {
        let mut client = self.client.clone();
        let metadata = client
            .get_metadata(proto::Empty::default())
            .await
            .map_err(err::tonic)?
            .into_inner();

        Ok(metadata.label)
    }

    /// Exchange a session token for an access token suitable for evaluating access control.
    pub async fn get_access_token(&self, session_token: &str) -> Result<AccessToken, Error> {
        let mut client = self.client.clone();
        let mut request = Request::new(proto::Empty::default());

        // TODO: This should use Authorization instead of Cookie?
        request.metadata_mut().append(
            COOKIE.as_str(),
            format!("session-cookie={session_token}")
                .parse()
                .map_err(err::unclassified)?,
        );

        let proto = client
            .get_access_token(request)
            .await
            .map_err(err::tonic)?
            .into_inner();

        let validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::ES256);
        let token_data = jsonwebtoken::decode::<AuthlyAccessTokenClaims>(
            &proto.token,
            &self.jwt_decoding_key,
            &validation,
        )
        .map_err(|err| Error::InvalidAccessToken(err.into()))?;

        Ok(AccessToken {
            token: proto.token,
            claims: token_data.claims,
        })
    }

    pub async fn remote_access_control(
        &self,
        resource_attributes: impl IntoIterator<Item = Eid>,
        access_token: Option<&str>,
    ) -> Result<bool, Error> {
        let mut client = self.client.clone();
        let mut request = Request::new(proto::AccessControlRequest {
            resource_attributes: resource_attributes
                .into_iter()
                .map(|attr| attr.to_bytes().to_vec())
                .collect(),
        });
        if let Some(access_token) = access_token {
            request.metadata_mut().append(
                AUTHORIZATION.as_str(),
                format!("Bearer {access_token}")
                    .parse()
                    .map_err(err::unclassified)?,
            );
        }

        let access_control_response = client
            .access_control(request)
            .await
            .map_err(err::tonic)?
            .into_inner();

        Ok(access_control_response.outcome > 0)
    }
}

impl ClientBuilder {
    /// Infer the Authly client from the environment it runs in.
    pub async fn from_environment(mut self) -> Result<Self, Error> {
        let key_pair = KeyPair::generate().map_err(|_err| Error::PrivateKeyGen)?;

        if std::fs::exists(K8S_SA_TOKENFILE).unwrap_or(false) {
            let token = std::fs::read_to_string(K8S_SA_TOKENFILE).map_err(err::unclassified)?;
            let authly_local_ca = std::fs::read("/etc/authly/local-ca.crt")
                .map_err(|_| Error::AuthlyCA("not mounted"))?;

            let client_cert = reqwest::ClientBuilder::new()
                .add_root_certificate(
                    reqwest::Certificate::from_pem(&authly_local_ca).map_err(err::unclassified)?,
                )
                .build()
                .map_err(err::unclassified)?
                .post("https://authly-k8s/api/csr")
                .body(key_pair.public_key_der())
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .send()
                .await
                .map_err(err::unauthorized)?
                .error_for_status()
                .map_err(err::unauthorized)?
                .bytes()
                .await
                .map_err(err::unclassified)?;
            let client_cert_pem = pem::encode_config(
                &Pem::new("CERTIFICATE", client_cert.to_vec()),
                EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            );

            self.jwt_decoding_key = Some(jwt_decoding_key_from_cert(&authly_local_ca)?);
            self.authly_local_ca = Some(authly_local_ca);
            self.identity = Some(Identity {
                cert_pem: client_cert_pem.into_bytes(),
                key_pem: key_pair.serialize_pem().into_bytes(),
            });

            Ok(self)
        } else {
            Err(Error::EnvironmentNotInferrable)
        }
    }

    /// Use the given CA certificate to verify the Authly server
    pub fn with_authly_local_ca_pem(mut self, ca: Vec<u8>) -> Result<Self, Error> {
        self.jwt_decoding_key = Some(jwt_decoding_key_from_cert(&ca)?);
        self.authly_local_ca = Some(ca);
        Ok(self)
    }

    /// Use a pre-certified client identity
    pub fn with_identity(mut self, identity: Identity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// Override Authly URL (default is https://authly)
    pub fn with_url(mut self, url: impl Into<String>) -> Self {
        self.url = url.into().into();
        self
    }

    /// Connect to Authly
    pub async fn connect(self) -> Result<Client, Error> {
        let authly_local_ca = self
            .authly_local_ca
            .ok_or_else(|| Error::AuthlyCA("not provided"))?;
        let jwt_decoding_key = self
            .jwt_decoding_key
            .ok_or_else(|| Error::AuthlyCA("missing public key"))?;
        let identity = self
            .identity
            .ok_or_else(|| Error::Identity("not provided"))?;

        let tls_config = tonic::transport::ClientTlsConfig::new()
            .ca_certificate(tonic::transport::Certificate::from_pem(authly_local_ca))
            .identity(tonic::transport::Identity::from_pem(
                identity.cert_pem,
                identity.key_pem,
            ));

        let endpoint = tonic::transport::Endpoint::from_shared(self.url.to_string())
            .map_err(err::network)?
            .tls_config(tls_config)
            .map_err(err::network)?;

        Ok(Client {
            client: AuthlyServiceClient::new(endpoint.connect().await.map_err(err::unclassified)?),
            jwt_decoding_key,
        })
    }
}

fn jwt_decoding_key_from_cert(cert: &[u8]) -> Result<jsonwebtoken::DecodingKey, Error> {
    let pem = pem::parse(cert).map_err(|_| Error::AuthlyCA("invalid authly certificate"))?;

    let (_, x509_cert) = x509_parser::parse_x509_certificate(pem.contents())
        .map_err(|_| Error::AuthlyCA("invalid authly certificate"))?;

    let public_key = x509_cert.public_key();

    // Assume that EC is always used
    Ok(jsonwebtoken::DecodingKey::from_ec_der(
        &public_key.subject_public_key.data,
    ))
}
