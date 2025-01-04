use std::borrow::Cow;

use authly_proto::service as proto;
use authly_proto::service::authly_service_client::AuthlyServiceClient;
use http::header::AUTHORIZATION;
use identity::Identity;
use pem::{EncodeConfig, Pem};
use rcgen::KeyPair;

pub mod identity;

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

    #[error("unclassified error: {0}")]
    Unclassified(anyhow::Error),
}

fn unclassified(err: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Unclassified(anyhow::Error::from(err))
}

fn network(err: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Unauthorized(anyhow::Error::from(err))
}

fn unauthorized(err: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Unauthorized(anyhow::Error::from(err))
}

pub struct Client {
    client: AuthlyServiceClient<tonic::transport::Channel>,
}

pub struct ClientBuilder {
    authly_local_ca: Option<Vec<u8>>,
    identity: Option<Identity>,
    url: Cow<'static, str>,
}

impl Client {
    pub fn builder() -> ClientBuilder {
        ClientBuilder {
            authly_local_ca: None,
            identity: None,
            url: Cow::Borrowed("https://authly"),
        }
    }

    /// The eid of this client
    pub async fn eid(&self) -> Result<String, Error> {
        let mut client = self.client.clone();
        let metadata = client
            .metadata(proto::Empty::default())
            .await
            .map_err(network)?
            .into_inner();

        Ok(metadata.eid)
    }

    /// The name of this client
    pub async fn name(&self) -> Result<String, Error> {
        let mut client = self.client.clone();
        let metadata = client
            .metadata(proto::Empty::default())
            .await
            .map_err(network)?
            .into_inner();

        Ok(metadata.name)
    }
}

impl ClientBuilder {
    /// Infer the Authly client from the environment it runs in.
    pub async fn from_environment(mut self) -> Result<Self, Error> {
        let key_pair = KeyPair::generate().map_err(|_err| Error::PrivateKeyGen)?;

        if std::fs::exists(K8S_SA_TOKENFILE).unwrap_or(false) {
            let token = std::fs::read_to_string(K8S_SA_TOKENFILE).map_err(unclassified)?;
            let authly_local_ca = std::fs::read("/etc/authly/local-ca.crt")
                .map_err(|_| Error::AuthlyCA("not mounted"))?;

            let client_cert = reqwest::ClientBuilder::new()
                .add_root_certificate(
                    reqwest::Certificate::from_pem(&authly_local_ca).map_err(unclassified)?,
                )
                .build()
                .map_err(unclassified)?
                .post("https://authly-k8s/api/csr")
                .body(key_pair.public_key_der())
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .send()
                .await
                .map_err(unauthorized)?
                .error_for_status()
                .map_err(unauthorized)?
                .bytes()
                .await
                .map_err(unclassified)?;
            let client_cert_pem = pem::encode_config(
                &Pem::new("CERTIFICATE", client_cert.to_vec()),
                EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            );

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
    pub fn with_authly_local_ca_pem(mut self, ca: Vec<u8>) -> Self {
        self.authly_local_ca = Some(ca);
        self
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
            .map_err(network)?
            .tls_config(tls_config)
            .map_err(network)?;

        Ok(Client {
            client: AuthlyServiceClient::new(endpoint.connect().await.map_err(unclassified)?),
        })
    }
}
