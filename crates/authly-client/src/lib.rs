use authly_proto::service as proto;
use authly_proto::service::authly_service_client::AuthlyServiceClient;
use http::header::AUTHORIZATION;
use pem::{EncodeConfig, Pem};
use rcgen::KeyPair;

const K8S_SA_TOKENFILE: &str = "/var/run/secrets/kubernetes.io/serviceaccount/token";

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("private key gen error")]
    PrivateKeyGen,

    #[error("environment not inferrable")]
    EnvironmentNotInferrable,

    #[error("authly CA not found")]
    AuthlyLocalCaNotFound,

    #[error("unauthorized")]
    Unauthorized(anyhow::Error),

    #[error("network error")]
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

impl Client {
    pub async fn infer() -> Result<Self, Error> {
        let key_pair = KeyPair::generate().map_err(|_err| Error::PrivateKeyGen)?;

        if std::fs::exists(K8S_SA_TOKENFILE).unwrap_or(false) {
            let token = std::fs::read_to_string(K8S_SA_TOKENFILE).map_err(unclassified)?;
            let authly_local_ca = std::fs::read("/etc/authly/local-ca.crt")
                .map_err(|_| Error::AuthlyLocalCaNotFound)?;

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
            let client_cert = pem::encode_config(
                &Pem::new("CERTIFICATE", client_cert.to_vec()),
                EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
            );

            let tls_config = tonic::transport::ClientTlsConfig::new()
                .ca_certificate(tonic::transport::Certificate::from_pem(authly_local_ca))
                .identity(tonic::transport::Identity::from_pem(
                    client_cert,
                    key_pair.serialize_pem(),
                ));

            let endpoint = tonic::transport::Endpoint::from_shared("https://authly")
                .map_err(network)?
                .tls_config(tls_config)
                .map_err(network)?;

            Ok(Self {
                client: AuthlyServiceClient::new(endpoint.connect().await.map_err(unclassified)?),
            })
        } else {
            Err(Error::EnvironmentNotInferrable)
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
