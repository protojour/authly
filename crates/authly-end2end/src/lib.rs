#![allow(unused)]

use hyper::header::SET_COOKIE;
use reqwest::Identity;

mod test_auth_access_control;
mod test_service;

struct ConnectionBuilder(authly_client::ClientBuilder);

impl ConnectionBuilder {
    fn for_testservice() -> anyhow::Result<Self> {
        Ok(Self(
            authly_client::Client::builder()
                .with_url("https://localhost:1443")
                .with_authly_local_ca_pem(std::fs::read("../../.local/etc/local/ca.crt")?)?
                .with_identity(authly_client::identity::Identity::from_pem(std::fs::read(
                    "../../.local/etc/service/f3e799137c034e1eb4cd3e4f65705932/identity.pem",
                )?)?),
        ))
    }

    /// Make a http client
    fn http_client(&self) -> anyhow::Result<reqwest::Client> {
        Ok(reqwest::Client::builder()
            .add_root_certificate(reqwest::tls::Certificate::from_pem(
                &self.0.get_local_ca_pem()?,
            )?)
            .identity(reqwest::Identity::from_pem(&self.0.get_identity_pem()?)?)
            .build()?)
    }

    /// Make a authly-service client
    async fn service_client(self) -> anyhow::Result<authly_client::Client> {
        Ok(self.0.connect().await?)
    }
}

fn reqwest_cookie(response: &reqwest::Response) {
    let cookie = response.headers().get_all(SET_COOKIE);
}

fn is_allowed(outcome: bool) -> bool {
    outcome
}

fn is_denied(outcome: bool) -> bool {
    !outcome
}
