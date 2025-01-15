#![allow(unused)]

use hyper::header::SET_COOKIE;
use reqwest::Identity;

mod test_auth_access_control;
mod test_service;
mod test_tls;

fn testservice_web_client() -> anyhow::Result<reqwest::Client> {
    let client = reqwest::Client::builder()
        .add_root_certificate(reqwest::tls::Certificate::from_pem(&std::fs::read(
            "../../.local/exported-local-ca.pem",
        )?)?)
        .identity(reqwest::Identity::from_pem(&std::fs::read(
            "../../.local/testservice-identity.pem",
        )?)?)
        .build()?;

    Ok(client)
}

async fn testservice_authly_client() -> anyhow::Result<authly_client::Client> {
    Ok(authly_client::Client::builder()
        .with_url("https://localhost:10443")
        .with_authly_local_ca_pem(std::fs::read("../../.local/exported-local-ca.pem")?)?
        .with_identity(authly_client::identity::Identity::from_multi_pem(
            std::fs::read("../../.local/testservice-identity.pem")?,
        )?)
        .connect()
        .await?)
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
