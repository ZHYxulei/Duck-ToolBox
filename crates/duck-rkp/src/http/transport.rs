use std::time::Duration;

use anyhow::{Result, ensure};
use ciborium::value::Value;
use reqwest::{Client, Response, Url, redirect::Policy};

use crate::{
    cbor::{encode, int, text},
    error::RkpError,
};

const MAX_RESPONSE: usize = 1024 * 1024;

pub fn validate_endpoint(value: &str) -> Result<()> {
    let url = Url::parse(value).map_err(|_| RkpError::InvalidEndpoint)?;
    let loopback = matches!(url.host_str(), Some("127.0.0.1" | "[::1]" | "localhost"));
    ensure!(
        (url.scheme() == "https" || (url.scheme() == "http" && loopback))
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        RkpError::InvalidEndpoint
    );
    Ok(())
}

pub fn rkp_client() -> Result<Client> {
    let builder = Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        .redirect(Policy::none())
        .retry(reqwest::retry::never());
    let builder = if cfg!(target_os = "android") {
        builder.tls_backend_preconfigured(duck_platform::net::embedded_rustls_config())
    } else {
        builder
    };
    Ok(builder.build()?)
}

pub async fn fetch_challenge(
    client: &Client,
    fingerprint: &str,
    server_url: &str,
) -> Result<Vec<u8>> {
    validate_endpoint(server_url)?;
    let payload = encode(&Value::Map(vec![
        (text("fingerprint"), text(fingerprint)),
        (text("id"), int(42)),
    ]))?;
    let response = client
        .post(format!("{server_url}:fetchEekChain"))
        .header("Content-Type", "application/cbor")
        .header("Accept", "application/cbor")
        .body(payload)
        .send()
        .await
        .map_err(|_| RkpError::ChallengeUnavailable)?;
    let status = response.status();
    let body = read_body(response, false).await?;
    if !status.is_success() {
        return Err(super::map_http_error(status, &body).into());
    }
    super::parse_challenge_response(&body)
}

pub(super) async fn read_body(mut response: Response, submitted: bool) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| {
        if submitted {
            RkpError::SubmissionUnknown
        } else {
            RkpError::ChallengeUnavailable
        }
    })? {
        ensure!(
            bytes.len().saturating_add(chunk.len()) <= MAX_RESPONSE,
            RkpError::InvalidRkpResponse("response exceeds size limit".into())
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}
