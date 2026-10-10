//! A WebSocket to a Signal server, tunnelled through Tor.
//!
//! Stack: Tor stream -> rustls (TLS 1.3 only, trusting ONLY the supplied root CA)
//! -> async-tungstenite (WebSocket handshake + framing).

use crate::client::TorClient;
use crate::error::{Result, TorError};
use async_tungstenite::tungstenite::{self, client::IntoClientRequest, http::HeaderValue};
use async_tungstenite::WebSocketStream;
use futures_rustls::client::TlsStream;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{pem::PemObject, CertificateDer};
use std::sync::Arc;
use tor_proto::client::stream::DataStream;

pub use async_tungstenite::tungstenite::Message;

pub type SignalWebSocket = WebSocketStream<TlsStream<DataStream>>;

/// TLS config that trusts exactly the root(s) in `root_pem` and nothing else.
pub fn pinned_tls_config(root_pem: &str) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(root_pem.as_bytes()) {
        let cert = cert.map_err(|e| TorError::tls(format!("invalid root PEM: {}", e)))?;
        roots
            .add(cert)
            .map_err(|e| TorError::tls(format!("invalid root certificate: {}", e)))?;
    }
    if roots.is_empty() {
        return Err(TorError::tls("no root certificate supplied"));
    }

    let mut config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|e| TorError::tls(format!("TLS config: {}", e)))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    // WebSocket upgrades require HTTP/1.1
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Open a WebSocket through Tor. Returns `Err(status)` inside `Ok` when the server
/// answers the upgrade with a non-101 HTTP status (e.g. 401 for bad credentials).
pub async fn open(
    client: &TorClient,
    url: &str,
    root_pem: &str,
    authorization: Option<&str>,
) -> Result<std::result::Result<SignalWebSocket, u16>> {
    let mut request = url
        .into_client_request()
        .map_err(|e| TorError::http_request(format!("invalid URL {}: {}", url, e)))?;
    let headers = request.headers_mut();
    headers.insert(
        "User-Agent",
        HeaderValue::from_static("unofficial-web-client/0.1"),
    );
    if let Some(value) = authorization {
        let value = HeaderValue::from_str(value)
            .map_err(|e| TorError::http_request(format!("invalid Authorization: {}", e)))?;
        headers.insert("Authorization", value);
    }

    let host = request
        .uri()
        .host()
        .ok_or_else(|| TorError::http_request("URL has no host"))?
        .to_string();
    let port = request.uri().port_u16().unwrap_or(443);

    let tls = client
        .open_tls(&host, port, pinned_tls_config(root_pem)?)
        .await?;

    match async_tungstenite::client_async(request, tls).await {
        Ok((ws, _response)) => Ok(Ok(ws)),
        Err(tungstenite::Error::Http(response)) => Ok(Err(response.status().as_u16())),
        Err(e) => Err(TorError::network(format!("WebSocket handshake failed: {}", e))),
    }
}
