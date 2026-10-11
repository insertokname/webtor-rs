//! Connections to Signal servers, tunnelled through Tor.
//!
//! Stack: carrier stream (a Tor stream) -> rustls (TLS 1.3 only, trusting
//! ONLY the supplied root CA) -> async-tungstenite (WebSocket) or hyper
//! (HTTP/1.1, see [`crate::signal_https`]).
//!
//! The carrier is the seam for tests: everything above it works on any
//! `AsyncRead + AsyncWrite` byte stream, so a test build can put TLS on top of
//! something other than a Tor stream (e.g. a WebSocket to a local relay in
//! front of a mock server) without touching the TLS or protocol layers.

use crate::client::TorClient;
use crate::error::{Result, TorError};
use async_tungstenite::tungstenite::{
    self,
    client::IntoClientRequest,
    http::{HeaderName, HeaderValue},
};
use async_tungstenite::WebSocketStream;
use futures::{AsyncRead, AsyncWrite};
use futures_rustls::client::TlsStream;
use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::{pem::PemObject, CertificateDer};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

pub use async_tungstenite::tungstenite::protocol::{frame::coding::CloseCode, CloseFrame};
pub use async_tungstenite::tungstenite::Message;

/// A byte stream TLS runs over.
pub trait CarrierStream: AsyncRead + AsyncWrite + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Unpin + 'static> CarrierStream for T {}

pub type BoxedCarrierStream = Pin<Box<dyn CarrierStream>>;
pub type SignalTlsStream = TlsStream<BoxedCarrierStream>;
pub type SignalWebSocket = WebSocketStream<SignalTlsStream>;

/// Where TLS connections are carried. Production uses Tor only.
#[derive(Clone)]
pub enum Carrier {
    Tor(Arc<TorClient>),
    /// Tests only (feature `test-relay`, never in production builds): a
    /// WebSocket to a local relay, `<relay url>?host=<host>&port=<port>`,
    /// that forwards the bytes to a mock server. TLS still runs end to end
    /// on top, pinned to the root the caller supplies.
    #[cfg(feature = "test-relay")]
    Relay(String),
}

impl Carrier {
    /// Opens a byte stream to `host:port` (the exit relay resolves the name).
    pub async fn connect(&self, host: &str, port: u16) -> Result<BoxedCarrierStream> {
        match self {
            Carrier::Tor(client) => Ok(Box::pin(client.open_stream(host, port).await?)),
            #[cfg(feature = "test-relay")]
            Carrier::Relay(relay) => {
                let mut url = url::Url::parse(relay)
                    .map_err(|e| TorError::Network(format!("invalid relay URL: {}", e)))?;
                url.query_pairs_mut()
                    .append_pair("host", host)
                    .append_pair("port", &port.to_string());
                Ok(Box::pin(
                    crate::websocket::WebSocketStream::connect(url.as_str()).await?,
                ))
            }
        }
    }
}

/// HTTP header list as sent and received at the JS boundary.
pub type HeaderList = Vec<(String, String)>;

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
    // WebSocket upgrades and our HTTP client both speak HTTP/1.1
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(Arc::new(config))
}

/// Opens a TLS connection to `host:port` over `carrier`.
pub async fn connect_tls(
    carrier: &Carrier,
    host: &str,
    port: u16,
    config: Arc<ClientConfig>,
) -> Result<SignalTlsStream> {
    let stream = carrier.connect(host, port).await?;
    let server_name = rustls_pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| TorError::tls(format!("invalid server name {}: {}", host, e)))?;
    futures_rustls::TlsConnector::from(config)
        .connect(server_name, stream)
        .await
        .map_err(|e| TorError::tls(format!("TLS with {} failed: {}", host, e)))
}

/// Result of a WebSocket upgrade request.
pub enum Upgrade {
    /// The server switched protocols; `headers` are the 101 response's.
    Open {
        socket: SignalWebSocket,
        headers: HeaderList,
    },
    /// The server answered with another status (e.g. 403, 429, 499).
    Refused { status: u16, headers: HeaderList },
}

fn header_list(headers: &tungstenite::http::HeaderMap) -> HeaderList {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_string(), value.to_string()))
        })
        .collect()
}

/// Opens a WebSocket to `url` (wss://host/path) over `carrier`, sending
/// `headers` with the upgrade request. Everything up to the end of the
/// handshake must finish within `timeout`.
pub async fn open(
    carrier: &Carrier,
    url: &str,
    root_pem: &str,
    headers: &[(String, String)],
    timeout: Duration,
) -> Result<Upgrade> {
    let mut request = url
        .into_client_request()
        .map_err(|e| TorError::http_request(format!("invalid URL: {}", e)))?;
    for (name, value) in headers {
        let name = HeaderName::from_bytes(name.as_bytes())
            .map_err(|e| TorError::http_request(format!("invalid header name: {}", e)))?;
        let value = HeaderValue::from_str(value)
            .map_err(|_| TorError::http_request(format!("invalid value for header {}", name)))?;
        request.headers_mut().insert(name, value);
    }

    let host = request
        .uri()
        .host()
        .ok_or_else(|| TorError::http_request("URL has no host"))?
        .to_string();
    let port = request.uri().port_u16().unwrap_or(443);
    let config = pinned_tls_config(root_pem)?;

    crate::retry::with_timeout(timeout, "WebSocket connect", async move {
        let tls = connect_tls(carrier, &host, port, config).await?;
        match async_tungstenite::client_async(request, tls).await {
            Ok((socket, response)) => Ok(Upgrade::Open {
                socket,
                headers: header_list(response.headers()),
            }),
            Err(tungstenite::Error::Http(response)) => Ok(Upgrade::Refused {
                status: response.status().as_u16(),
                headers: header_list(response.headers()),
            }),
            Err(e) => Err(TorError::network(format!(
                "WebSocket handshake failed: {}",
                e
            ))),
        }
    })
    .await
}
