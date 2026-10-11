//! HTTPS requests to Signal hosts (storage service, CDNs, ...) through Tor.
//!
//! hyper's HTTP/1.1 client connection over rustls (TLS 1.3, trusting only the
//! root passed per request) over a carrier stream. Idle keep-alive
//! connections are kept per (host, port, root) and reused, like Node's HTTPS
//! agent does for Desktop.

use crate::error::{Result, TorError};
use crate::signal_socket::{connect_tls, pinned_tls_config, Carrier, HeaderList};
use crate::time::Instant;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use std::cell::RefCell;
use std::collections::HashMap;
use std::time::Duration;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, warn};

/// Idle connections are dropped after this long (servers close them anyway).
const IDLE_TIMEOUT: Duration = Duration::from_secs(50);
const MAX_IDLE_PER_KEY: usize = 4;

pub struct HttpsRequest {
    pub method: String,
    /// Absolute https:// URL.
    pub url: String,
    pub headers: HeaderList,
    pub body: Option<Vec<u8>>,
    pub root_pem: String,
    /// Covers connecting, sending and receiving the whole response.
    pub timeout: Duration,
    /// Larger response bodies fail the request.
    pub max_response_bytes: usize,
}

pub struct HttpsResponse {
    pub status: u16,
    pub headers: HeaderList,
    pub body: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    host: String,
    port: u16,
    root_pem: String,
}

struct IdleConnection {
    sender: SendRequest<Full<Bytes>>,
    idle_since: Instant,
}

/// An HTTPS client over one carrier. Create a new one when the carrier is
/// replaced (e.g. a new Tor client), so that no connection outlives it.
pub struct SignalHttpsClient {
    carrier: Carrier,
    idle: RefCell<HashMap<PoolKey, Vec<IdleConnection>>>,
}

impl SignalHttpsClient {
    pub fn new(carrier: Carrier) -> Self {
        Self {
            carrier,
            idle: RefCell::new(HashMap::new()),
        }
    }

    /// Drops every idle connection.
    pub fn clear(&self) {
        self.idle.borrow_mut().clear();
    }

    fn take_idle(&self, key: &PoolKey) -> Option<SendRequest<Full<Bytes>>> {
        let mut idle = self.idle.borrow_mut();
        let list = idle.get_mut(key)?;
        while let Some(connection) = list.pop() {
            if connection.idle_since.elapsed() < IDLE_TIMEOUT
                && !connection.sender.is_closed()
                && connection.sender.is_ready()
            {
                return Some(connection.sender);
            }
        }
        None
    }

    fn put_idle(&self, key: PoolKey, sender: SendRequest<Full<Bytes>>) {
        if sender.is_closed() {
            return;
        }
        let mut idle = self.idle.borrow_mut();
        let list = idle.entry(key).or_default();
        list.retain(|c| c.idle_since.elapsed() < IDLE_TIMEOUT && !c.sender.is_closed());
        if list.len() < MAX_IDLE_PER_KEY {
            list.push(IdleConnection {
                sender,
                idle_since: Instant::now(),
            });
        }
    }

    async fn connect(&self, key: &PoolKey) -> Result<SendRequest<Full<Bytes>>> {
        let config = pinned_tls_config(&key.root_pem)?;
        let tls = connect_tls(&self.carrier, &key.host, key.port, config).await?;
        let (sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls.compat()))
                .await
                .map_err(|e| TorError::network(format!("HTTP handshake failed: {}", e)))?;
        let host = key.host.clone();
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = connection.await {
                debug!("HTTPS connection to {} ended: {}", host, e);
            }
        });
        Ok(sender)
    }

    pub async fn request(&self, request: HttpsRequest) -> Result<HttpsResponse> {
        let timeout = request.timeout;
        crate::retry::with_timeout(timeout, "HTTPS request", self.request_inner(request)).await
    }

    async fn request_inner(&self, request: HttpsRequest) -> Result<HttpsResponse> {
        let url = url::Url::parse(&request.url)
            .map_err(|e| TorError::http_request(format!("invalid URL: {}", e)))?;
        if url.scheme() != "https" {
            return Err(TorError::http_request("only https:// URLs are supported"));
        }
        let host = url
            .host_str()
            .ok_or_else(|| TorError::http_request("URL has no host"))?
            .to_string();
        let port = url.port().unwrap_or(443);
        let key = PoolKey {
            host: host.clone(),
            port,
            root_pem: request.root_pem.clone(),
        };
        let path_and_query = match url.query() {
            Some(query) => format!("{}?{}", url.path(), query),
            None => url.path().to_string(),
        };
        let method = hyper::Method::from_bytes(request.method.as_bytes())
            .map_err(|_| TorError::http_request("invalid HTTP method"))?;
        let host_header = if port == 443 {
            host.clone()
        } else {
            format!("{}:{}", host, port)
        };
        let body = Bytes::from(request.body.unwrap_or_default());

        let build = || -> Result<hyper::Request<Full<Bytes>>> {
            let mut builder = hyper::Request::builder()
                .method(method.clone())
                .uri(path_and_query.as_str());
            let has_host = request
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("host"));
            if !has_host {
                builder = builder.header(hyper::header::HOST, host_header.as_str());
            }
            for (name, value) in &request.headers {
                builder = builder.header(name.as_str(), value.as_str());
            }
            builder
                .body(Full::new(body.clone()))
                .map_err(|e| TorError::http_request(format!("invalid request: {}", e)))
        };

        // A reused keep-alive connection may have been closed by the server
        // just before we sent on it; then retry once on a fresh connection,
        // if the request was never sent or is safe to repeat.
        let idempotent = matches!(method, hyper::Method::GET | hyper::Method::HEAD);
        let mut reused = self.take_idle(&key);
        loop {
            let was_reused = reused.is_some();
            let mut sender = match reused.take() {
                Some(sender) => sender,
                None => self.connect(&key).await?,
            };
            if sender.ready().await.is_err() {
                if was_reused {
                    continue;
                }
                return Err(TorError::network("HTTPS connection closed"));
            }
            let response = match sender.send_request(build()?).await {
                Ok(response) => response,
                Err(e)
                    if was_reused
                        && (e.is_canceled() || (idempotent && e.is_incomplete_message())) =>
                {
                    warn!(
                        "reused HTTPS connection to {} failed ({}), retrying",
                        host, e
                    );
                    continue;
                }
                Err(e) => return Err(TorError::network(format!("HTTPS request failed: {}", e))),
            };

            let status = response.status().as_u16();
            let headers = response
                .headers()
                .iter()
                .filter_map(|(name, value)| {
                    value
                        .to_str()
                        .ok()
                        .map(|value| (name.as_str().to_string(), value.to_string()))
                })
                .collect();
            let body = Limited::new(response.into_body(), request.max_response_bytes)
                .collect()
                .await
                .map_err(|e| TorError::network(format!("HTTPS response body: {}", e)))?
                .to_bytes()
                .to_vec();
            self.put_idle(key, sender);
            return Ok(HttpsResponse {
                status,
                headers,
                body,
            });
        }
    }
}
