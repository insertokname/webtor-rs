//! HTTPS requests to Signal hosts (storage service, CDNs, ...) through Tor.
//!
//! hyper's HTTP/1.1 client connection over rustls (TLS 1.3, trusting only the
//! root passed per request) over a carrier stream. Idle keep-alive
//! connections are kept per (host, port, root) and reused, like Node's HTTPS
//! agent does for Desktop.
//!
//! Response bodies are streamed: [`HttpsBody::next`] yields the body piece by
//! piece as it arrives, each piece within an idle timeout, so large downloads
//! neither sit in memory nor need a deadline for the whole transfer. Request
//! bodies can be streamed too ([`RequestBody::Stream`], e.g. uploads): pieces
//! are pulled as the connection takes them, and the request's timeout then
//! bounds each wait (connecting, the next piece being taken, the response
//! head after the last piece) instead of the whole upload. A
//! connection whose request or body is abandoned (error, timeout, cancel,
//! drop) is aborted: its task ends and the TLS and carrier streams are
//! dropped, so a hung connection never lingers.

use crate::error::{Result, TorError};
use crate::signal_socket::{connect_tls, pinned_tls_config, Carrier, HeaderList};
use crate::time::Instant;
pub use bytes::Bytes;
use futures::future::{AbortHandle, Abortable};
use futures::stream::LocalBoxStream;
use futures::StreamExt;
use http_body_util::BodyExt;
use hyper::body::{Frame, Incoming, SizeHint};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::cell::Cell;
use hyper::client::conn::http1::SendRequest;
use hyper_util::rt::TokioIo;
use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;
use tokio_util::compat::FuturesAsyncReadCompatExt;
use tracing::{debug, warn};

/// Idle connections are dropped after this long (servers close them anyway).
const IDLE_TIMEOUT: Duration = Duration::from_secs(50);
const MAX_IDLE_PER_KEY: usize = 4;

/// A request body: none, in memory, or pulled piece by piece.
pub enum RequestBody {
    Bytes(Vec<u8>),
    Stream(LocalBoxStream<'static, Result<Bytes>>),
}

pub struct HttpsRequest {
    pub method: String,
    /// Absolute https:// URL.
    pub url: String,
    pub headers: HeaderList,
    pub body: Option<RequestBody>,
    pub root_pem: String,
    /// Covers connecting, sending the request and receiving the response
    /// head; with a streamed body, each of those waits instead (see the
    /// module documentation). The response body has its own idle timeout
    /// (see [`HttpsBody::next`]).
    pub timeout: Duration,
}

/// What hyper sends: a body in memory, or pieces pulled from a stream (not
/// `Send`: on wasm the pieces come from JavaScript).
enum OutgoingBody {
    Full(Option<Bytes>),
    Stream(LocalBoxStream<'static, Result<Bytes>>),
}

impl hyper::body::Body for OutgoingBody {
    type Data = Bytes;
    type Error = TorError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>>>> {
        match self.get_mut() {
            OutgoingBody::Full(bytes) => {
                Poll::Ready(bytes.take().filter(|b| !b.is_empty()).map(|b| Ok(Frame::data(b))))
            }
            OutgoingBody::Stream(stream) => stream
                .poll_next_unpin(cx)
                .map(|piece| piece.map(|piece| piece.map(Frame::data))),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            OutgoingBody::Full(bytes) => bytes.as_ref().is_none_or(|b| b.is_empty()),
            OutgoingBody::Stream(_) => false,
        }
    }

    fn size_hint(&self) -> SizeHint {
        match self {
            OutgoingBody::Full(bytes) => SizeHint::with_exact(bytes.as_ref().map_or(0, |b| b.len() as u64)),
            OutgoingBody::Stream(_) => SizeHint::default(),
        }
    }
}

pub struct HttpsResponse {
    pub status: u16,
    pub headers: HeaderList,
    pub body: HttpsBody,
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct PoolKey {
    host: String,
    port: u16,
    root_pem: String,
}

/// One HTTP/1.1 connection: the request handle and the means to end its task.
struct Connection {
    sender: SendRequest<OutgoingBody>,
    abort: AbortHandle,
}

impl Connection {
    fn usable(&self) -> bool {
        !self.sender.is_closed() && !self.abort.is_aborted()
    }
}

struct IdleConnection {
    connection: Connection,
    idle_since: Instant,
}

#[derive(Default)]
struct Pool {
    idle: HashMap<PoolKey, Vec<IdleConnection>>,
}

impl Pool {
    fn take(&mut self, key: &PoolKey) -> Option<Connection> {
        let list = self.idle.get_mut(key)?;
        while let Some(idle) = list.pop() {
            if idle.idle_since.elapsed() < IDLE_TIMEOUT
                && idle.connection.usable()
                && idle.connection.sender.is_ready()
            {
                return Some(idle.connection);
            }
            idle.connection.abort.abort();
        }
        None
    }

    fn put(&mut self, key: PoolKey, connection: Connection) {
        if !connection.usable() {
            connection.abort.abort();
            return;
        }
        let list = self.idle.entry(key).or_default();
        list.retain(|idle| {
            let keep = idle.idle_since.elapsed() < IDLE_TIMEOUT && idle.connection.usable();
            if !keep {
                idle.connection.abort.abort();
            }
            keep
        });
        if list.len() < MAX_IDLE_PER_KEY {
            list.push(IdleConnection {
                connection,
                idle_since: Instant::now(),
            });
        } else {
            connection.abort.abort();
        }
    }

    fn clear(&mut self) {
        for (_, list) in self.idle.drain() {
            for idle in list {
                idle.connection.abort.abort();
            }
        }
    }
}

/// A response body being received. Dropping it before the end aborts the
/// connection; reading it to the end returns the connection to the pool.
pub struct HttpsBody {
    incoming: Option<Incoming>,
    connection: Option<Connection>,
    /// Aborts the connection; also tells a cut-off body from a complete one.
    abort: AbortHandle,
    pool: Rc<RefCell<Pool>>,
    key: PoolKey,
    /// Content-Length, when the response has a body of that length.
    expected: Option<u64>,
    received: u64,
}

impl HttpsBody {
    /// The next piece of the body, `None` at its end. Fails if nothing
    /// arrives within `idle` (the connection is then aborted).
    pub async fn next(&mut self, idle: Duration) -> Result<Option<Bytes>> {
        loop {
            let Some(incoming) = self.incoming.as_mut() else {
                return Ok(None);
            };
            let frame = crate::retry::with_timeout(idle, "HTTPS response body", async {
                incoming
                    .frame()
                    .await
                    .transpose()
                    .map_err(|e| TorError::network(format!("HTTPS response body: {}", e)))
            })
            .await;
            match frame {
                Ok(Some(frame)) => {
                    if let Ok(data) = frame.into_data() {
                        if !data.is_empty() {
                            self.received += data.len() as u64;
                            return Ok(Some(data));
                        }
                    }
                }
                // hyper ends the body quietly when its connection task is
                // gone (aborted): that is not the end of the response.
                Ok(None) if self.abort.is_aborted() => {
                    self.cancel();
                    return Err(TorError::network("HTTPS response body: connection aborted"));
                }
                Ok(None) if self.expected.is_some_and(|expected| expected != self.received) => {
                    let expected = self.expected.unwrap_or_default();
                    self.cancel();
                    return Err(TorError::network(format!(
                        "HTTPS response body: got {} of {} bytes",
                        self.received, expected
                    )));
                }
                Ok(None) => {
                    self.incoming = None;
                    if let Some(connection) = self.connection.take() {
                        self.pool.borrow_mut().put(self.key.clone(), connection);
                    }
                    return Ok(None);
                }
                Err(e) => {
                    self.cancel();
                    return Err(e);
                }
            }
        }
    }

    /// Aborts the connection from outside (e.g. while `next` is pending,
    /// which then fails).
    pub fn abort_handle(&self) -> AbortHandle {
        self.abort.clone()
    }

    /// Stops receiving: the connection is aborted (unless the body was complete).
    pub fn cancel(&mut self) {
        self.incoming = None;
        if let Some(connection) = self.connection.take() {
            connection.abort.abort();
        }
    }
}

impl Drop for HttpsBody {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// Runs `future` until it completes, failing if `progress` (a time the
/// future keeps moving forward) falls `timeout` behind.
async fn with_idle_timeout<F, T>(
    timeout: Duration,
    operation_name: &str,
    progress: &Cell<Instant>,
    future: F,
) -> Result<T>
where
    F: std::future::Future<Output = Result<T>>,
{
    use futures::future::{select, Either};

    let mut future = std::pin::pin!(future);
    loop {
        let idle = progress.get().elapsed();
        if idle >= timeout {
            return Err(TorError::timeout(format!(
                "{} made no progress for {:?}",
                operation_name, timeout
            )));
        }
        let sleep = std::pin::pin!(crate::retry::sleep(timeout - idle));
        match select(future.as_mut(), sleep).await {
            Either::Left((result, _)) => return result,
            Either::Right(((), _)) => continue,
        }
    }
}

/// An HTTPS client over one carrier. Create a new one when the carrier is
/// replaced (e.g. a new Tor client), so that no connection outlives it.
pub struct SignalHttpsClient {
    carrier: Carrier,
    pool: Rc<RefCell<Pool>>,
}

impl SignalHttpsClient {
    pub fn new(carrier: Carrier) -> Self {
        Self {
            carrier,
            pool: Rc::new(RefCell::new(Pool::default())),
        }
    }

    /// Drops (and aborts) every idle connection.
    pub fn clear(&self) {
        self.pool.borrow_mut().clear();
    }

    async fn connect(&self, key: &PoolKey) -> Result<Connection> {
        let config = pinned_tls_config(&key.root_pem)?;
        let tls = connect_tls(&self.carrier, &key.host, key.port, config).await?;
        let (sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls.compat()))
                .await
                .map_err(|e| TorError::network(format!("HTTP handshake failed: {}", e)))?;
        let (abort, registration) = AbortHandle::new_pair();
        let host = key.host.clone();
        wasm_bindgen_futures::spawn_local(async move {
            match Abortable::new(connection, registration).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => debug!("HTTPS connection to {} ended: {}", host, e),
                Err(_) => debug!("HTTPS connection to {} aborted", host),
            }
        });
        Ok(Connection { sender, abort })
    }

    /// Sends the request; resolves once the response head arrived (within
    /// `request.timeout`), with the body still to be read.
    pub async fn request(&self, request: HttpsRequest) -> Result<HttpsResponse> {
        let timeout = request.timeout;
        // The connection in use, so that a timeout can abort it.
        let current: RefCell<Option<AbortHandle>> = RefCell::new(None);
        let streamed = matches!(request.body, Some(RequestBody::Stream(_)));
        let result = if streamed {
            // Progress: set when the request starts and whenever the
            // connection takes a piece of the body (or its end).
            let progress = Rc::new(Cell::new(Instant::now()));
            let inner = self.request_inner(request, &current, Some(progress.clone()));
            with_idle_timeout(timeout, "HTTPS request", &progress, inner).await
        } else {
            crate::retry::with_timeout(
                timeout,
                "HTTPS request",
                self.request_inner(request, &current, None),
            )
            .await
        };
        if result.is_err() {
            if let Some(abort) = current.borrow_mut().take() {
                abort.abort();
            }
        }
        result
    }

    async fn request_inner(
        &self,
        request: HttpsRequest,
        current: &RefCell<Option<AbortHandle>>,
        progress: Option<Rc<Cell<Instant>>>,
    ) -> Result<HttpsResponse> {
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
        // In memory: can be sent again (a retry on a fresh connection).
        // Streamed: sent once, on a fresh connection (no retry).
        let (bytes, mut stream) = match request.body {
            None => (Bytes::new(), None),
            Some(RequestBody::Bytes(bytes)) => (Bytes::from(bytes), None),
            Some(RequestBody::Stream(stream)) => (Bytes::new(), Some(stream)),
        };
        let streamed = stream.is_some();

        let mut build = || -> Result<hyper::Request<OutgoingBody>> {
            let body: OutgoingBody = match stream.take() {
                Some(stream) => {
                    // Every piece taken, and the end, is progress.
                    let progress = progress.clone();
                    let pieces = stream
                        .map(Some)
                        .chain(futures::stream::once(async { None }))
                        .filter_map(move |piece| {
                            if let Some(progress) = &progress {
                                progress.set(Instant::now());
                            }
                            async move { piece }
                        });
                    OutgoingBody::Stream(pieces.boxed_local())
                }
                None if streamed => {
                    return Err(TorError::http_request(
                        "a streamed request body can only be sent once",
                    ))
                }
                None => OutgoingBody::Full(Some(bytes.clone())),
            };
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
                .body(body)
                .map_err(|e| TorError::http_request(format!("invalid request: {}", e)))
        };

        // A reused keep-alive connection may have been closed by the server
        // just before we sent on it; then retry once on a fresh connection,
        // if the request was never sent or is safe to repeat.
        let idempotent = matches!(method, hyper::Method::GET | hyper::Method::HEAD);
        let mut reused = if streamed {
            None
        } else {
            self.pool.borrow_mut().take(&key)
        };
        loop {
            let was_reused = reused.is_some();
            let mut connection = match reused.take() {
                Some(connection) => connection,
                None => self.connect(&key).await?,
            };
            *current.borrow_mut() = Some(connection.abort.clone());
            let fail = |connection: Connection| {
                connection.abort.abort();
                current.borrow_mut().take();
            };
            if connection.sender.ready().await.is_err() {
                fail(connection);
                if was_reused {
                    continue;
                }
                return Err(TorError::network("HTTPS connection closed"));
            }
            let response = match connection.sender.send_request(build()?).await {
                Ok(response) => response,
                Err(e)
                    if was_reused
                        && (e.is_canceled() || (idempotent && e.is_incomplete_message())) =>
                {
                    warn!(
                        "reused HTTPS connection to {} failed ({}), retrying",
                        host, e
                    );
                    fail(connection);
                    continue;
                }
                Err(e) => {
                    fail(connection);
                    return Err(TorError::network(format!("HTTPS request failed: {}", e)));
                }
            };
            current.borrow_mut().take();

            let status = response.status().as_u16();
            let has_body = method != hyper::Method::HEAD
                && !matches!(status, 100..=199 | 204 | 304)
                && !response.headers().contains_key(hyper::header::TRANSFER_ENCODING);
            let expected = response
                .headers()
                .get(hyper::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse::<u64>().ok())
                .filter(|_| has_body);
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
            return Ok(HttpsResponse {
                status,
                headers,
                body: HttpsBody {
                    incoming: Some(response.into_body()),
                    abort: connection.abort.clone(),
                    connection: Some(connection),
                    pool: self.pool.clone(),
                    key,
                    expected,
                    received: 0,
                },
            });
        }
    }
}
