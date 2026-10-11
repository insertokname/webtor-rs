//! SMUX (Simple MUltipleXing) protocol implementation
//!
//! SMUX provides stream multiplexing over a single connection.
//! This implements version 2 of the protocol.
//!
//! Segment format (8 bytes header + payload):
//! - Byte 0: version (must be 2)
//! - Byte 1: command (syn=0, fin=1, psh=2, nop=3, upd=4)
//! - Bytes 2-3: payload length (little-endian)
//! - Bytes 4-7: stream ID (little-endian)
//! - Bytes 8+: payload

use crate::error::{Result, TorError};
use futures::{AsyncRead, AsyncWrite, AsyncWriteExt};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};
use std::time::Duration;
use tracing::{debug, trace, warn};

/// SMUX protocol version
const SMUX_VERSION: u8 = 2;

/// Default stream ID
const DEFAULT_STREAM_ID: u32 = 3;

/// The peer's window until its first UPD (smux-go `initialPeerWindow`).
const INITIAL_PEER_WINDOW: u32 = 262144;

/// Largest data frame payload (smux-go default `MaxFrameSize`).
const MAX_FRAME_SIZE: usize = 32768;

/// NOP interval (smux-go default `KeepAliveInterval`).
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// Fail the session when the bridge, which sends a NOP every 10 s, has sent
/// nothing for this long.
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(60);

/// Receive window we advertise to the peer. 64 KB capped
/// throughput at ~64 KB per round trip, which is very slow through Tor.
const RECEIVE_WINDOW: u32 = 4 * 1024 * 1024;

/// Send a window update (UPD) after consuming this many
/// bytes. Must stay well below smux-go's initial peer window (256 KB), or the
/// sender stalls before our first update arrives.
const UPD_THRESHOLD: u32 = 32 * 1024;

/// SMUX commands
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum SmuxCommand {
    /// Stream open (SYN)
    Syn = 0,
    /// Stream close (FIN)
    Fin = 1,
    /// Push data (PSH)
    Psh = 2,
    /// No-op / ping (NOP)
    Nop = 3,
    /// Window update (UPD)
    Upd = 4,
}

impl TryFrom<u8> for SmuxCommand {
    type Error = TorError;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(SmuxCommand::Syn),
            1 => Ok(SmuxCommand::Fin),
            2 => Ok(SmuxCommand::Psh),
            3 => Ok(SmuxCommand::Nop),
            4 => Ok(SmuxCommand::Upd),
            _ => Err(TorError::Protocol(format!(
                "Invalid SMUX command: {}",
                value
            ))),
        }
    }
}

/// SMUX segment
#[derive(Debug, Clone)]
pub struct SmuxSegment {
    pub version: u8,
    pub command: SmuxCommand,
    pub stream_id: u32,
    pub data: Vec<u8>,
}

impl SmuxSegment {
    pub fn new(command: SmuxCommand, stream_id: u32, data: Vec<u8>) -> Self {
        Self {
            version: SMUX_VERSION,
            command,
            stream_id,
            data,
        }
    }

    pub fn syn(stream_id: u32) -> Self {
        Self::new(SmuxCommand::Syn, stream_id, Vec::new())
    }

    pub fn fin(stream_id: u32) -> Self {
        Self::new(SmuxCommand::Fin, stream_id, Vec::new())
    }

    pub fn psh(stream_id: u32, data: Vec<u8>) -> Self {
        Self::new(SmuxCommand::Psh, stream_id, data)
    }

    pub fn nop(stream_id: u32) -> Self {
        Self::new(SmuxCommand::Nop, stream_id, Vec::new())
    }

    pub fn upd(stream_id: u32, consumed: u32, window: u32) -> Self {
        let mut data = Vec::with_capacity(8);
        // smux-go uses little-endian for UPD payload
        data.extend_from_slice(&consumed.to_le_bytes());
        data.extend_from_slice(&window.to_le_bytes());
        Self::new(SmuxCommand::Upd, stream_id, data)
    }

    /// Encode segment to bytes
    /// Note: smux-go uses little-endian for length and stream_id
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.data.len());

        buf.push(self.version);
        buf.push(self.command as u8);
        buf.extend_from_slice(&(self.data.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.stream_id.to_le_bytes());
        buf.extend_from_slice(&self.data);

        buf
    }

    /// Decode segment from bytes, returns (segment, bytes_consumed)
    pub fn decode(buf: &[u8]) -> Result<Option<(Self, usize)>> {
        if buf.len() < 8 {
            return Ok(None); // Need more data
        }

        let version = buf[0];
        if version != SMUX_VERSION {
            return Err(TorError::Protocol(format!(
                "Invalid SMUX version: {} (expected {})",
                version, SMUX_VERSION
            )));
        }

        let command = SmuxCommand::try_from(buf[1])?;
        // smux-go uses little-endian for length and stream_id
        let data_len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
        let stream_id = u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]);

        let total_len = 8 + data_len;
        if buf.len() < total_len {
            return Ok(None); // Need more data
        }

        let data = buf[8..total_len].to_vec();

        let segment = SmuxSegment {
            version,
            command,
            stream_id,
            data,
        };

        Ok(Some((segment, total_len)))
    }
}

/// Window update structure
#[derive(Debug, Clone, Copy)]
pub struct SmuxUpdate {
    pub consumed: u32,
    pub window: u32,
}

impl SmuxUpdate {
    pub fn decode(data: &[u8]) -> Result<Self> {
        if data.len() < 8 {
            return Err(TorError::Protocol("SmuxUpdate too short".to_string()));
        }

        // smux-go uses little-endian for UPD payload
        let consumed = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        let window = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);

        Ok(Self { consumed, window })
    }
}

/// SMUX stream state
#[derive(Debug)]
struct SmuxState {
    stream_id: u32,
    /// Bytes we've read from peer
    self_read: u32,
    /// Bytes we've written to peer
    self_write: u32,
    /// Bytes read since last UPD sent
    self_increment: u32,
    /// Our receive window size
    self_window: u32,
    /// Bytes peer has consumed
    peer_consumed: u32,
    /// Peer's window size
    peer_window: u32,
    /// Whether we've sent SYN
    syn_sent: bool,
    /// Whether we've received SYN
    syn_received: bool,
}

impl SmuxState {
    fn new(stream_id: u32) -> Self {
        Self {
            stream_id,
            self_read: 0,
            self_write: 0,
            self_increment: 0,
            self_window: RECEIVE_WINDOW,
            peer_consumed: 0,
            peer_window: INITIAL_PEER_WINDOW,
            syn_sent: false,
            syn_received: false,
        }
    }

    /// Bytes the peer still lets us send, as smux-go computes it (modular
    /// arithmetic on the 32-bit counters). Err if the peer claims to have
    /// consumed more than we sent.
    fn send_window(&self) -> io::Result<u32> {
        let inflight = self.self_write.wrapping_sub(self.peer_consumed) as i32;
        if inflight < 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "SMUX peer acknowledged more data than was sent",
            ));
        }
        Ok((self.peer_window as i32).saturating_sub(inflight).max(0) as u32)
    }

    /// Check if we should send a window update
    fn should_send_update(&self) -> bool {
        self.self_increment >= UPD_THRESHOLD
    }
}

type Timer = Pin<Box<dyn Future<Output = ()>>>;

/// SMUX multiplexed stream
///
/// Follows smux-go v2 (the Snowflake bridge side):
/// - sending respects the peer's window (`peerWindow - (written - peerConsumed)`)
///   from UPD frames; writers wait for an UPD when it is exhausted;
/// - data frames are at most MAX_FRAME_SIZE bytes;
/// - a NOP is sent every KEEPALIVE_INTERVAL (the bridge closes sessions that
///   send nothing for 4 minutes), and the session fails loudly when the bridge,
///   which pings every 10 s, sends nothing for KEEPALIVE_TIMEOUT.
pub struct SmuxStream<S> {
    inner: S,
    state: SmuxState,
    read_buffer: Vec<u8>,
    data_buffer: Vec<u8>,
    /// Encoded control frames (UPD, NOP) waiting to be written
    pending_out: Vec<u8>,
    /// Writer waiting for the peer to open its window
    write_waker: Option<Waker>,
    keepalive_interval: Duration,
    keepalive_timeout: Duration,
    keepalive_timer: Option<Timer>,
    /// Keepalive intervals since the last frame from the peer
    silent_intervals: u32,
    fin_sent: bool,
}

impl<S> SmuxStream<S> {
    pub fn new(inner: S) -> Self {
        Self::with_stream_id(inner, DEFAULT_STREAM_ID)
    }

    pub fn with_stream_id(inner: S, stream_id: u32) -> Self {
        Self {
            inner,
            state: SmuxState::new(stream_id),
            read_buffer: Vec::with_capacity(4096),
            data_buffer: Vec::new(),
            pending_out: Vec::new(),
            write_waker: None,
            keepalive_interval: KEEPALIVE_INTERVAL,
            keepalive_timeout: KEEPALIVE_TIMEOUT,
            keepalive_timer: None,
            silent_intervals: 0,
            fin_sent: false,
        }
    }

    #[cfg(test)]
    fn with_keepalive(mut self, interval: Duration, timeout: Duration) -> Self {
        self.keepalive_interval = interval;
        self.keepalive_timeout = timeout;
        self
    }

    /// On each keepalive tick: queue a NOP, and fail if the peer has been
    /// silent for the keepalive timeout.
    fn poll_keepalive(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        loop {
            match self.keepalive_timer.as_mut() {
                None => {}
                Some(timer) => {
                    if timer.as_mut().poll(cx).is_pending() {
                        return Ok(());
                    }
                    self.silent_intervals += 1;
                    if self.keepalive_interval * self.silent_intervals >= self.keepalive_timeout {
                        warn!(
                            "SMUX keepalive timeout: nothing from the bridge for {:?}",
                            self.keepalive_timeout
                        );
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "SMUX keepalive timeout: nothing from the bridge for {:?}",
                                self.keepalive_timeout
                            ),
                        ));
                    }
                    self.pending_out
                        .extend_from_slice(&SmuxSegment::nop(0).encode());
                }
            }
            self.keepalive_timer = Some(Box::pin(crate::retry::sleep(self.keepalive_interval)));
            // Loop once more to poll the new timer, which registers our waker.
        }
    }
}

impl<S: AsyncWrite + Unpin> SmuxStream<S> {
    /// Write queued control frames. The inner (KCP) stream
    /// accepts a whole buffer or returns Pending before accepting anything.
    fn poll_drain_pending(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.pending_out.is_empty() {
            return Poll::Ready(Ok(()));
        }
        match Pin::new(&mut self.inner).poll_write(cx, &self.pending_out) {
            Poll::Ready(Ok(n)) if n == self.pending_out.len() => {
                self.pending_out.clear();
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Partial SMUX control frame write",
            ))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> SmuxStream<S> {
    /// Initialize SMUX connection (send SYN + UPD)
    pub async fn initialize(&mut self) -> Result<()> {
        if self.state.syn_sent {
            return Ok(());
        }

        debug!("Initializing SMUX stream {}", self.state.stream_id);

        // Send SYN
        let syn = SmuxSegment::syn(self.state.stream_id);
        self.inner
            .write_all(&syn.encode())
            .await
            .map_err(|e| TorError::Network(format!("Failed to send SMUX SYN: {}", e)))?;

        // Send initial window update
        let upd = SmuxSegment::upd(self.state.stream_id, 0, self.state.self_window);
        self.inner
            .write_all(&upd.encode())
            .await
            .map_err(|e| TorError::Network(format!("Failed to send SMUX UPD: {}", e)))?;

        self.inner
            .flush()
            .await
            .map_err(|e| TorError::Network(format!("Failed to flush SMUX init: {}", e)))?;

        self.state.syn_sent = true;
        debug!("SMUX stream initialized");

        Ok(())
    }

    /// Close the stream
    pub async fn close(&mut self) -> Result<()> {
        let fin = SmuxSegment::fin(self.state.stream_id);
        self.inner
            .write_all(&fin.encode())
            .await
            .map_err(|e| TorError::Network(format!("Failed to send FIN: {}", e)))?;
        self.inner
            .flush()
            .await
            .map_err(|e| TorError::Network(format!("Failed to flush FIN: {}", e)))?;
        Ok(())
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for SmuxStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        this.poll_keepalive(cx)?;
        // Control frames (UPD, NOP) go out from the read path too. Pending is fine:
        // they stay queued and are retried on the next read or write.
        if let Poll::Ready(Err(e)) = this.poll_drain_pending(cx) {
            return Poll::Ready(Err(e));
        }

        // Drain data buffer first
        if !this.data_buffer.is_empty() {
            let len = std::cmp::min(buf.len(), this.data_buffer.len());
            buf[..len].copy_from_slice(&this.data_buffer[..len]);
            this.data_buffer.drain(..len);
            return Poll::Ready(Ok(len));
        }

        loop {
            // Decode every complete frame in the read buffer
            while let Some((segment, consumed)) = SmuxSegment::decode(&this.read_buffer)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?
            {
                this.read_buffer.drain(..consumed);
                this.silent_intervals = 0;

                if segment.stream_id != this.state.stream_id && segment.stream_id != 0 {
                    continue; // Wrong stream
                }

                match segment.command {
                    SmuxCommand::Syn => {
                        debug!("SMUX: received SYN for stream {}", segment.stream_id);
                        this.state.syn_received = true;
                    }
                    SmuxCommand::Psh => {
                        let len = segment.data.len() as u32;
                        this.state.self_read = this.state.self_read.wrapping_add(len);
                        this.state.self_increment = this.state.self_increment.wrapping_add(len);

                        // Without window updates the peer stops sending after
                        // its initial window (silent stall).
                        if this.state.should_send_update() {
                            let upd = SmuxSegment::upd(
                                this.state.stream_id,
                                this.state.self_read,
                                this.state.self_window,
                            );
                            this.pending_out.extend_from_slice(&upd.encode());
                            this.state.self_increment = 0;
                        }
                        if let Poll::Ready(Err(e)) = this.poll_drain_pending(cx) {
                            return Poll::Ready(Err(e));
                        }

                        if segment.data.is_empty() {
                            continue;
                        }
                        let len = std::cmp::min(buf.len(), segment.data.len());
                        buf[..len].copy_from_slice(&segment.data[..len]);
                        if len < segment.data.len() {
                            this.data_buffer.extend_from_slice(&segment.data[len..]);
                        }
                        return Poll::Ready(Ok(len));
                    }
                    SmuxCommand::Fin => {
                        debug!("SMUX: received FIN for stream {}", segment.stream_id);
                        return Poll::Ready(Ok(0)); // EOF
                    }
                    SmuxCommand::Upd => {
                        let update = SmuxUpdate::decode(&segment.data).map_err(|e| {
                            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
                        })?;
                        trace!(
                            "SMUX: received UPD consumed={}, window={}",
                            update.consumed,
                            update.window
                        );
                        this.state.peer_consumed = update.consumed;
                        this.state.peer_window = update.window;
                        if let Some(waker) = this.write_waker.take() {
                            waker.wake();
                        }
                    }
                    SmuxCommand::Nop => {}
                }
            }

            // Read more data
            let mut temp = [0u8; 4096];
            match Pin::new(&mut this.inner).poll_read(cx, &mut temp) {
                Poll::Ready(Ok(0)) => return Poll::Ready(Ok(0)),
                Poll::Ready(Ok(n)) => this.read_buffer.extend_from_slice(&temp[..n]),
                Poll::Ready(Err(e)) => {
                    warn!("SMUX poll_read: inner error: {}", e);
                    return Poll::Ready(Err(e));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for SmuxStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // Queued control frames go first (nothing accepted yet).
        match self.poll_drain_pending(cx) {
            Poll::Ready(Ok(())) => {}
            other => return other.map(|r| r.map(|()| 0)),
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }

        // Flow control: wait for an UPD (seen by poll_read) while the peer's window is full.
        let window = self.state.send_window()?;
        if window == 0 {
            trace!("SMUX poll_write: peer window full, waiting for UPD");
            self.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }

        // The inner (KCP) stream takes a whole frame or nothing, so a frame is never torn.
        let n = buf.len().min(window as usize).min(MAX_FRAME_SIZE);
        let encoded = SmuxSegment::psh(self.state.stream_id, buf[..n].to_vec()).encode();
        match Pin::new(&mut self.inner).poll_write(cx, &encoded) {
            Poll::Ready(Ok(written)) if written == encoded.len() => {
                self.state.self_write = self.state.self_write.wrapping_add(n as u32);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Ok(_)) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "Partial SMUX write",
            ))),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain_pending(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.inner).poll_flush(cx),
            other => other,
        }
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Send FIN (once) before closing
        if !self.fin_sent {
            let fin = SmuxSegment::fin(self.state.stream_id).encode();
            match Pin::new(&mut self.inner).poll_write(cx, &fin) {
                Poll::Ready(Ok(_)) => self.fin_sent = true,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        Pin::new(&mut self.inner).poll_close(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use futures::task::{waker, ArcWake};
    use futures::AsyncReadExt;
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    /// In-memory peer: bytes queued in `rx` are read by the stream, written
    /// bytes collect in `tx`.
    #[derive(Clone, Default)]
    struct MockPeer(Arc<Mutex<MockPeerState>>);

    #[derive(Default)]
    struct MockPeerState {
        rx: VecDeque<u8>,
        tx: Vec<u8>,
        read_waker: Option<Waker>,
    }

    impl MockPeer {
        fn deliver(&self, bytes: &[u8]) {
            let mut state = self.0.lock().unwrap();
            state.rx.extend(bytes);
            if let Some(w) = state.read_waker.take() {
                w.wake();
            }
        }

        /// Decodes everything written so far into frames.
        fn sent_frames(&self) -> Vec<SmuxSegment> {
            let state = self.0.lock().unwrap();
            let mut frames = Vec::new();
            let mut pos = 0;
            while let Some((segment, n)) = SmuxSegment::decode(&state.tx[pos..]).unwrap() {
                frames.push(segment);
                pos += n;
            }
            assert_eq!(pos, state.tx.len(), "torn frame in output");
            frames
        }
    }

    impl AsyncRead for MockPeer {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut [u8],
        ) -> Poll<io::Result<usize>> {
            let mut state = self.0.lock().unwrap();
            if state.rx.is_empty() {
                state.read_waker = Some(cx.waker().clone());
                return Poll::Pending;
            }
            let n = buf.len().min(state.rx.len());
            for (i, b) in state.rx.drain(..n).enumerate() {
                buf[i] = b;
            }
            Poll::Ready(Ok(n))
        }
    }

    impl AsyncWrite for MockPeer {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            self.0.lock().unwrap().tx.extend_from_slice(buf);
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[derive(Default)]
    struct WakeCounter(AtomicUsize);
    impl ArcWake for WakeCounter {
        fn wake_by_ref(arc_self: &Arc<Self>) {
            arc_self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Writes as much of `data` as the stream accepts without blocking.
    fn write_until_pending(
        stream: &mut SmuxStream<MockPeer>,
        data: &[u8],
        cx: &mut Context<'_>,
    ) -> usize {
        let mut written = 0;
        while written < data.len() {
            match Pin::new(&mut *stream).poll_write(cx, &data[written..]) {
                Poll::Ready(Ok(n)) => {
                    assert!(n > 0);
                    written += n;
                }
                Poll::Ready(Err(e)) => panic!("write failed: {e}"),
                Poll::Pending => break,
            }
        }
        written
    }

    #[tokio::test]
    async fn large_write_respects_peer_window() {
        let peer = MockPeer::default();
        let mut stream = SmuxStream::with_stream_id(peer.clone(), 3);
        let counter = Arc::new(WakeCounter::default());
        let w = waker(counter.clone());
        let mut cx = Context::from_waker(&w);
        let data: Vec<u8> = (0..2 * 1024 * 1024).map(|i| (i * 7 % 251) as u8).collect();

        // Before any UPD the peer's window is smux-go's initial 256 KB.
        let mut written = write_until_pending(&mut stream, &data, &mut cx);
        assert_eq!(written, INITIAL_PEER_WINDOW as usize);

        // The peer consumed 128 KB and advertises 1 MB (Snowflake's MaxStreamBuffer):
        // reading the UPD wakes the blocked writer, which may then fill the window.
        peer.deliver(&SmuxSegment::upd(3, 128 * 1024, 1024 * 1024).encode());
        let mut buf = [0u8; 16];
        assert!(Pin::new(&mut stream)
            .poll_read(&mut cx, &mut buf)
            .is_pending());
        assert!(
            counter.0.load(Ordering::SeqCst) >= 1,
            "writer was not woken by UPD"
        );
        written += write_until_pending(&mut stream, &data[written..], &mut cx);
        assert_eq!(written, 128 * 1024 + 1024 * 1024);

        let mut payload = Vec::new();
        for frame in peer.sent_frames() {
            if frame.command == SmuxCommand::Psh {
                assert!(frame.data.len() <= MAX_FRAME_SIZE);
                payload.extend_from_slice(&frame.data);
            }
        }
        assert_eq!(payload, data[..written]);
    }

    #[tokio::test]
    async fn bogus_update_is_an_error() {
        let peer = MockPeer::default();
        let mut stream = SmuxStream::with_stream_id(peer.clone(), 3);
        let counter = Arc::new(WakeCounter::default());
        let w = waker(counter);
        let mut cx = Context::from_waker(&w);

        assert!(matches!(
            Pin::new(&mut stream).poll_write(&mut cx, &[1u8; 100]),
            Poll::Ready(Ok(100))
        ));
        peer.deliver(&SmuxSegment::upd(3, 1000, 65536).encode());
        let mut buf = [0u8; 16];
        assert!(Pin::new(&mut stream)
            .poll_read(&mut cx, &mut buf)
            .is_pending());
        match Pin::new(&mut stream).poll_write(&mut cx, &[1u8; 100]) {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::InvalidData),
            other => panic!("expected an error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn sends_window_updates_while_reading() {
        let peer = MockPeer::default();
        let mut stream = SmuxStream::with_stream_id(peer.clone(), 3);
        for _ in 0..4 {
            peer.deliver(&SmuxSegment::psh(3, vec![0u8; 16 * 1024]).encode());
        }
        let mut buf = vec![0u8; 64 * 1024];
        let mut read = 0;
        while read < 64 * 1024 {
            read += stream.read(&mut buf).await.unwrap();
        }
        let updates: Vec<_> = peer
            .sent_frames()
            .into_iter()
            .filter(|f| f.command == SmuxCommand::Upd)
            .map(|f| SmuxUpdate::decode(&f.data).unwrap())
            .collect();
        assert_eq!(updates.len(), 2);
        assert_eq!(updates[1].consumed, 64 * 1024);
        assert_eq!(updates[1].window, RECEIVE_WINDOW);
    }

    #[tokio::test]
    async fn keepalive_pings_and_times_out_when_peer_is_silent() {
        let peer = MockPeer::default();
        let mut stream = SmuxStream::with_stream_id(peer.clone(), 3)
            .with_keepalive(Duration::from_millis(20), Duration::from_millis(100));
        let mut buf = [0u8; 16];
        let err = stream.read(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let nops = peer
            .sent_frames()
            .iter()
            .filter(|f| f.command == SmuxCommand::Nop)
            .count();
        assert!(nops >= 3, "only {nops} NOPs sent");
    }

    #[tokio::test]
    async fn keepalive_survives_while_peer_pings() {
        let peer = MockPeer::default();
        let mut stream = SmuxStream::with_stream_id(peer.clone(), 3)
            .with_keepalive(Duration::from_millis(20), Duration::from_millis(100));
        let pinger = peer.clone();
        let ping = tokio::spawn(async move {
            for _ in 0..15 {
                tokio::time::sleep(Duration::from_millis(20)).await;
                pinger.deliver(&SmuxSegment::nop(0).encode());
            }
            pinger.deliver(&SmuxSegment::psh(3, b"done".to_vec()).encode());
        });
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"done");
        ping.await.unwrap();
    }

    #[test]
    fn test_segment_encode_decode() {
        let segment = SmuxSegment::psh(3, b"Hello".to_vec());
        let encoded = segment.encode();

        assert_eq!(encoded[0], SMUX_VERSION);
        assert_eq!(encoded[1], SmuxCommand::Psh as u8);

        let (decoded, consumed) = SmuxSegment::decode(&encoded).unwrap().unwrap();
        assert_eq!(decoded.version, SMUX_VERSION);
        assert_eq!(decoded.command, SmuxCommand::Psh);
        assert_eq!(decoded.stream_id, 3);
        assert_eq!(decoded.data, b"Hello");
        assert_eq!(consumed, encoded.len());
    }

    #[test]
    fn test_segment_syn() {
        let segment = SmuxSegment::syn(5);
        assert_eq!(segment.command, SmuxCommand::Syn);
        assert_eq!(segment.stream_id, 5);
        assert!(segment.data.is_empty());
    }

    #[test]
    fn test_segment_upd() {
        let segment = SmuxSegment::upd(3, 1000, 65535);
        assert_eq!(segment.command, SmuxCommand::Upd);
        assert_eq!(segment.data.len(), 8);

        let update = SmuxUpdate::decode(&segment.data).unwrap();
        assert_eq!(update.consumed, 1000);
        assert_eq!(update.window, 65535);
    }

    #[test]
    fn test_partial_decode() {
        let segment = SmuxSegment::psh(3, b"Hello".to_vec());
        let encoded = segment.encode();

        // Partial header
        assert!(SmuxSegment::decode(&encoded[..4]).unwrap().is_none());

        // Full segment
        assert!(SmuxSegment::decode(&encoded).unwrap().is_some());
    }

    #[test]
    fn test_invalid_version() {
        let mut buf = SmuxSegment::psh(3, b"test".to_vec()).encode();
        buf[0] = 1; // Wrong version

        assert!(SmuxSegment::decode(&buf).is_err());
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        fn smux_command_strategy() -> impl Strategy<Value = SmuxCommand> {
            prop_oneof![
                Just(SmuxCommand::Syn),
                Just(SmuxCommand::Fin),
                Just(SmuxCommand::Psh),
                Just(SmuxCommand::Nop),
                Just(SmuxCommand::Upd),
            ]
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            #[test]
            fn smux_segment_roundtrips(
                cmd in smux_command_strategy(),
                stream_id in any::<u32>(),
                data in proptest::collection::vec(any::<u8>(), 0..=1024),
            ) {
                let seg = SmuxSegment {
                    version: SMUX_VERSION,
                    command: cmd,
                    stream_id,
                    data,
                };
                let encoded = seg.encode();

                let (decoded, consumed_bytes) = SmuxSegment::decode(&encoded).unwrap().unwrap();

                prop_assert_eq!(decoded.version, SMUX_VERSION);
                prop_assert_eq!(decoded.command, cmd);
                prop_assert_eq!(decoded.stream_id, stream_id);
                prop_assert_eq!(decoded.data, seg.data);
                prop_assert_eq!(consumed_bytes, encoded.len());
            }

            #[test]
            fn smux_update_roundtrips(consumed in any::<u32>(), window in any::<u32>()) {
                let seg = SmuxSegment::upd(3, consumed, window);
                let upd = SmuxUpdate::decode(&seg.data).unwrap();

                prop_assert_eq!(upd.consumed, consumed);
                prop_assert_eq!(upd.window, window);
            }

            #[test]
            fn smux_partial_decode_returns_none(
                cmd in smux_command_strategy(),
                stream_id in any::<u32>(),
                data in proptest::collection::vec(any::<u8>(), 0..=256),
            ) {
                let seg = SmuxSegment {
                    version: SMUX_VERSION,
                    command: cmd,
                    stream_id,
                    data,
                };
                let encoded = seg.encode();

                for split in 0..encoded.len() {
                    let prefix = &encoded[..split];
                    let res = SmuxSegment::decode(prefix).unwrap();
                    prop_assert!(res.is_none(), "Expected None for prefix of length {}", split);
                }

                let full = SmuxSegment::decode(&encoded).unwrap();
                prop_assert!(full.is_some());
            }

            #[test]
            fn smux_rejects_invalid_version(
                version in any::<u8>().prop_filter("valid version filtered", |v| *v != SMUX_VERSION),
            ) {
                let mut buf = Vec::with_capacity(12);
                buf.push(version);
                buf.push(SmuxCommand::Psh as u8);
                buf.extend_from_slice(&4u16.to_le_bytes()); // data_len = 4
                buf.extend_from_slice(&1u32.to_le_bytes()); // stream_id
                buf.extend_from_slice(&[0u8; 4]); // data

                let res = SmuxSegment::decode(&buf);
                prop_assert!(res.is_err());
            }

            #[test]
            fn smux_rejects_invalid_command(
                cmd_byte in 5u8..=255u8, // commands 0-4 are valid
            ) {
                let mut buf = Vec::with_capacity(12);
                buf.push(SMUX_VERSION);
                buf.push(cmd_byte);
                buf.extend_from_slice(&4u16.to_le_bytes()); // data_len = 4
                buf.extend_from_slice(&1u32.to_le_bytes()); // stream_id
                buf.extend_from_slice(&[0u8; 4]); // data

                let res = SmuxSegment::decode(&buf);
                prop_assert!(res.is_err());
            }
        }

        #[test]
        fn smux_update_rejects_short_payload() {
            // UPD payload must be 8 bytes
            for len in 0..8 {
                let data = vec![0u8; len];
                let result = SmuxUpdate::decode(&data);
                assert!(result.is_err(), "Expected error for payload length {}", len);
            }
        }
    }
}
