//! Async KCP stream wrapper (Snowflake / Turbo Tunnel reliability layer)
//!
//! Glue between the `kcp` crate and any AsyncRead + AsyncWrite transport.
//!
//! Rewritten: the previous glue lost data under normal
//! conditions, which made long-lived connections stall after a few minutes:
//! - KCP output was dropped when the transport was not immediately writable,
//! - a retried `poll_write` re-queued bytes KCP had already accepted,
//! - KCP timers (retransmission, window probes) only ran when the application
//!   happened to read or write,
//! - reads with a buffer smaller than a KCP segment failed with UserBufTooSmall.
//!
//! This version follows the standard pattern (as in kcp-go, used by Snowflake):
//! - every KCP output packet is queued and written in order, never dropped;
//! - `poll_write` only returns Pending *before* KCP accepts data;
//! - `kcp.update` is driven by a timer, at the deadline `kcp.check` reports;
//! - received segments are buffered so callers may read with any buffer size;
//! - a dead link (too many retransmissions) is reported as an error instead of
//!   stalling silently, so upper layers can reconnect.

use crate::time::Instant;
use futures::{AsyncRead, AsyncWrite};
use kcp::Kcp;
use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, Write};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

/// Collects KCP output, one entry per packet (packet boundaries preserved).
#[derive(Clone, Default)]
struct OutputQueue(Arc<Mutex<VecDeque<Vec<u8>>>>);

impl Write for OutputQueue {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().push_back(buf.to_vec());
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// KCP configuration
#[derive(Debug, Clone)]
pub struct KcpConfig {
    /// Conversation ID (must match on both sides)
    pub conv: u32,
    /// Enable nodelay mode
    pub nodelay: bool,
    /// Update interval in milliseconds
    pub interval: i32,
    /// Fast resend trigger count (0 = disabled)
    pub resend: i32,
    /// Disable congestion control
    pub nc: bool,
    /// Send window size
    pub snd_wnd: u16,
    /// Receive window size
    pub rcv_wnd: u16,
}

impl Default for KcpConfig {
    fn default() -> Self {
        Self {
            conv: 0,
            // Match Snowflake Go settings: nodelay=false, interval=100, nc=true
            nodelay: false,
            interval: 100,
            resend: 0,
            nc: true,
            snd_wnd: 128,
            rcv_wnd: 128,
        }
    }
}

type Timer = Pin<Box<dyn Future<Output = ()>>>;

/// Async KCP stream over an arbitrary transport
pub struct KcpStream<S> {
    kcp: Kcp<OutputQueue>,
    output: OutputQueue,
    transport: S,
    start_time: Instant,
    /// Fires when KCP next needs `update` (retransmissions, window probes, flushes)
    timer: Option<Timer>,
    /// Tasks waiting for send-window space. Both the reader (control frames
    /// such as SMUX window updates) and the writer can wait here, so a single
    /// slot could lose the writer's wakeup.
    write_wakers: Vec<Waker>,
    /// Maximum bytes waiting in KCP's send queue before applying backpressure
    snd_limit: usize,
    /// Scratch buffer for transport reads
    rx_scratch: Vec<u8>,
    /// Received data not yet handed to the caller
    rx_pending: Vec<u8>,
    rx_pos: usize,
    transport_eof: bool,
}

fn kcp_err(e: kcp::Error) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("KCP error: {:?}", e))
}

impl<S> KcpStream<S> {
    /// Create a new KCP stream over the given transport
    pub fn new(transport: S, config: KcpConfig) -> Self {
        let output = OutputQueue::default();
        let mut kcp = Kcp::new_stream(config.conv, output.clone());
        kcp.set_nodelay(config.nodelay, config.interval, config.resend, config.nc);
        kcp.set_wndsize(config.snd_wnd, config.rcv_wnd);

        Self {
            kcp,
            output,
            transport,
            start_time: Instant::now(),
            timer: None,
            write_wakers: Vec::new(),
            snd_limit: 2 * config.snd_wnd as usize,
            rx_scratch: vec![0u8; 65536],
            rx_pending: Vec::new(),
            rx_pos: 0,
            transport_eof: false,
        }
    }

    fn now_ms(&self) -> u32 {
        self.start_time.elapsed().as_millis() as u32
    }

    /// Run KCP's periodic work if it is due, and arm the timer for the next deadline.
    fn poll_timer(&mut self, cx: &mut Context<'_>) -> io::Result<()> {
        loop {
            if let Some(timer) = self.timer.as_mut() {
                if timer.as_mut().poll(cx).is_pending() {
                    return Ok(());
                }
                self.timer = None;
            }
            self.kcp.update(self.now_ms()).map_err(kcp_err)?;
            if self.kcp.is_dead_link() {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "KCP link is dead (too many retransmissions)",
                ));
            }
            let wait_ms = self.kcp.check(self.now_ms()).max(1) as u64;
            self.timer = Some(Box::pin(crate::retry::sleep(Duration::from_millis(wait_ms))));
            // Loop once more to poll the new timer, which registers our waker.
        }
    }
}

impl<S: AsyncWrite + Unpin> KcpStream<S> {
    /// Write queued KCP packets to the transport, in order, without dropping any.
    /// Ready(Ok) once everything is written and flushed; Pending if the transport
    /// is not writable yet (packets stay queued).
    fn poll_drain_output(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            let packet = match self.output.0.lock().unwrap().front() {
                Some(packet) => packet.clone(),
                None => break,
            };
            match Pin::new(&mut self.transport).poll_write(cx, &packet) {
                Poll::Ready(Ok(n)) if n == packet.len() => {
                    self.output.0.lock().unwrap().pop_front();
                }
                Poll::Ready(Ok(n)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        format!("transport accepted {} of {} bytes of a KCP packet", n, packet.len()),
                    )))
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Pin::new(&mut self.transport).poll_flush(cx)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncRead for KcpStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // 1. Feed every packet the transport has ready into KCP.
        let mut got_input = false;
        while !this.transport_eof {
            match Pin::new(&mut this.transport).poll_read(cx, &mut this.rx_scratch) {
                Poll::Ready(Ok(0)) => this.transport_eof = true,
                Poll::Ready(Ok(n)) => {
                    this.kcp.input(&this.rx_scratch[..n]).map_err(kcp_err)?;
                    got_input = true;
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => break,
            }
        }

        // 2. Timers (also performs KCP's first `update`, required before flushing).
        this.poll_timer(cx)?;

        if got_input {
            // Acknowledge promptly, and let a blocked writer retry: ACKs free window space.
            this.kcp.flush_ack().map_err(kcp_err)?;
            for waker in this.write_wakers.drain(..) {
                waker.wake();
            }
        }

        // 3. Send whatever KCP produced (ACKs, retransmissions). Pending is fine here:
        //    packets stay queued and we are woken when the transport is writable.
        if let Poll::Ready(Err(e)) = this.poll_drain_output(cx) {
            return Poll::Ready(Err(e));
        }

        // 4. Hand received data to the caller, buffering whole KCP segments.
        if this.rx_pos == this.rx_pending.len() {
            this.rx_pending.clear();
            this.rx_pos = 0;
            match this.kcp.peeksize() {
                Ok(size) => {
                    this.rx_pending.resize(size, 0);
                    let n = this.kcp.recv(&mut this.rx_pending).map_err(kcp_err)?;
                    this.rx_pending.truncate(n);
                }
                Err(kcp::Error::RecvQueueEmpty) | Err(kcp::Error::ExpectingFragment) => {
                    return if this.transport_eof {
                        Poll::Ready(Ok(0))
                    } else {
                        Poll::Pending
                    };
                }
                Err(e) => return Poll::Ready(Err(kcp_err(e))),
            }
        }
        let n = buf.len().min(this.rx_pending.len() - this.rx_pos);
        buf[..n].copy_from_slice(&this.rx_pending[this.rx_pos..this.rx_pos + n]);
        this.rx_pos += n;
        Poll::Ready(Ok(n))
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for KcpStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = &mut *self;

        // Backpressure: refuse new data (before accepting any) while the send queue is full.
        if this.kcp.wait_snd() >= this.snd_limit {
            if let Poll::Ready(Err(e)) = this.poll_drain_output(cx) {
                return Poll::Ready(Err(e));
            }
            if !this.write_wakers.iter().any(|w| w.will_wake(cx.waker())) {
                this.write_wakers.push(cx.waker().clone());
            }
            return Poll::Pending;
        }

        // From here on the data is accepted: never return Pending.
        let n = this.kcp.send(buf).map_err(kcp_err)?;
        this.kcp.update(this.now_ms()).map_err(kcp_err)?;
        this.kcp.flush().map_err(kcp_err)?;
        if let Poll::Ready(Err(e)) = this.poll_drain_output(cx) {
            return Poll::Ready(Err(e));
        }
        Poll::Ready(Ok(n))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_drain_output(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.poll_drain_output(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut self.transport).poll_close(cx),
            other => other,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kcp_config_default() {
        let config = KcpConfig::default();
        // Match Snowflake Go settings: nodelay=false, interval=100, nc=true
        assert!(!config.nodelay);
        assert_eq!(config.interval, 100);
        assert!(config.nc);
    }

    #[test]
    fn test_output_queue_preserves_packets() {
        let mut queue = OutputQueue::default();
        queue.write_all(b"first").unwrap();
        queue.write_all(b"second").unwrap();

        let packets = queue.0.lock().unwrap();
        assert_eq!(packets.len(), 2);
        assert_eq!(packets[0], b"first");
        assert_eq!(packets[1], b"second");
    }
}
