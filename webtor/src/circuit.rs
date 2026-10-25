//! Tor circuit management
//!
//! Streams are grouped by isolation key: streams with the same key share a
//! circuit, streams with different keys never do. The app uses this to keep
//! its chat connections apart from bulk transfers (lanes, see
//! [`IsolationKey::lane`]); webtor's own HTTP client uses it to keep sites
//! apart.
//!
//! - A key keeps using its circuit while the circuit works and is younger
//!   than [`MAX_CIRCUIT_AGE`]; a closed or failed circuit is replaced on the
//!   next stream, one build at a time per key.
//! - One spare circuit is kept ready, so a key that needs a new circuit
//!   (first use, after a failure or [`CircuitManager::renew`]) usually gets
//!   one without waiting for a build.
//! - Builds that take much longer than recent ones are given up and the
//!   circuit is built again through other relays (like Tor's circuit build
//!   timeout): a circuit that is slow to build is slow to use.
//! - [`CircuitManager::renew`] retires circuits: no new streams go to them,
//!   streams already open on them keep working until they end.

use crate::config::MAX_CIRCUITS_PER_ISOLATION_KEY;
use crate::error::{Result, TorError};
use crate::isolation::IsolationKey;
use crate::relay::{Relay, RelayManager};
use crate::time::Instant;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tor_linkspec::HasRelayIds;
use tor_netdir::params::NetParameters;
use tor_proto::ccparams::{
    self, Algorithm, AlgorithmType, CongestionControlParamsBuilder, CongestionWindowParamsBuilder,
    FixedWindowParamsBuilder, RoundTripEstimatorParamsBuilder,
};
use tor_proto::channel::Channel;
use tor_proto::circuit::CircParameters;
use tor_proto::client::circuit::TimeoutEstimator;
use tor_proto::client::stream::DataStream;
use tor_proto::{CellCount, ClientTunnel, FlowCtrlParameters};
use tor_units::Percentage;
use tracing::{debug, error, info, warn};

/// New streams go to a circuit for at most this long after it was built.
pub const MAX_CIRCUIT_AGE: Duration = Duration::from_secs(60 * 60);
/// A bulk-transfer circuit (any key but lane 0) unused this long is dropped.
const MAX_IDLE: Duration = Duration::from_secs(60 * 10);
/// Circuits kept at most (in use, spare and being built), so that a burst of
/// keys cannot make us build circuits without end.
const MAX_LIVE_CIRCUITS: usize = 10;
/// Attempts to build a circuit (each through newly picked relays).
const BUILD_ATTEMPTS: usize = 3;
/// Build timeout until enough builds were seen to know what is usual, and
/// for the last attempt.
const DEFAULT_BUILD_TIMEOUT: Duration = Duration::from_secs(60);
/// Bounds of the learned build timeout.
const MIN_BUILD_TIMEOUT: Duration = Duration::from_secs(4);
/// The learned timeout is this many times the median of recent builds.
const BUILD_TIMEOUT_FACTOR: u32 = 3;
/// Recent builds the timeout is learned from, and how many it needs (the
/// first circuit is enough: waiting 60 s for a hung build costs more than an
/// early sample that is off, and given-up builds count as samples).
const BUILD_SAMPLES: usize = 20;
const MIN_BUILD_SAMPLES: usize = 1;
/// How long a stream may take to open before the circuit is given up on and
/// the stream is tried once more on another circuit (Tor waits 10 s, then
/// 15 s, before it tries another circuit for a stream).
pub const STREAM_OPEN_TIMEOUT: Duration = Duration::from_secs(10);

/// Circuit status
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitStatus {
    Creating,
    Ready,
    Extending,
    Failed,
    /// Retired: takes no new streams (open ones keep working).
    Closed,
}

/// Tor circuit information
pub struct Circuit {
    pub id: String,
    pub status: CircuitStatus,
    pub created_at: Instant,
    pub last_used: Instant,
    /// How long building it took.
    pub build_time: Duration,
    pub relays: Vec<Relay>,
    pub(crate) internal_circuit: Option<Arc<ClientTunnel>>,
    /// Stream isolation key - circuits are bound to a single isolation key
    /// None means the circuit is unassigned and can be bound to any key
    pub isolation_key: Option<IsolationKey>,
    _private: (),
}

impl std::fmt::Debug for Circuit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Circuit")
            .field("id", &self.id)
            .field("status", &self.status)
            .field("created_at", &self.created_at)
            .field("last_used", &self.last_used)
            .field("build_time", &self.build_time)
            .field("relays", &self.relays)
            .field("internal_circuit", &self.internal_circuit.is_some())
            .field("isolation_key", &self.isolation_key)
            .finish()
    }
}

impl Circuit {
    pub fn new(id: String, internal_circuit: Option<Arc<ClientTunnel>>) -> Self {
        let now = Instant::now();
        Self {
            id,
            status: CircuitStatus::Creating,
            created_at: now,
            last_used: now,
            build_time: Duration::ZERO,
            relays: Vec::new(),
            internal_circuit,
            isolation_key: None,
            _private: (),
        }
    }

    /// Bind this circuit to an isolation key (can only be done once)
    pub fn set_isolation_key(&mut self, key: IsolationKey) {
        if self.isolation_key.is_none() {
            self.isolation_key = Some(key);
        }
    }

    pub fn age(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn time_since_last_use(&self) -> Duration {
        self.last_used.elapsed()
    }

    pub fn update_last_used(&mut self) {
        self.last_used = Instant::now();
    }

    pub fn is_ready(&self) -> bool {
        self.status == CircuitStatus::Ready
    }

    pub fn is_failed(&self) -> bool {
        self.status == CircuitStatus::Failed
    }

    pub fn is_closed(&self) -> bool {
        self.status == CircuitStatus::Closed
    }

    /// Ready, its Tor circuit still open, and young enough for new streams.
    pub fn takes_new_streams(&self) -> bool {
        self.is_ready()
            && self.age() < MAX_CIRCUIT_AGE
            && self
                .internal_circuit
                .as_ref()
                .is_some_and(|tunnel| !tunnel.is_closed())
    }

    /// Begin a TCP stream to the given host and port through this circuit.
    ///
    /// The hostname resolution is performed by the exit relay, so you can
    /// pass hostnames instead of IP addresses.
    pub async fn begin_stream(&self, host: &str, port: u16) -> Result<DataStream> {
        let tunnel = self
            .internal_circuit
            .as_ref()
            .ok_or_else(|| TorError::Internal("No internal circuit available".to_string()))?;

        debug!("Beginning stream to {}:{}", host, port);

        let stream = tunnel
            .begin_stream(host, port, None)
            .await
            .map_err(|e| TorError::Internal(format!("Failed to begin stream: {}", e)))?;

        info!("Stream established to {}:{}", host, port);
        Ok(stream)
    }
}

/// Circuit parameters without a consensus (the first hop, one-hop directory
/// circuits): Tor's fixed window. Hops with a CREATE_FAST handshake cannot
/// negotiate anything else.
pub fn make_circ_params() -> Result<CircParameters> {
    fixed_window_circparams(&NetParameters::default())
}

/// Circuit parameters with Tor's fixed window (no congestion control).
pub fn fixed_window_circparams(inp: &NetParameters) -> Result<CircParameters> {
    circparameters_from_netparameters(inp, build_cc_fixedwindow(inp))
}

// The functions below are Arti's (tor-circmgr 0.37 src/build.rs: the same
// mapping from consensus parameters to circuit parameters), here because
// tor-circmgr itself (guards, channel manager, state on disk) is not part of
// this client.

/// Return the congestion control Vegas algorithm using the given network parameters.
fn build_cc_vegas(
    inp: &NetParameters,
    vegas_queue_params: ccparams::VegasQueueParams,
) -> Algorithm {
    Algorithm::Vegas(
        ccparams::VegasParamsBuilder::default()
            .cell_in_queue_params(vegas_queue_params)
            .ss_cwnd_max(inp.cc_ss_max.into())
            .cwnd_full_gap(inp.cc_cwnd_full_gap.into())
            .cwnd_full_min_pct(Percentage::new(
                inp.cc_cwnd_full_minpct.as_percent().get() as u32
            ))
            .cwnd_full_per_cwnd(inp.cc_cwnd_full_per_cwnd.into())
            .build()
            .expect("Unable to build Vegas params from NetParams"),
    )
}

/// Return the congestion control FixedWindow algorithm using the given network parameters.
fn build_cc_fixedwindow(inp: &NetParameters) -> Algorithm {
    Algorithm::FixedWindow(build_cc_fixedwindow_params(inp))
}

/// Return the parameters for the congestion control FixedWindow algorithm
/// using the given network parameters.
fn build_cc_fixedwindow_params(inp: &NetParameters) -> ccparams::FixedWindowParams {
    FixedWindowParamsBuilder::default()
        .circ_window_start(inp.circuit_window.get() as u16)
        .circ_window_min(inp.circuit_window.lower() as u16)
        .circ_window_max(inp.circuit_window.upper() as u16)
        .build()
        .expect("Unable to build FixedWindow params from NetParams")
}

/// Return a new circuit parameter struct using the given network parameters and algorithm to use.
fn circparameters_from_netparameters(
    inp: &NetParameters,
    alg: Algorithm,
) -> Result<CircParameters> {
    let internal = |what: &str, e: &dyn std::fmt::Display| {
        TorError::Internal(format!("Unable to build {what} params from NetParams: {e}"))
    };
    let cwnd_params = CongestionWindowParamsBuilder::default()
        .cwnd_init(inp.cc_cwnd_init.into())
        .cwnd_inc_pct_ss(Percentage::new(
            inp.cc_cwnd_inc_pct_ss.as_percent().get() as u32
        ))
        .cwnd_inc(inp.cc_cwnd_inc.into())
        .cwnd_inc_rate(inp.cc_cwnd_inc_rate.into())
        .cwnd_min(inp.cc_cwnd_min.into())
        .cwnd_max(inp.cc_cwnd_max.into())
        .sendme_inc(inp.cc_sendme_inc.into())
        .build()
        .map_err(|e| internal("CongestionWindow", &e))?;
    let rtt_params = RoundTripEstimatorParamsBuilder::default()
        .ewma_cwnd_pct(Percentage::new(
            inp.cc_ewma_cwnd_pct.as_percent().get() as u32
        ))
        .ewma_max(inp.cc_ewma_max.into())
        .ewma_ss_max(inp.cc_ewma_ss.into())
        .rtt_reset_pct(Percentage::new(
            inp.cc_rtt_reset_pct.as_percent().get() as u32
        ))
        .build()
        .map_err(|e| internal("RTT", &e))?;
    let ccontrol = CongestionControlParamsBuilder::default()
        .alg(alg)
        .fixed_window_params(build_cc_fixedwindow_params(inp))
        .cwnd_params(cwnd_params)
        .rtt_params(rtt_params)
        .build()
        .map_err(|e| internal("CongestionControl", &e))?;
    let flow_ctrl_params = FlowCtrlParameters {
        cc_xoff_client: CellCount::new(inp.cc_xoff_client.get_u32()),
        cc_xoff_exit: CellCount::new(inp.cc_xoff_exit.get_u32()),
        cc_xon_rate: CellCount::new(inp.cc_xon_rate.get_u32()),
        cc_xon_change_pct: inp.cc_xon_change_pct.get_u32(),
        cc_xon_ewma_cnt: inp.cc_xon_ewma_cnt.get_u32(),
    };
    Ok(CircParameters::new(
        inp.extend_by_ed25519_id.into(),
        ccontrol,
        flow_ctrl_params,
    ))
}

/// Circuit parameters for exit circuits from the consensus parameters, as
/// Arti's circuit manager makes them: Vegas congestion control when the
/// consensus asks for it (it does: `cc_alg=2`). Each hop negotiates it in
/// its ntor v3 handshake; a hop whose relay does not support it (no
/// FlowCtrl=2 in its protocols) uses the fixed window instead (tor-proto's
/// `HopSettings`).
pub fn exit_circparams_from_netparams(inp: &NetParameters) -> Result<CircParameters> {
    let alg = match AlgorithmType::from(inp.cc_alg.get()) {
        AlgorithmType::VEGAS => build_cc_vegas(
            inp,
            (
                inp.cc_vegas_alpha_exit.into(),
                inp.cc_vegas_beta_exit.into(),
                inp.cc_vegas_delta_exit.into(),
                inp.cc_vegas_gamma_exit.into(),
                inp.cc_vegas_sscap_exit.into(),
            )
                .into(),
        ),
        // Unrecognized, fallback to fixed window as in SENDME v0.
        _ => build_cc_fixedwindow(inp),
    };
    circparameters_from_netparameters(inp, alg)
}

pub(crate) struct SimpleTimeoutEstimator;
impl TimeoutEstimator for SimpleTimeoutEstimator {
    fn circuit_build_timeout(&self, _length: usize) -> Duration {
        DEFAULT_BUILD_TIMEOUT
    }
}

/// Recent circuit build times, and the timeout learned from them.
#[derive(Default)]
struct BuildTimes {
    recent: VecDeque<Duration>,
}

impl BuildTimes {
    fn record(&mut self, took: Duration) {
        if self.recent.len() == BUILD_SAMPLES {
            self.recent.pop_front();
        }
        self.recent.push_back(took);
    }

    fn median(&self) -> Option<Duration> {
        if self.recent.len() < MIN_BUILD_SAMPLES {
            return None;
        }
        let mut sorted: Vec<_> = self.recent.iter().copied().collect();
        sorted.sort();
        Some(sorted[sorted.len() / 2])
    }

    /// How long a build may take before it is given up (all but the last
    /// attempt): a few times the usual, within bounds.
    fn timeout(&self) -> Duration {
        match self.median() {
            Some(median) => {
                (median * BUILD_TIMEOUT_FACTOR).clamp(MIN_BUILD_TIMEOUT, DEFAULT_BUILD_TIMEOUT)
            }
            None => DEFAULT_BUILD_TIMEOUT,
        }
    }
}

/// Circuit statistics, for diagnostics and measurements.
#[derive(Debug, Clone)]
pub struct CircuitStats {
    /// Recent build times, oldest first.
    pub build_times: Vec<Duration>,
    /// The build timeout in force.
    pub build_timeout: Duration,
    /// Builds given up for taking too long.
    pub abandoned_builds: u32,
    /// Circuits that take new streams: (key, build time, age).
    pub circuits: Vec<(Option<String>, Duration, Duration)>,
}

/// Circuit manager for handling multiple circuits
#[derive(Clone)]
pub struct CircuitManager {
    circuits: Arc<RwLock<Vec<Arc<RwLock<Circuit>>>>>,
    relay_manager: Arc<RwLock<RelayManager>>,
    channel: Arc<RwLock<Option<Arc<Channel>>>>,
    prebuild_in_progress: Arc<AtomicBool>,
    /// One lock per isolation key: one circuit build at a time per key.
    key_locks: Arc<std::sync::Mutex<HashMap<IsolationKey, Arc<tokio::sync::Mutex<()>>>>>,
    build_times: Arc<std::sync::Mutex<BuildTimes>>,
    abandoned_builds: Arc<std::sync::atomic::AtomicU32>,
    congestion_control: Arc<AtomicBool>,
}

impl CircuitManager {
    pub fn new(
        relay_manager: Arc<RwLock<RelayManager>>,
        channel: Arc<RwLock<Option<Arc<Channel>>>>,
    ) -> Self {
        Self {
            circuits: Arc::new(RwLock::new(Vec::new())),
            relay_manager,
            channel,
            prebuild_in_progress: Arc::new(AtomicBool::new(false)),
            key_locks: Default::default(),
            build_times: Default::default(),
            abandoned_builds: Default::default(),
            congestion_control: Arc::new(AtomicBool::new(true)),
        }
    }

    /// Congestion control on new circuits (on by default, see
    /// `TorClientOptions::congestion_control`).
    pub fn set_congestion_control(&self, enabled: bool) {
        self.congestion_control.store(enabled, Ordering::Relaxed);
    }

    /// Create a new circuit, optionally binding it to an isolation key
    ///
    /// If an isolation key is provided, the circuit will be bound to it
    /// BEFORE being added to the circuit list, preventing races where
    /// another request could steal the unassigned circuit.
    pub async fn create_circuit_with_isolation(
        &self,
        isolation_key: Option<IsolationKey>,
    ) -> Result<Arc<RwLock<Circuit>>> {
        let started = Instant::now();
        let circuit_id = format!("circuit_{}", uuid::Uuid::new_v4());
        info!("Creating new circuit: {}", circuit_id);

        let channel_guard = self.channel.read().await;
        let channel = channel_guard
            .as_ref()
            .ok_or_else(|| TorError::Internal("Channel not established".to_string()))?
            .clone();
        drop(channel_guard);

        // Pick the path first: without a directory there is nothing to build.
        let path = {
            let relay_manager = self.relay_manager.read().await;
            relay_manager
                .select_path(
                    channel.target(),
                    self.congestion_control.load(Ordering::Relaxed),
                )
                .map_err(|e| {
                    error!("Failed to select relays: {}", e);
                    e
                })?
        };

        // Create pending tunnel
        let (pending_tunnel, reactor) = channel
            .new_tunnel(Arc::new(SimpleTimeoutEstimator) as Arc<dyn TimeoutEstimator>)
            .await
            .map_err(|e| TorError::Internal(format!("Failed to create pending tunnel: {}", e)))?;

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = reactor.run().await {
                debug!("Circuit reactor finished with error: {}", e);
            }
        });

        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(async move {
            if let Err(e) = reactor.run().await {
                debug!("Circuit reactor finished with error: {}", e);
            }
        });

        // First hop (the bridge): CREATE_FAST, the channel's TLS
        // authenticates the bridge.
        let tunnel = pending_tunnel
            .create_firsthop_fast(make_circ_params()?)
            .await
            .map_err(|e| TorError::Internal(format!("Failed to create first hop: {}", e)))?;

        // Placeholder entry for the bridge in the circuit view (Snowflake has
        // no address of its own here).
        let bridge_fingerprint = channel
            .target()
            .rsa_identity()
            .map(|id| hex::encode(id.as_bytes()))
            .unwrap_or_else(|| "0000000000000000000000000000000000000000".to_string());
        let bridge_relay = Relay::new(
            bridge_fingerprint,
            "Snowflake".to_string(),
            "0.0.0.0".to_string(),
            0,
            std::collections::HashSet::new(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        );

        // Middle, then exit: ntor v3 where the relay supports it, which also
        // negotiates congestion control (see exit_circparams_from_netparams).
        for (role, relay, target) in [
            ("middle", &path.middle, &path.middle_target),
            ("exit", &path.exit, &path.exit_target),
        ] {
            debug!(
                "Extending to {}: {} (fp={})",
                role,
                relay.nickname,
                &relay.fingerprint[..8.min(relay.fingerprint.len())]
            );
            tunnel
                .as_single_circ()
                .map_err(|e| TorError::Internal(format!("Failed to get single circ: {}", e)))?
                .extend(target, path.params.clone())
                .await
                .map_err(|e| TorError::Internal(format!("Failed to extend to {}: {}", role, e)))?;
        }

        let mut circuit = Circuit::new(circuit_id.clone(), Some(Arc::new(tunnel)));
        circuit.relays = vec![bridge_relay, path.middle, path.exit];
        circuit.status = CircuitStatus::Ready;
        circuit.build_time = started.elapsed();

        // Bind isolation key BEFORE adding to list to prevent races
        if let Some(key) = isolation_key {
            circuit.set_isolation_key(key);
        }

        info!(
            "Circuit {} built in {} ms",
            circuit_id,
            circuit.build_time.as_millis()
        );

        let circuit_arc = Arc::new(RwLock::new(circuit));
        self.circuits.write().await.push(circuit_arc.clone());
        Ok(circuit_arc)
    }

    /// Builds a circuit with the learned timeout: a build that takes a few
    /// times longer than recent ones is given up and tried again through
    /// other relays; so is one that fails. The last attempt gets the full
    /// default timeout.
    async fn build_circuit(&self, key: Option<IsolationKey>) -> Result<Arc<RwLock<Circuit>>> {
        let mut last_error = None;
        for attempt in 1..=BUILD_ATTEMPTS {
            let timeout = if attempt == BUILD_ATTEMPTS {
                DEFAULT_BUILD_TIMEOUT
            } else {
                self.build_times
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .timeout()
            };
            let started = Instant::now();
            let result = crate::retry::with_timeout(
                timeout,
                "building a circuit",
                self.create_circuit_with_isolation(key.clone()),
            )
            .await;
            match result {
                Ok(circuit) => {
                    let took = circuit.read().await.build_time;
                    self.build_times
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .record(took);
                    return Ok(circuit);
                }
                Err(e) => {
                    if matches!(e, TorError::Timeout(_)) {
                        // Counts as a sample too: if every build is this slow
                        // (a slower transport), the timeout follows.
                        self.build_times
                            .lock()
                            .unwrap_or_else(|e| e.into_inner())
                            .record(started.elapsed());
                        self.abandoned_builds.fetch_add(1, Ordering::Relaxed);
                        warn!(
                            "circuit build took over {} ms, building another (attempt {}/{})",
                            timeout.as_millis(),
                            attempt,
                            BUILD_ATTEMPTS
                        );
                    } else if attempt < BUILD_ATTEMPTS {
                        warn!(
                            "circuit build failed, building another (attempt {}/{}): {}",
                            attempt, BUILD_ATTEMPTS, e
                        );
                    }
                    // Without a channel or a directory, another attempt
                    // cannot do better.
                    if self.channel.read().await.is_none()
                        || !self.relay_manager.read().await.has_directory()
                    {
                        return Err(e);
                    }
                    last_error = Some(e);
                }
            }
        }
        Err(last_error.unwrap_or_else(|| TorError::circuit_creation("no attempt made")))
    }

    /// Create a new circuit (unassigned, for prebuilding)
    pub async fn create_circuit(&self) -> Result<Arc<RwLock<Circuit>>> {
        self.build_circuit(None).await
    }

    /// Get a ready circuit (create one if none exist)
    pub async fn get_ready_circuit(&self) -> Result<Arc<RwLock<Circuit>>> {
        // First, try to find an existing ready circuit
        let circuits = self.circuits.read().await;
        for circuit in circuits.iter() {
            let circuit_read = circuit.read().await;
            if circuit_read.takes_new_streams() {
                debug!("Found existing ready circuit: {}", circuit_read.id);
                return Ok(circuit.clone());
            }
        }
        drop(circuits);

        // No ready circuit found, create a new one
        self.create_circuit().await
    }

    /// Get a ready circuit and mark it as used (updates last_used timestamp)
    pub async fn get_ready_circuit_and_mark_used(&self) -> Result<Arc<RwLock<Circuit>>> {
        let circuit = self.get_ready_circuit().await?;
        {
            let mut circ = circuit.write().await;
            circ.update_last_used();
        }
        Ok(circuit)
    }

    fn key_lock(&self, key: &IsolationKey) -> Arc<tokio::sync::Mutex<()>> {
        self.key_locks
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .entry(key.clone())
            .or_default()
            .clone()
    }

    /// Get or create a circuit bound to the given isolation key: the key's
    /// circuit while it takes new streams, else the spare, else a new one
    /// (one build at a time per key; concurrent callers share it).
    pub async fn get_circuit_for_isolation_key(
        &self,
        key: Option<IsolationKey>,
    ) -> Result<Arc<RwLock<Circuit>>> {
        // If no isolation key, fall back to legacy behavior
        let key = match key {
            Some(k) => k,
            None => return self.get_ready_circuit_and_mark_used().await,
        };

        let lock = self.key_lock(&key);
        let _building = lock.lock().await;
        self.prune().await;

        // 1. The key's own circuit
        if let Some(circuit) = self.find_bound(&key).await {
            return Ok(circuit);
        }

        // 2. The spare (or any ready unassigned circuit), bound under the
        //    circuit's write lock so two keys cannot both take it
        let mut spare = None;
        for circuit in self.circuits.read().await.iter() {
            let mut circuit_write = circuit.write().await;
            if circuit_write.takes_new_streams() && circuit_write.isolation_key.is_none() {
                debug!(
                    "Binding unassigned circuit {} to isolation key {}",
                    circuit_write.id, key
                );
                circuit_write.set_isolation_key(key.clone());
                circuit_write.update_last_used();
                spare = Some(circuit.clone());
                break;
            }
        }
        if let Some(circuit) = spare {
            self.refill_spare();
            return Ok(circuit);
        }

        // 3. A new circuit already bound to this key
        info!("Creating new circuit for isolation key {}", key);
        let circuit = self.build_circuit(Some(key)).await?;
        circuit.write().await.update_last_used();
        self.refill_spare();
        Ok(circuit)
    }

    /// The circuit bound to `key` that takes new streams, if any (marked used).
    async fn find_bound(&self, key: &IsolationKey) -> Option<Arc<RwLock<Circuit>>> {
        let circuits = self.circuits.read().await;
        let mut bound = 0;
        for circuit in circuits.iter() {
            let circuit_read = circuit.read().await;
            if circuit_read.isolation_key.as_ref() != Some(key) {
                continue;
            }
            let usable = circuit_read.takes_new_streams();
            drop(circuit_read);
            if usable {
                circuit.write().await.update_last_used();
                return Some(circuit.clone());
            }
            bound += 1;
        }
        if bound >= MAX_CIRCUITS_PER_ISOLATION_KEY {
            debug!("{} circuit(s) of {} no longer take streams", bound, key);
        }
        None
    }

    /// The circuit `circuit` failed (a stream could not be opened on it):
    /// no new streams go to it.
    pub async fn mark_failed(&self, circuit: &Arc<RwLock<Circuit>>) {
        let mut circuit = circuit.write().await;
        if circuit.status == CircuitStatus::Ready {
            info!("Circuit {} failed, no new streams on it", circuit.id);
            circuit.status = CircuitStatus::Failed;
        }
    }

    /// Retires the circuits bound to `key` (all bound circuits when `None`):
    /// new streams for those keys get new circuits (the spare first), streams
    /// already open keep working. Returns how many were retired.
    pub async fn renew(&self, key: Option<&IsolationKey>) -> usize {
        let circuits = self.circuits.read().await;
        let mut retired = 0;
        for circuit in circuits.iter() {
            let mut circuit_write = circuit.write().await;
            let matches = match (key, circuit_write.isolation_key.as_ref()) {
                (_, None) => false,
                (None, Some(_)) => true,
                (Some(key), Some(bound)) => key == bound,
            };
            if matches && circuit_write.status == CircuitStatus::Ready {
                circuit_write.status = CircuitStatus::Closed;
                retired += 1;
            }
        }
        info!("Retired {} circuit(s)", retired);
        retired
    }

    /// Drops our reference to circuits that take no new streams, and to
    /// idle bulk-transfer circuits. A circuit without streams then closes;
    /// one with open streams stays until they end.
    async fn prune(&self) {
        let mut circuits = self.circuits.write().await;
        let before = circuits.len();
        let mut kept = Vec::with_capacity(before);
        for circuit in circuits.drain(..) {
            let keep = {
                let c = circuit.read().await;
                let idle_bulk = c
                    .isolation_key
                    .as_ref()
                    .is_some_and(|key| key.lane_number() != Some(0))
                    && c.time_since_last_use() > MAX_IDLE;
                c.status == CircuitStatus::Creating || (c.takes_new_streams() && !idle_bulk)
            };
            if keep {
                kept.push(circuit);
            }
        }
        *circuits = kept;
        if circuits.len() != before {
            debug!("Dropped {} circuit(s)", before - circuits.len());
        }
    }

    /// Builds a spare circuit in the background unless there is one (or one
    /// is being built), so the next key that needs a circuit gets it at once.
    pub fn refill_spare(&self) {
        if self.prebuild_in_progress.swap(true, Ordering::SeqCst) {
            return;
        }
        let manager = self.clone();
        let task = async move {
            let needed = {
                let circuits = manager.circuits.read().await;
                let mut live = 0;
                let mut spare = false;
                for circuit in circuits.iter() {
                    let c = circuit.read().await;
                    if c.takes_new_streams() {
                        live += 1;
                        spare |= c.isolation_key.is_none();
                    }
                }
                !spare && live < MAX_LIVE_CIRCUITS
            };
            if needed && manager.channel.read().await.is_some() {
                match manager.build_circuit(None).await {
                    Ok(circuit) => debug!("Spare circuit {} ready", circuit.read().await.id),
                    Err(e) => warn!("Failed to build a spare circuit: {}", e),
                }
            }
            manager.prebuild_in_progress.store(false, Ordering::SeqCst);
        };
        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(task);
        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(task);
    }

    /// Circuit statistics (build times, the circuits in use).
    pub async fn stats(&self) -> CircuitStats {
        let (build_times, build_timeout) = {
            let times = self.build_times.lock().unwrap_or_else(|e| e.into_inner());
            (times.recent.iter().copied().collect(), times.timeout())
        };
        let mut circuits_info = Vec::new();
        for circuit in self.circuits.read().await.iter() {
            let c = circuit.read().await;
            if c.takes_new_streams() {
                circuits_info.push((
                    c.isolation_key.as_ref().map(|k| k.to_string()),
                    c.build_time,
                    c.age(),
                ));
            }
        }
        CircuitStats {
            build_times,
            build_timeout,
            abandoned_builds: self.abandoned_builds.load(Ordering::Relaxed),
            circuits: circuits_info,
        }
    }

    /// Get circuit status information
    pub async fn get_circuit_status(&self) -> CircuitStatusInfo {
        let circuits = self.circuits.read().await;
        let mut ready_count = 0;
        let mut creating_count = 0;
        let mut failed_count = 0;
        let mut total_age = Duration::from_secs(0);

        for circuit in circuits.iter() {
            let circuit_read = circuit.read().await;
            match circuit_read.status {
                CircuitStatus::Ready if circuit_read.takes_new_streams() => ready_count += 1,
                CircuitStatus::Creating => creating_count += 1,
                CircuitStatus::Failed => failed_count += 1,
                _ => {}
            }
            total_age += circuit_read.age();
        }

        let avg_age = if circuits.is_empty() {
            Duration::from_secs(0)
        } else {
            total_age / circuits.len() as u32
        };

        CircuitStatusInfo {
            total_circuits: circuits.len(),
            ready_circuits: ready_count,
            creating_circuits: creating_count,
            failed_circuits: failed_count,
            average_circuit_age: avg_age,
        }
    }

    /// Update relay manager with new relay list
    pub async fn update_relays(&self, new_relays: Vec<crate::relay::Relay>) {
        let mut relay_manager = self.relay_manager.write().await;
        relay_manager.update_relays(new_relays);
    }

    /// Synchronous version of update_relays for use when we already have a mutable reference
    pub fn update_relay_list(&mut self, new_relays: Vec<crate::relay::Relay>) {
        if let Ok(mut relay_manager) = self.relay_manager.try_write() {
            relay_manager.update_relays(new_relays);
        }
    }

    /// Get relay information from the most recent ready circuit
    pub async fn get_circuit_relays(&self) -> Option<Vec<CircuitRelayInfo>> {
        let circuits = self.circuits.read().await;
        // Iterate in reverse to get the most recently created circuit
        for circuit in circuits.iter().rev() {
            let circuit_read = circuit.read().await;
            if circuit_read.is_ready() && !circuit_read.relays.is_empty() {
                return Some(
                    circuit_read
                        .relays
                        .iter()
                        .enumerate()
                        .map(|(idx, relay)| {
                            let role = match idx {
                                0 => "Bridge",
                                1 => "Middle",
                                2 => "Exit",
                                _ => "Unknown",
                            };
                            // For Snowflake bridges, the address is typically 0.0.0.0 since
                            // we connect via WebRTC - show something more meaningful
                            let address = if idx == 0
                                && (relay.address == "0.0.0.0"
                                    || relay.address.starts_with("0.0.0.0:"))
                            {
                                "Snowflake (WebRTC)".to_string()
                            } else {
                                relay.address.clone()
                            };
                            CircuitRelayInfo {
                                role: role.to_string(),
                                nickname: relay.nickname.clone(),
                                address,
                                fingerprint: relay.fingerprint.chars().take(16).collect(),
                            }
                        })
                        .collect(),
                );
            }
        }
        None
    }

    /// Preemptively build a spare circuit if conditions are met
    ///
    /// This ensures we have a fresh circuit ready before existing ones expire.
    /// Called periodically or after successful requests.
    pub async fn maybe_prebuild_circuit(&self, max_circuits: usize, age_threshold: Duration) {
        let status = self.get_circuit_status().await;

        // Only prebuild if we have at least 1 ready circuit
        if status.ready_circuits == 0 {
            debug!("Skipping prebuild: no ready circuits");
            return;
        }

        // Limit total circuits
        if status.total_circuits >= max_circuits {
            debug!("Skipping prebuild: at max circuits ({})", max_circuits);
            return;
        }

        // Only if circuits are getting old
        if status.average_circuit_age < age_threshold {
            debug!(
                "Skipping prebuild: circuits not old enough (avg {:?} < threshold {:?})",
                status.average_circuit_age, age_threshold
            );
            return;
        }

        self.refill_spare();
    }

    /// Clean up failed and old circuits
    pub async fn cleanup_circuits(&self) -> Result<()> {
        self.prune().await;
        Ok(())
    }
}

/// Circuit relay information for display
#[derive(Debug, Clone)]
pub struct CircuitRelayInfo {
    pub role: String,
    pub nickname: String,
    pub address: String,
    pub fingerprint: String,
}

/// Circuit status information
#[derive(Debug, Clone)]
pub struct CircuitStatusInfo {
    pub total_circuits: usize,
    pub ready_circuits: usize,
    pub creating_circuits: usize,
    pub failed_circuits: usize,
    pub average_circuit_age: Duration,
}

impl CircuitStatusInfo {
    pub fn has_ready_circuits(&self) -> bool {
        self.ready_circuits > 0
    }

    pub fn is_healthy(&self) -> bool {
        self.ready_circuits > 0 && self.failed_circuits == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::{flags, Relay};

    fn create_test_relay(fingerprint: &str, flags: Vec<&str>) -> Relay {
        Relay::new(
            fingerprint.to_string(),
            format!("test_{}", fingerprint),
            "127.0.0.1".to_string(),
            9001,
            flags.into_iter().map(String::from).collect(),
            "0000000000000000000000000000000000000000000000000000000000000000".to_string(),
        )
    }

    #[tokio::test]
    async fn test_circuit_creation() {
        let relays = vec![
            create_test_relay("relay1", vec![flags::FAST, flags::STABLE, flags::GUARD]),
            create_test_relay("relay2", vec![flags::FAST, flags::STABLE, flags::V2DIR]),
            create_test_relay("relay3", vec![flags::FAST, flags::STABLE, flags::EXIT]),
        ];

        let relay_manager = Arc::new(RwLock::new(RelayManager::new(relays)));
        // Create empty channel for testing
        let channel = Arc::new(RwLock::new(None));
        let circuit_manager = CircuitManager::new(relay_manager, channel);

        // This will fail because channel is not established
        let result = circuit_manager.create_circuit().await;
        assert!(result.is_err());
    }

    #[test]
    fn test_circuit_status() {
        let mut circuit = Circuit::new("test_circuit".to_string(), None);

        assert_eq!(circuit.status, CircuitStatus::Creating);
        assert!(!circuit.is_ready());
        assert!(!circuit.is_failed());
        assert!(!circuit.is_closed());

        circuit.status = CircuitStatus::Ready;
        assert!(circuit.is_ready());
        // No Tor circuit behind it: nothing can use it.
        assert!(!circuit.takes_new_streams());

        circuit.status = CircuitStatus::Failed;
        assert!(circuit.is_failed());

        circuit.status = CircuitStatus::Closed;
        assert!(circuit.is_closed());
    }

    #[test]
    fn test_circuit_isolation_key_binding() {
        let mut circuit = Circuit::new("test_circuit".to_string(), None);
        assert!(circuit.isolation_key.is_none());

        let key1 = IsolationKey::from_string("example.com");
        circuit.set_isolation_key(key1.clone());
        assert_eq!(circuit.isolation_key, Some(key1.clone()));

        // Trying to set a different key should be ignored (circuits bind once)
        let key2 = IsolationKey::from_string("other.com");
        circuit.set_isolation_key(key2);
        assert_eq!(circuit.isolation_key, Some(key1));
    }

    #[test]
    fn test_circuit_new_has_no_isolation_key() {
        let circuit = Circuit::new("test".to_string(), None);
        assert!(circuit.isolation_key.is_none());
    }

    #[test]
    fn lanes_are_isolation_keys() {
        assert_eq!(IsolationKey::lane(0).lane_number(), Some(0));
        assert_eq!(IsolationKey::lane(3).lane_number(), Some(3));
        assert_ne!(IsolationKey::lane(0), IsolationKey::lane(1));
        assert_eq!(IsolationKey::from_string("example.com").lane_number(), None);
    }

    #[test]
    fn build_timeout_follows_recent_builds() {
        let mut times = BuildTimes::default();
        assert_eq!(times.timeout(), DEFAULT_BUILD_TIMEOUT);
        times.record(Duration::from_millis(2000));
        assert_eq!(times.timeout(), Duration::from_millis(6000));
        for ms in [1500, 1700, 1800, 2500] {
            times.record(Duration::from_millis(ms));
        }
        // 3 x the median, at least MIN_BUILD_TIMEOUT
        assert_eq!(times.timeout(), Duration::from_millis(5400));
        for _ in 0..BUILD_SAMPLES {
            times.record(Duration::from_millis(200));
        }
        assert_eq!(times.timeout(), MIN_BUILD_TIMEOUT);
        for _ in 0..BUILD_SAMPLES {
            times.record(Duration::from_secs(30));
        }
        assert_eq!(times.timeout(), DEFAULT_BUILD_TIMEOUT);
        assert_eq!(times.recent.len(), BUILD_SAMPLES);
    }

    #[test]
    fn exit_params_use_vegas_when_the_consensus_says_so() {
        let mut params = NetParameters::default();
        let vegas = exit_circparams_from_netparams(&params).unwrap();
        assert!(matches!(vegas.ccontrol.alg(), Algorithm::Vegas(_)));
        params.cc_alg = 0.try_into().unwrap();
        let fixed = exit_circparams_from_netparams(&params).unwrap();
        assert!(matches!(fixed.ccontrol.alg(), Algorithm::FixedWindow(_)));
        // The first hop never negotiates
        assert!(matches!(
            make_circ_params().unwrap().ccontrol.alg(),
            Algorithm::FixedWindow(_)
        ));
    }
}
