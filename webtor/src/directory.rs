//! The Tor network directory: which relays exist and how to reach them.
//!
//! Every directory is verified the way Arti's directory manager does it
//! before any relay from it is used:
//!
//! - authority key certificates: self-signed (identity key over the
//!   certificate, signing key cross-certifying the identity), within their
//!   lifetime, and from an authority whose v3 identity is pinned in the code
//!   (Arti's default list, `tor_dircommon::authority`);
//! - the microdescriptor consensus: within its lifetime (with Arti's default
//!   `DirTolerance`: one day early, three days late) and signed by more than
//!   half of the pinned authorities;
//! - microdescriptors: only those whose SHA-256 digest is listed in the
//!   signed consensus are used (others are dropped), and they must cover
//!   enough of the network to build paths (Arti's `NetDir` rule).
//!
//! The result is an Arti `NetDir`; circuits pick relays from it with Arti's
//! relay selection (bandwidth-weighted, see `relay.rs`).
//!
//! Two sources: a snapshot served next to the page (`consensus.txt.br`,
//! `certs.txt.br`, `microdescriptors.txt.br`, fetched at build time) and, if
//! that is missing, stale or does not verify, the same documents fetched
//! through the bridge (BEGIN_DIR), as a Tor client using bridges does. A
//! directory that does not verify is never used.

use crate::error::{Result, TorError};
use crate::relay::RelayManager;
use crate::time::system_time_now;
use futures::{AsyncReadExt, AsyncWriteExt};
use std::collections::{HashMap, HashSet};
use std::io::Read;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tor_checkable::{ExternallySigned, SelfSigned, Timebound};
use tor_dircommon::authority::AuthorityContacts;
use tor_dircommon::config::DirTolerance;
use tor_llcrypto::pk::rsa::RsaIdentity;
use tor_netdir::{MdReceiver, NetDir, PartialNetDir};
use tor_netdoc::doc::authcert::AuthCert;
use tor_netdoc::doc::microdesc::MicrodescReader;
use tor_netdoc::doc::netstatus::{Lifetime, MdConsensus};
use tor_netdoc::AllowAnnotations;
use tor_proto::channel::Channel;
use tor_proto::client::circuit::TimeoutEstimator;
use tracing::{error, info, warn};

/// Base URL of the directory snapshot: served by the hosting site itself.
#[cfg(target_arch = "wasm32")]
const CACHED_CONSENSUS_BASE_URL: &str = "./tor";

/// Largest directory document we accept from the bridge (decompressed).
const MAX_DIR_RESPONSE_BYTES: usize = 64 * 1024 * 1024;
/// Age of a consensus after which a new client looks for a newer one.
const REFRESH_AFTER: Duration = Duration::from_secs(24 * 60 * 60);
/// Microdescriptor digests per request to the bridge.
const MICRODESC_CHUNK: usize = 256;
/// Microdescriptor requests to the bridge in flight at once.
const MICRODESC_PARALLEL: usize = 3;
/// Bound on each directory request through the bridge.
const DIR_REQUEST_TIMEOUT: Duration = Duration::from_secs(60);

/// Why a directory was refused.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DirectoryError {
    #[error("consensus unreadable: {0}")]
    Consensus(String),
    #[error("consensus not valid at this time ({0}); check the system clock")]
    NotTimely(String),
    #[error("consensus is not signed by enough of the known directory authorities")]
    UnknownAuthorities,
    #[error("no valid certificate for enough signing authorities ({have} of the {need} needed)")]
    MissingCertificates { have: usize, need: usize },
    #[error("consensus signatures do not verify")]
    BadSignature,
    #[error("authority certificates unreadable: {0}")]
    Certificates(String),
    #[error("microdescriptors unreadable: {0}")]
    Microdescriptors(String),
    #[error("too few microdescriptors to build paths ({have} of {relays} relays)")]
    NotEnoughMicrodescriptors { have: usize, relays: usize },
}

impl From<DirectoryError> for TorError {
    fn from(e: DirectoryError) -> Self {
        TorError::Directory(e.to_string())
    }
}

/// What a verified directory contains, for logs and checks.
#[derive(Debug, Clone)]
pub struct DirectorySummary {
    pub valid_after: SystemTime,
    pub fresh_until: SystemTime,
    pub valid_until: SystemTime,
    /// Relays in the consensus.
    pub relays: usize,
    /// Authority certificates that passed every check.
    pub certificates: usize,
    /// Microdescriptors listed in the consensus (used).
    pub microdescriptors: usize,
    /// Microdescriptors not listed in the consensus or unreadable (dropped).
    pub dropped_microdescriptors: usize,
    /// Relays usable for circuits (in the consensus, with a microdescriptor).
    pub usable_relays: usize,
}

/// A directory that passed verification.
pub struct VerifiedDirectory {
    pub netdir: NetDir,
    pub summary: DirectorySummary,
    nicknames: HashMap<RsaIdentity, String>,
}

impl VerifiedDirectory {
    /// A relay's nickname (for logs and the circuit view).
    pub fn nickname(&self, id: &RsaIdentity) -> &str {
        self.nicknames.get(id).map(String::as_str).unwrap_or("")
    }

    /// The consensus lifetime.
    pub fn lifetime(&self) -> &Lifetime {
        self.netdir.lifetime()
    }

    /// True while the consensus is usable at `now` (within the tolerance).
    pub fn usable_at(&self, now: SystemTime) -> bool {
        DirTolerance::default()
            .extend_lifetime(self.lifetime())
            .valid_at(now)
    }

    /// True while no newer directory is worth fetching: the snapshot is
    /// refreshed daily, a Tor client fetches a new consensus hourly.
    pub fn recent_at(&self, now: SystemTime) -> bool {
        now < self.lifetime().valid_after() + REFRESH_AFTER
    }
}

/// The v3 identities of the directory authorities whose signatures count.
pub fn pinned_authorities() -> Vec<RsaIdentity> {
    AuthorityContacts::default().v3idents().clone()
}

/// Verifies a directory: `consensus` (microdesc flavour), the authorities'
/// key `certs` (concatenated) and `microdescs` (concatenated), at `now`.
pub fn verify_directory(
    consensus: &str,
    certs: &str,
    microdescs: &str,
    now: SystemTime,
) -> std::result::Result<VerifiedDirectory, DirectoryError> {
    verify_directory_with(
        consensus,
        certs,
        microdescs,
        now,
        &pinned_authorities(),
        &DirTolerance::default(),
    )
}

/// [`verify_directory`] with the trusted authorities and tolerance given.
pub(crate) fn verify_directory_with(
    consensus: &str,
    certs: &str,
    microdescs: &str,
    now: SystemTime,
    authorities: &[RsaIdentity],
    tolerance: &DirTolerance,
) -> std::result::Result<VerifiedDirectory, DirectoryError> {
    let (consensus, n_certs) = verify_consensus(consensus, certs, now, authorities, tolerance)?;

    let relays = consensus.relays().len();
    let nicknames = consensus
        .relays()
        .iter()
        .map(|rs| (*rs.rsa_identity(), rs.nickname().to_string()))
        .collect();
    let lifetime = consensus.lifetime().clone();

    let mut partial = PartialNetDir::new(consensus, None);
    let reader = MicrodescReader::new(microdescs, &AllowAnnotations::AnnotationsNotAllowed)
        .map_err(|e| DirectoryError::Microdescriptors(e.to_string()))?;
    let mut used = 0;
    let mut dropped = 0;
    for md in reader {
        // add_microdesc only takes a microdescriptor whose digest (computed
        // over its text while parsing) is listed in the consensus.
        match md.map(|md| partial.add_microdesc(md.into_microdesc())) {
            Ok(true) => used += 1,
            _ => dropped += 1,
        }
    }
    if dropped > 0 {
        warn!("dropped {dropped} microdescriptors not listed in the consensus or unreadable");
    }
    let netdir = partial
        .unwrap_if_sufficient()
        .map_err(|_| DirectoryError::NotEnoughMicrodescriptors { have: used, relays })?;
    let usable_relays = netdir.relays().count();

    Ok(VerifiedDirectory {
        netdir,
        summary: DirectorySummary {
            valid_after: lifetime.valid_after(),
            fresh_until: lifetime.fresh_until(),
            valid_until: lifetime.valid_until(),
            relays,
            certificates: n_certs,
            microdescriptors: used,
            dropped_microdescriptors: dropped,
            usable_relays,
        },
        nicknames,
    })
}

/// The consensus, if it is timely and well signed according to `certs`, and
/// the number of certificates accepted.
pub(crate) fn verify_consensus(
    consensus: &str,
    certs: &str,
    now: SystemTime,
    authorities: &[RsaIdentity],
    tolerance: &DirTolerance,
) -> std::result::Result<(MdConsensus, usize), DirectoryError> {
    let certs = check_certificates(certs, now, authorities, tolerance)?;
    let consensus = check_consensus(consensus, &certs, now, authorities, tolerance)?;
    Ok((consensus, certs.len()))
}

/// The certificates that are well signed, timely and from a pinned authority.
fn check_certificates(
    text: &str,
    now: SystemTime,
    authorities: &[RsaIdentity],
    tolerance: &DirTolerance,
) -> std::result::Result<Vec<AuthCert>, DirectoryError> {
    let mut accepted = Vec::new();
    let parsed =
        AuthCert::parse_multiple(text).map_err(|e| DirectoryError::Certificates(e.to_string()))?;
    for cert in parsed {
        let cert = match cert {
            Ok(cert) => cert,
            Err(e) => {
                warn!("authority certificate refused: {e}");
                continue;
            }
        };
        let cert = match cert.check_signature() {
            Ok(cert) => cert,
            Err(e) => {
                warn!("authority certificate refused: bad signature: {e}");
                continue;
            }
        };
        let cert = match tolerance.extend_tolerance(cert).check_valid_at(&now) {
            Ok(cert) => cert,
            Err(e) => {
                warn!("authority certificate refused: {e}");
                continue;
            }
        };
        if !authorities.contains(cert.id_fingerprint()) {
            warn!(
                "authority certificate refused: unknown authority {}",
                cert.id_fingerprint()
            );
            continue;
        }
        accepted.push(cert);
    }
    Ok(accepted)
}

/// The consensus, if it is timely and well signed by the pinned authorities.
fn check_consensus(
    text: &str,
    certs: &[AuthCert],
    now: SystemTime,
    authorities: &[RsaIdentity],
    tolerance: &DirTolerance,
) -> std::result::Result<MdConsensus, DirectoryError> {
    let (_, _, unchecked) =
        MdConsensus::parse(text).map_err(|e| DirectoryError::Consensus(e.to_string()))?;
    let unvalidated = tolerance
        .extend_tolerance(unchecked)
        .check_valid_at(&now)
        .map_err(|e| DirectoryError::NotTimely(e.to_string()))?;
    let n_authorities = u16::try_from(authorities.len()).expect("a handful of authorities");
    let unvalidated = unvalidated.set_n_authorities(n_authorities);
    let ids: Vec<&RsaIdentity> = authorities.iter().collect();
    if !unvalidated.authorities_are_correct(&ids) {
        return Err(DirectoryError::UnknownAuthorities);
    }
    if unvalidated.key_is_correct(certs).is_err() {
        // signing_cert_ids(): the key ids of every signature on the consensus.
        let have: HashSet<RsaIdentity> = unvalidated
            .signing_cert_ids()
            .filter(|ids| certs.iter().any(|c| c.key_ids() == ids))
            .map(|ids| ids.id_fingerprint)
            .collect();
        return Err(DirectoryError::MissingCertificates {
            have: have.len(),
            need: authorities.len() / 2 + 1,
        });
    }
    unvalidated
        .check_signature(certs)
        .map_err(|_| DirectoryError::BadSignature)
}

/// The last verified directory, shared by every client in this page: a new
/// Tor client (after a failure) does not download and verify it again.
static VERIFIED: Mutex<Option<Arc<VerifiedDirectory>>> = Mutex::new(None);

fn cached_directory(now: SystemTime) -> Option<Arc<VerifiedDirectory>> {
    let slot = VERIFIED.lock().unwrap_or_else(|e| e.into_inner());
    slot.as_ref().filter(|dir| dir.usable_at(now)).cloned()
}

fn remember_directory(dir: Arc<VerifiedDirectory>) {
    *VERIFIED.lock().unwrap_or_else(|e| e.into_inner()) = Some(dir);
}

fn log_directory(source: &str, dir: &VerifiedDirectory) {
    let s = &dir.summary;
    info!(
        "Tor directory from {source} verified: {} relays, {} usable, {} certificates, {} microdescriptors ({} dropped), valid until {}",
        s.relays,
        s.usable_relays,
        s.certificates,
        s.microdescriptors,
        s.dropped_microdescriptors,
        humantime::format_rfc3339_seconds(s.valid_until),
    );
}

/// Directory manager for handling network documents
pub struct DirectoryManager {
    pub relay_manager: Arc<RwLock<RelayManager>>,
    /// Why the snapshot could not be used, if it could not.
    snapshot_error: Mutex<Option<String>>,
}

impl DirectoryManager {
    pub fn new(relay_manager: Arc<RwLock<RelayManager>>) -> Self {
        Self {
            relay_manager,
            snapshot_error: Mutex::new(None),
        }
    }

    async fn install(&self, dir: Arc<VerifiedDirectory>) {
        self.relay_manager.write().await.set_directory(dir);
    }

    /// True once a verified directory is installed.
    pub async fn has_directory(&self) -> bool {
        self.relay_manager.read().await.has_directory()
    }

    /// Why the snapshot was not used (for error messages).
    pub fn snapshot_error(&self) -> Option<String> {
        self.snapshot_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Installs the verified directory snapshot served at `base_url`
    /// (default `./tor`), or the one this page verified before. On failure
    /// the client fetches the directory through the bridge instead.
    #[cfg(target_arch = "wasm32")]
    pub async fn load_cached_consensus(&self, base_url: Option<&str>) -> Result<()> {
        let now = system_time_now();
        let earlier = cached_directory(now);
        if let Some(dir) = earlier.as_ref().filter(|dir| dir.recent_at(now)) {
            info!("Using the Tor directory verified earlier");
            self.install(dir.clone()).await;
            return Ok(());
        }
        let dir = match (load_snapshot(base_url).await, earlier) {
            // Never go back to an older consensus (as Tor clients).
            (Ok(new), Some(old)) if old.summary.valid_after > new.summary.valid_after => {
                info!("The Tor directory snapshot is older than the one verified earlier");
                old
            }
            (Ok(new), _) => {
                log_directory("the snapshot", &new);
                remember_directory(new.clone());
                new
            }
            (Err(e), earlier) => {
                warn!("Tor directory snapshot not usable: {e}");
                let Some(old) = earlier else {
                    *self
                        .snapshot_error
                        .lock()
                        .unwrap_or_else(|e| e.into_inner()) = Some(e.to_string());
                    return Err(e);
                };
                info!("Using the Tor directory verified earlier (still valid)");
                old
            }
        };
        self.install(dir).await;
        Ok(())
    }

    /// Native builds ship no snapshot: the directory comes through the bridge.
    #[cfg(not(target_arch = "wasm32"))]
    pub async fn load_cached_consensus(&self, _base_url: Option<&str>) -> Result<()> {
        if let Some(dir) = cached_directory(system_time_now()) {
            self.install(dir).await;
        }
        Ok(())
    }

    /// Fetches the consensus, the authorities' certificates and every
    /// microdescriptor through the bridge (one-hop BEGIN_DIR circuits on
    /// `channel`), verifies them and installs the directory.
    pub async fn fetch_and_process_consensus(&self, channel: Arc<Channel>) -> Result<()> {
        info!("Fetching the Tor directory through the bridge");
        let fingerprints: Vec<String> = pinned_authorities()
            .iter()
            .map(|id| hex::encode_upper(id.as_bytes()))
            .collect();
        let (consensus, certs) = futures::try_join!(
            dir_get(
                channel.clone(),
                "/tor/status-vote/current/consensus-microdesc.z".to_string()
            ),
            dir_get(
                channel.clone(),
                format!("/tor/keys/fp/{}.z", fingerprints.join("+"))
            ),
        )?;

        // Only the microdescriptors of relays in a consensus that verifies
        // are worth fetching: check it before the large download.
        let (checked, _) = verify_consensus(
            &consensus,
            &certs,
            system_time_now(),
            &pinned_authorities(),
            &DirTolerance::default(),
        )?;
        let digests: Vec<[u8; 32]> = checked.relays().iter().map(|r| *r.md_digest()).collect();
        drop(checked);
        info!(
            "Consensus from the bridge verified; fetching {} microdescriptors",
            digests.len()
        );

        let chunks: Vec<&[[u8; 32]]> = digests.chunks(MICRODESC_CHUNK).collect();
        let mut microdescs = String::new();
        for group in chunks.chunks(MICRODESC_PARALLEL) {
            let bodies: Vec<String> =
                futures::future::try_join_all(group.iter().map(|chunk: &&[[u8; 32]]| {
                    let encoded: Vec<String> = chunk
                        .iter()
                        .map(|d| {
                            use base64::Engine;
                            base64::engine::general_purpose::STANDARD_NO_PAD.encode(d)
                        })
                        .collect();
                    dir_get(
                        channel.clone(),
                        format!("/tor/micro/d/{}.z", encoded.join("-")),
                    )
                }))
                .await?;
            for body in bodies {
                microdescs.push_str(&body);
            }
        }

        let dir = Arc::new(verify_directory(
            &consensus,
            &certs,
            &microdescs,
            system_time_now(),
        )?);
        log_directory("the bridge", &dir);
        remember_directory(dir.clone());
        self.install(dir).await;
        Ok(())
    }
}

/// Fetches and verifies the snapshot served at `base_url` (default `./tor`).
#[cfg(target_arch = "wasm32")]
async fn load_snapshot(base_url: Option<&str>) -> Result<Arc<VerifiedDirectory>> {
    let base_url = base_url
        .unwrap_or(CACHED_CONSENSUS_BASE_URL)
        .trim_end_matches('/');
    let urls =
        ["consensus", "certs", "microdescriptors"].map(|name| format!("{base_url}/{name}.txt.br"));
    let (consensus, certs, microdescs) = futures::try_join!(
        fetch_brotli_text(&urls[0]),
        fetch_brotli_text(&urls[1]),
        fetch_brotli_text(&urls[2]),
    )?;
    let dir = Arc::new(verify_directory(
        &consensus,
        &certs,
        &microdescs,
        system_time_now(),
    )?);
    Ok(dir)
}

/// GET `path` from the bridge's directory cache over a one-hop BEGIN_DIR
/// circuit. Paths ending in `.z` are answered zlib-compressed.
async fn dir_get(channel: Arc<Channel>, path: String) -> Result<String> {
    crate::retry::with_timeout(DIR_REQUEST_TIMEOUT, "directory request", async {
        let (pending_tunnel, reactor) = channel
            .new_tunnel(
                Arc::new(crate::circuit::SimpleTimeoutEstimator) as Arc<dyn TimeoutEstimator>
            )
            .await
            .map_err(|e| TorError::Internal(format!("Failed to create tunnel for dir: {}", e)))?;

        #[cfg(target_arch = "wasm32")]
        wasm_bindgen_futures::spawn_local(async move {
            if let Err(e) = reactor.run().await {
                error!("Dir circuit reactor finished with error: {}", e);
            }
        });
        #[cfg(not(target_arch = "wasm32"))]
        tokio::spawn(async move {
            if let Err(e) = reactor.run().await {
                error!("Dir circuit reactor finished with error: {}", e);
            }
        });

        let params = crate::circuit::make_circ_params()?;
        let tunnel = pending_tunnel
            .create_firsthop_fast(params)
            .await
            .map_err(|e| TorError::Network(format!("Failed to create dir circuit: {}", e)))?;
        let tunnel = Arc::new(tunnel);
        let mut stream = tunnel
            .begin_dir_stream()
            .await
            .map_err(|e| TorError::Network(format!("Failed to begin dir stream: {}", e)))?;

        let request =
            format!("GET {path} HTTP/1.0\r\nHost: directory\r\nConnection: close\r\n\r\n");
        stream
            .write_all(request.as_bytes())
            .await
            .map_err(|e| TorError::Network(format!("Failed to write dir request: {}", e)))?;
        stream
            .flush()
            .await
            .map_err(|e| TorError::Network(format!("Failed to flush dir request: {}", e)))?;

        let mut response = Vec::new();
        (&mut stream)
            .take(MAX_DIR_RESPONSE_BYTES as u64 + 1)
            .read_to_end(&mut response)
            .await
            .map_err(|e| TorError::Network(format!("Failed to read dir response: {}", e)))?;
        if response.len() > MAX_DIR_RESPONSE_BYTES {
            return Err(TorError::Directory("directory response too large".into()));
        }

        let mut headers = [httparse::EMPTY_HEADER; 32];
        let mut parsed = httparse::Response::new(&mut headers);
        let body_start = match parsed.parse(&response) {
            Ok(httparse::Status::Complete(n)) => n,
            _ => return Err(TorError::Directory("malformed directory response".into())),
        };
        if parsed.code != Some(200) {
            return Err(TorError::Directory(format!(
                "directory request answered {}",
                parsed.code.unwrap_or(0)
            )));
        }
        let body = &response[body_start..];
        let bytes = if path.ends_with(".z") {
            let mut out = Vec::new();
            flate2::read::ZlibDecoder::new(body)
                .take(MAX_DIR_RESPONSE_BYTES as u64 + 1)
                .read_to_end(&mut out)
                .map_err(|e| TorError::Directory(format!("bad compressed response: {}", e)))?;
            if out.len() > MAX_DIR_RESPONSE_BYTES {
                return Err(TorError::Directory("directory response too large".into()));
            }
            out
        } else {
            body.to_vec()
        };
        String::from_utf8(bytes)
            .map_err(|_| TorError::Directory("directory response is not UTF-8".into()))
    })
    .await
}

/// Fetches a brotli-compressed text document (WASM only).
#[cfg(target_arch = "wasm32")]
async fn fetch_brotli_text(url: &str) -> Result<String> {
    let bytes = fetch_url(url)
        .await
        .map_err(|e| TorError::Network(format!("{url}: {e}")))?;
    decompress_brotli(&bytes).map_err(|e| TorError::Directory(format!("{url}: {e}")))
}

/// Decompress brotli-compressed data
#[cfg(target_arch = "wasm32")]
fn decompress_brotli(compressed: &[u8]) -> std::io::Result<String> {
    let mut decompressed = Vec::new();
    let mut decoder = brotli::Decompressor::new(compressed, 4096);
    decoder.read_to_end(&mut decompressed)?;
    String::from_utf8(decompressed)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))
}

/// Fetch a URL and return the response body as bytes (WASM only)
#[cfg(target_arch = "wasm32")]
async fn fetch_url(url: &str) -> std::result::Result<Vec<u8>, String> {
    use wasm_bindgen::JsCast;
    use wasm_bindgen_futures::JsFuture;
    use web_sys::{Request, RequestInit, Response};

    let window = web_sys::window().ok_or("No window")?;

    let opts = RequestInit::new();
    opts.set_method("GET");

    let request = Request::new_with_str_and_init(url, &opts)
        .map_err(|e| format!("Failed to create request: {:?}", e))?;

    let resp_value = JsFuture::from(window.fetch_with_request(&request))
        .await
        .map_err(|e| format!("Fetch failed: {:?}", e))?;

    let resp: Response = resp_value
        .dyn_into()
        .map_err(|_| "Response is not a Response")?;

    if !resp.ok() {
        return Err(format!("HTTP error: {}", resp.status()));
    }

    let array_buffer = JsFuture::from(
        resp.array_buffer()
            .map_err(|e| format!("Failed to get array buffer: {:?}", e))?,
    )
    .await
    .map_err(|e| format!("Failed to read response: {:?}", e))?;

    let uint8_array = js_sys::Uint8Array::new(&array_buffer);
    let mut bytes = vec![0u8; uint8_array.length() as usize];
    uint8_array.copy_to(&mut bytes);

    Ok(bytes)
}

#[cfg(test)]
#[path = "directory_tests.rs"]
mod tests;
