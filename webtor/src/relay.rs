//! Tor relay management and selection

use crate::directory::VerifiedDirectory;
use crate::error::{Result, TorError};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use tor_linkspec::{ChanTarget, CircTarget, HasAddrs, OwnedCircTarget};
use tor_netdir::{FamilyRules, SubnetConfig};
use tor_relay_selection::{
    RelayExclusion, RelaySelectionConfig, RelaySelector, RelayUsage, TargetPort,
};
use tracing::{debug, info};

/// Tor relay information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relay {
    pub fingerprint: String,
    pub nickname: String,
    pub address: String,
    pub or_port: u16,
    pub dir_port: Option<u16>,
    pub flags: HashSet<String>,
    pub bandwidth: u64,
    pub consensus_weight: u32,
    pub version: String,
    pub microdescriptor_hash: String,

    // New fields for keys
    #[serde(default)]
    pub ed25519_identity: Option<String>, // Hex encoded
    #[serde(default)]
    pub ntor_onion_key: Option<String>, // Hex encoded
}

impl Relay {
    /// Create a new Relay instance
    pub fn new(
        fingerprint: String,
        nickname: String,
        address: String,
        or_port: u16,
        flags: HashSet<String>,
        ntor_onion_key: String,
    ) -> Self {
        Self {
            fingerprint,
            nickname,
            address,
            or_port,
            dir_port: None,
            flags,
            bandwidth: 0,
            consensus_weight: 0,
            version: String::new(),
            microdescriptor_hash: String::new(),
            ed25519_identity: None,
            ntor_onion_key: Some(ntor_onion_key),
        }
    }

    /// A relay picked from a verified directory.
    fn from_netdir(relay: &tor_netdir::Relay<'_>, dir: &VerifiedDirectory) -> Result<Self> {
        let addr = relay
            .addrs()
            .find(|a| a.is_ipv4())
            .ok_or_else(|| TorError::relay_selection("relay without an IPv4 address"))?;
        let details = relay.low_level_details();
        let mut relay_flags = HashSet::new();
        if details.is_flagged_fast() {
            relay_flags.insert(flags::FAST.to_string());
        }
        if details.is_flagged_stable() {
            relay_flags.insert(flags::STABLE.to_string());
        }
        if details.is_suitable_as_guard() {
            relay_flags.insert(flags::GUARD.to_string());
        }
        if details.policies_allow_some_port() {
            relay_flags.insert(flags::EXIT.to_string());
        }
        let mut out = Relay::new(
            hex::encode(relay.rsa_id().as_bytes()),
            dir.nickname(relay.rsa_id()).to_string(),
            addr.ip().to_string(),
            addr.port(),
            relay_flags,
            hex::encode(relay.ntor_onion_key().as_bytes()),
        );
        out.ed25519_identity = Some(hex::encode(relay.id().as_bytes()));
        Ok(out)
    }
}

/// Relay selection criteria
#[derive(Debug, Clone)]
pub struct RelayCriteria {
    pub need_flags: HashSet<String>,
    pub exclude_flags: HashSet<String>,
    pub exclude_fingerprints: HashSet<String>,
    pub min_bandwidth: u64,
    pub max_selection: usize,
}

impl Default for RelayCriteria {
    fn default() -> Self {
        Self {
            need_flags: HashSet::new(),
            exclude_flags: HashSet::new(),
            exclude_fingerprints: HashSet::new(),
            min_bandwidth: 0,
            max_selection: 10,
        }
    }
}

impl RelayCriteria {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_flag(mut self, flag: &str) -> Self {
        self.need_flags.insert(flag.to_string());
        self
    }

    pub fn without_flag(mut self, flag: &str) -> Self {
        self.exclude_flags.insert(flag.to_string());
        self
    }

    pub fn without_fingerprint(mut self, fingerprint: &str) -> Self {
        self.exclude_fingerprints.insert(fingerprint.to_string());
        self
    }

    pub fn without_fingerprints(mut self, fingerprints: Vec<String>) -> Self {
        for fp in fingerprints {
            self.exclude_fingerprints.insert(fp);
        }
        self
    }

    pub fn with_min_bandwidth(mut self, bandwidth: u64) -> Self {
        self.min_bandwidth = bandwidth;
        self
    }

    pub fn with_max_selection(mut self, max: usize) -> Self {
        self.max_selection = max;
        self
    }
}

/// The middle and exit relays of a new circuit, as picked by
/// [`RelayManager::select_path`].
pub struct SelectedPath {
    pub middle: Relay,
    pub exit: Relay,
    pub middle_target: OwnedCircTarget,
    pub exit_target: OwnedCircTarget,
    /// For extending to the middle and exit (from the consensus).
    pub params: tor_proto::circuit::CircParameters,
}

/// Relay manager for selecting appropriate relays
pub struct RelayManager {
    /// Relays given directly (tests); circuits use `directory`.
    pub relays: Vec<Relay>,
    /// The verified Tor directory circuits pick their relays from.
    directory: Option<Arc<VerifiedDirectory>>,
}

impl RelayManager {
    pub fn new(relays: Vec<Relay>) -> Self {
        Self {
            relays,
            directory: None,
        }
    }

    /// Uses `directory` (verified, see `directory.rs`) for new circuits.
    pub fn set_directory(&mut self, directory: Arc<VerifiedDirectory>) {
        self.directory = Some(directory);
    }

    pub fn has_directory(&self) -> bool {
        self.directory.is_some()
    }

    /// Number of relays circuits can use.
    pub fn relay_count(&self) -> usize {
        match &self.directory {
            Some(dir) => dir.summary.usable_relays,
            None => self.relays.len(),
        }
    }

    /// Picks the middle and exit relays of a circuit whose first hop is
    /// `first_hop`, from the verified directory, with Arti's relay selection:
    /// bandwidth-weighted by role, the exit allowing port 443, no two relays
    /// of the circuit in the same family or subnet. Signal's connections are
    /// long-lived, so both relays need the Stable flag.
    ///
    /// The targets carry what the directory says about each relay, including
    /// the protocols it supports (ntor v3, congestion control), and the
    /// circuit parameters come from the consensus, as in Arti's circuit
    /// manager.
    /// `congestion_control` false: the fixed window instead (see
    /// `TorClientOptions::congestion_control`).
    pub fn select_path<CT: ChanTarget>(
        &self,
        first_hop: &CT,
        congestion_control: bool,
    ) -> Result<SelectedPath> {
        let dir = self.directory.as_ref().ok_or_else(|| {
            TorError::relay_selection("no verified Tor directory to pick relays from")
        })?;
        let netdir = &dir.netdir;
        let long_lived_ports: HashSet<u16> = [443].into_iter().collect();
        let cfg = RelaySelectionConfig {
            long_lived_ports: &long_lived_ports,
            subnet_config: SubnetConfig::default(),
        };
        let mut rng = rand09::rng();

        let first_hop_exclusion =
            RelayExclusion::exclude_channel_target_family(&cfg, first_hop, netdir);
        let exit_selector = RelaySelector::new(
            RelayUsage::exit_to_all_ports(&cfg, vec![TargetPort::ipv4(443)]),
            first_hop_exclusion.clone(),
        );
        let (exit, info) = exit_selector.select_relay(&mut rng, netdir);
        let exit =
            exit.ok_or_else(|| TorError::relay_selection(format!("no exit relay: {info}")))?;

        let mut middle_exclusion = first_hop_exclusion;
        middle_exclusion.extend(&RelayExclusion::exclude_relays_in_same_family(
            &cfg,
            vec![exit.clone()],
            FamilyRules::from(netdir.params()),
        ));
        let middle_selector = RelaySelector::new(
            RelayUsage::middle_relay(Some(exit_selector.usage())),
            middle_exclusion,
        );
        let (middle, info) = middle_selector.select_relay(&mut rng, netdir);
        let middle =
            middle.ok_or_else(|| TorError::relay_selection(format!("no middle relay: {info}")))?;

        Ok(SelectedPath {
            middle: Relay::from_netdir(&middle, dir)?,
            exit: Relay::from_netdir(&exit, dir)?,
            middle_target: OwnedCircTarget::from_circ_target(&middle),
            exit_target: OwnedCircTarget::from_circ_target(&exit),
            params: if congestion_control {
                crate::circuit::exit_circparams_from_netparams(netdir.params())?
            } else {
                crate::circuit::fixed_window_circparams(netdir.params())?
            },
        })
    }

    /// Select relays matching the given criteria
    pub fn select_relays(&self, criteria: &RelayCriteria) -> Result<Vec<Relay>> {
        let mut candidates: Vec<&Relay> = self
            .relays
            .iter()
            .filter(|relay| {
                // Check excluded fingerprints
                if criteria.exclude_fingerprints.contains(&relay.fingerprint) {
                    return false;
                }

                // Check required flags
                for flag in &criteria.need_flags {
                    if !relay.flags.contains(flag) {
                        return false;
                    }
                }

                // Check excluded flags
                for flag in &criteria.exclude_flags {
                    if relay.flags.contains(flag) {
                        return false;
                    }
                }

                // Check bandwidth
                relay.bandwidth >= criteria.min_bandwidth
            })
            .collect();

        if candidates.is_empty() {
            return Err(TorError::relay_selection(
                "No relays match the selection criteria",
            ));
        }

        // Sort by consensus weight (higher is better)
        candidates.sort_by_key(|relay| std::cmp::Reverse(relay.consensus_weight));

        // Take top candidates
        let selected: Vec<Relay> = candidates
            .into_iter()
            .take(criteria.max_selection)
            .cloned()
            .collect();

        info!(
            "Selected {} relays from {} total",
            selected.len(),
            self.relays.len()
        );
        debug!("Selection criteria: {:?}", criteria);

        Ok(selected)
    }

    /// Select a single relay randomly from candidates
    pub fn select_relay(&self, criteria: &RelayCriteria) -> Result<Relay> {
        use rand::seq::SliceRandom;

        let candidates = self.select_relays(criteria)?;

        if candidates.is_empty() {
            return Err(TorError::relay_selection("No suitable relays found"));
        }

        // Select a random relay from the top candidates to avoid deterministic paths
        // and ensure load balancing
        let mut rng = rand::thread_rng();
        candidates
            .choose(&mut rng)
            .cloned()
            .ok_or_else(|| TorError::relay_selection("Failed to choose random relay"))
    }

    /// Get relay by fingerprint
    pub fn get_relay(&self, fingerprint: &str) -> Option<&Relay> {
        self.relays
            .iter()
            .find(|relay| relay.fingerprint == fingerprint)
    }

    /// Update relay list from consensus
    pub fn update_relays(&mut self, new_relays: Vec<Relay>) {
        info!(
            "Updating relay list: {} -> {} relays",
            self.relays.len(),
            new_relays.len()
        );
        self.relays = new_relays;
    }
}

/// Common relay flag constants
pub mod flags {
    pub const AUTHORITY: &str = "Authority";
    pub const BAD_EXIT: &str = "BadExit";
    pub const EXIT: &str = "Exit";
    pub const FAST: &str = "Fast";
    pub const GUARD: &str = "Guard";
    pub const HSDIR: &str = "HSDir";
    pub const NAMED: &str = "Named";
    pub const STABLE: &str = "Stable";
    pub const RUNNING: &str = "Running";
    pub const VALID: &str = "Valid";
    pub const V2DIR: &str = "V2Dir";
}

/// Helper functions for common relay selections
pub mod selection {
    use super::*;

    /// Select middle relays (Fast, Stable, V2Dir)
    pub fn middle_relays() -> RelayCriteria {
        RelayCriteria::new()
            .with_flag(flags::FAST)
            .with_flag(flags::STABLE)
            .with_flag(flags::V2DIR)
    }

    /// Select exit relays (Fast, Stable, Exit, not BadExit)
    pub fn exit_relays() -> RelayCriteria {
        RelayCriteria::new()
            .with_flag(flags::FAST)
            .with_flag(flags::STABLE)
            .with_flag(flags::EXIT)
            .without_flag(flags::BAD_EXIT)
    }

    /// Select guard relays (Fast, Stable, Guard)
    pub fn guard_relays() -> RelayCriteria {
        RelayCriteria::new()
            .with_flag(flags::FAST)
            .with_flag(flags::STABLE)
            .with_flag(flags::GUARD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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

    #[test]
    fn test_relay_selection() {
        let relays = vec![
            create_test_relay("relay1", vec![flags::FAST, flags::STABLE, flags::V2DIR]),
            create_test_relay("relay2", vec![flags::FAST, flags::STABLE, flags::EXIT]),
            create_test_relay(
                "relay3",
                vec![flags::FAST, flags::STABLE, flags::EXIT, flags::BAD_EXIT],
            ),
        ];

        let manager = RelayManager::new(relays);

        // Test middle relay selection
        let middle_criteria = selection::middle_relays();
        let middle_relays = manager.select_relays(&middle_criteria).unwrap();
        assert_eq!(middle_relays.len(), 1);
        assert!(middle_relays[0].flags.contains(flags::V2DIR));

        // Test exit relay selection
        let exit_criteria = selection::exit_relays();
        let exit_relays = manager.select_relays(&exit_criteria).unwrap();
        assert_eq!(exit_relays.len(), 1);
        assert!(exit_relays[0].flags.contains(flags::EXIT));
        assert!(!exit_relays[0].flags.contains(flags::BAD_EXIT));
    }

    #[cfg(not(target_arch = "wasm32"))]
    mod proptests {
        use super::*;
        use proptest::prelude::*;

        const ALL_FLAGS: &[&str] = &[
            flags::AUTHORITY,
            flags::BAD_EXIT,
            flags::EXIT,
            flags::FAST,
            flags::GUARD,
            flags::HSDIR,
            flags::NAMED,
            flags::STABLE,
            flags::RUNNING,
            flags::VALID,
            flags::V2DIR,
        ];

        fn relay_flags_strategy() -> impl Strategy<Value = HashSet<String>> {
            proptest::collection::hash_set(
                proptest::sample::select(ALL_FLAGS).prop_map(|s| s.to_string()),
                0..=ALL_FLAGS.len(),
            )
        }

        fn relay_strategy() -> impl Strategy<Value = Relay> {
            (
                "[a-f0-9]{8}", // fingerprint
                relay_flags_strategy(),
                0u64..1_000_000u64, // bandwidth
                0u32..100_000u32,   // consensus_weight
            )
                .prop_map(|(fingerprint, flags, bandwidth, weight)| {
                    let mut relay = Relay::new(
                        fingerprint.clone(),
                        format!("relay_{}", &fingerprint[..4]),
                        "127.0.0.1".to_string(),
                        9001,
                        flags,
                        "00".repeat(32),
                    );
                    relay.bandwidth = bandwidth;
                    relay.consensus_weight = weight;
                    relay
                })
        }

        fn criteria_strategy() -> impl Strategy<Value = RelayCriteria> {
            (
                relay_flags_strategy(),                               // need_flags
                relay_flags_strategy(),                               // exclude_flags
                proptest::collection::hash_set("[a-f0-9]{8}", 0..=3), // exclude_fingerprints
                0u64..500_000u64,                                     // min_bandwidth
                1usize..=10usize,                                     // max_selection
            )
                .prop_map(
                    |(
                        need_flags,
                        exclude_flags,
                        exclude_fingerprints,
                        min_bandwidth,
                        max_selection,
                    )| {
                        RelayCriteria {
                            need_flags,
                            exclude_flags,
                            exclude_fingerprints,
                            min_bandwidth,
                            max_selection,
                        }
                    },
                )
        }

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(128))]

            #[test]
            fn relay_selection_respects_invariants(
                relays in proptest::collection::vec(relay_strategy(), 0..=16),
                criteria in criteria_strategy(),
            ) {
                let mgr = RelayManager::new(relays.clone());
                let result = mgr.select_relays(&criteria);

                match result {
                    Ok(selected) => {
                        // Size bound
                        prop_assert!(selected.len() <= criteria.max_selection);

                        for r in &selected {
                            // Required flags present
                            for f in &criteria.need_flags {
                                prop_assert!(r.flags.contains(f),
                                    "Relay {} missing required flag {}", r.fingerprint, f);
                            }
                            // Excluded flags absent
                            for f in &criteria.exclude_flags {
                                prop_assert!(!r.flags.contains(f),
                                    "Relay {} has excluded flag {}", r.fingerprint, f);
                            }
                            // Excluded fingerprints not selected
                            prop_assert!(!criteria.exclude_fingerprints.contains(&r.fingerprint),
                                "Relay {} should have been excluded by fingerprint", r.fingerprint);
                            // Bandwidth threshold
                            prop_assert!(r.bandwidth >= criteria.min_bandwidth,
                                "Relay {} bandwidth {} below minimum {}",
                                r.fingerprint, r.bandwidth, criteria.min_bandwidth);
                        }

                        // Ordering: sorted by consensus_weight descending
                        for win in selected.windows(2) {
                            prop_assert!(win[0].consensus_weight >= win[1].consensus_weight,
                                "Relays not sorted by consensus_weight");
                        }
                    }
                    Err(_) => {
                        // When error, there must be no valid candidates
                        let manual_count = relays.iter().filter(|relay| {
                            !criteria.exclude_fingerprints.contains(&relay.fingerprint)
                                && criteria.need_flags.iter().all(|f| relay.flags.contains(f))
                                && criteria.exclude_flags.iter().all(|f| !relay.flags.contains(f))
                                && relay.bandwidth >= criteria.min_bandwidth
                        }).count();

                        prop_assert_eq!(manual_count, 0,
                            "select_relays returned error but {} candidates exist", manual_count);
                    }
                }
            }

            #[test]
            fn select_relay_picks_from_select_relays(
                relays in proptest::collection::vec(relay_strategy(), 1..=16),
                criteria in criteria_strategy(),
            ) {
                let mgr = RelayManager::new(relays);

                let list_result = mgr.select_relays(&criteria);
                let single_result = mgr.select_relay(&criteria);

                match (list_result, single_result) {
                    (Ok(list), Ok(single)) => {
                        prop_assert!(list.iter().any(|r| r.fingerprint == single.fingerprint),
                            "select_relay returned {} not in select_relays list",
                            single.fingerprint);
                    }
                    (Err(_), Err(_)) => {
                        // Both error: consistent
                    }
                    (Ok(list), Err(_)) => {
                        prop_assert!(list.is_empty(),
                            "select_relay errored but select_relays returned {} items",
                            list.len());
                    }
                    (Err(_), Ok(single)) => {
                        prop_assert!(false,
                            "select_relays errored but select_relay returned {}",
                            single.fingerprint);
                    }
                }
            }
        }
    }
}
