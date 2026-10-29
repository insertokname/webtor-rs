//! Directory verification tests.
//!
//! Two sets of documents:
//! - Arti's own test network (a chutney network with three authorities,
//!   `tor-dirmgr/testdata`), always available. Its microdescriptors belong to
//!   another consensus, so only the consensus and certificate checks run on it.
//! - A real snapshot made by `scripts/fetch-consensus.sh`, when
//!   `WEBTOR_TEST_DIRECTORY` names its directory (consensus.txt, certs.txt,
//!   microdescriptors.txt): every check, against the authorities pinned in
//!   the code.

use super::*;
use std::time::Duration;

const TEST_CONSENSUS: &str =
    include_str!("../../vendor/arti/crates/tor-dirmgr/testdata/mdconsensus1.txt");
const TEST_CERTS: [&str; 3] = [
    include_str!("../../vendor/arti/crates/tor-dirmgr/testdata/cert-5696.txt"),
    include_str!("../../vendor/arti/crates/tor-dirmgr/testdata/cert-5A23.txt"),
    include_str!("../../vendor/arti/crates/tor-dirmgr/testdata/cert-7C47.txt"),
];
const TEST_AUTHORITIES: [&str; 3] = [
    "5696AB38CB3852AFA476A5C07B2D4788963D5567",
    "5A23BA701776C9C1AB1C06E734E92AB3D5350D64",
    "7C47DCB4A90E2C2B7C7AD27BD641D038CF5D7EBE",
];
const DAY: Duration = Duration::from_secs(24 * 60 * 60);
const MINUTE: Duration = Duration::from_secs(60);

/// A set of directory documents and who is trusted to sign them.
#[derive(Clone)]
struct Docs {
    name: &'static str,
    consensus: String,
    certs: String,
    /// None: check the consensus and certificates only.
    microdescs: Option<String>,
    authorities: Vec<RsaIdentity>,
    /// A time at which the consensus is fresh.
    now: SystemTime,
}

impl Docs {
    fn verify(&self) -> std::result::Result<Option<VerifiedDirectory>, DirectoryError> {
        self.verify_at(self.now)
    }

    fn verify_at(
        &self,
        now: SystemTime,
    ) -> std::result::Result<Option<VerifiedDirectory>, DirectoryError> {
        let tolerance = DirTolerance::default();
        match &self.microdescs {
            Some(mds) => verify_directory_with(
                &self.consensus,
                &self.certs,
                mds,
                now,
                &self.authorities,
                &tolerance,
            )
            .map(Some),
            None => verify_consensus(
                &self.consensus,
                &self.certs,
                now,
                &self.authorities,
                &tolerance,
            )
            .map(|_| None),
        }
    }

    fn time(&self, keyword: &str) -> SystemTime {
        consensus_time(&self.consensus, keyword)
    }

    /// When the consensus starts being accepted, before the tolerance:
    /// valid-after minus the voting delay's distribution interval.
    fn start(&self) -> SystemTime {
        let line = self
            .consensus
            .lines()
            .find(|l| l.starts_with("voting-delay "))
            .unwrap();
        let dist: u64 = line.split(' ').nth(2).unwrap().parse().unwrap();
        self.time("valid-after") - Duration::from_secs(dist)
    }
}

fn test_network() -> Docs {
    Docs {
        name: "test network",
        consensus: TEST_CONSENSUS.to_string(),
        certs: TEST_CERTS.concat(),
        microdescs: None,
        authorities: TEST_AUTHORITIES
            .iter()
            .map(|hex| RsaIdentity::from_hex(hex).unwrap())
            .collect(),
        now: consensus_time(TEST_CONSENSUS, "valid-after") + Duration::from_secs(20),
    }
}

/// The real snapshot, if WEBTOR_TEST_DIRECTORY is set.
fn real_network() -> Option<Docs> {
    let dir = std::path::PathBuf::from(std::env::var_os("WEBTOR_TEST_DIRECTORY")?);
    let read = |name: &str| std::fs::read_to_string(dir.join(name)).unwrap();
    let consensus = read("consensus.txt");
    let now = consensus_time(&consensus, "valid-after") + 30 * MINUTE;
    Some(Docs {
        name: "real snapshot",
        certs: read("certs.txt"),
        microdescs: Some(read("microdescriptors.txt")),
        consensus,
        authorities: pinned_authorities(),
        now,
    })
}

/// Both sets of documents (the real one only when available).
fn networks() -> Vec<Docs> {
    let mut all = vec![test_network()];
    match real_network() {
        Some(docs) => all.push(docs),
        None => eprintln!("WEBTOR_TEST_DIRECTORY not set: real snapshot checks skipped"),
    }
    all
}

fn consensus_time(consensus: &str, keyword: &str) -> SystemTime {
    let prefix = format!("{keyword} ");
    let line = consensus
        .lines()
        .find(|l| l.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no {keyword} line"));
    humantime::parse_rfc3339(&format!("{}Z", line[prefix.len()..].replace(' ', "T"))).unwrap()
}

/// Replaces the first line starting with `prefix` by `edit(line)`.
fn edit_first_line(text: &str, prefix: &str, edit: impl Fn(&str) -> String) -> String {
    let mut done = false;
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        if !done && line.starts_with(prefix) {
            out.push_str(&edit(line));
            done = true;
        } else {
            out.push_str(line);
        }
    }
    assert!(done, "no line starting with {prefix:?}");
    out
}

/// Signature blocks of a consensus, as byte ranges.
fn signature_blocks(consensus: &str) -> Vec<(usize, usize)> {
    let end_marker = "-----END SIGNATURE-----\n";
    let mut blocks = Vec::new();
    let mut search = 0;
    while let Some(i) = consensus[search..].find("\ndirectory-signature ") {
        let start = search + i + 1;
        let end = start + consensus[start..].find(end_marker).unwrap() + end_marker.len();
        blocks.push((start, end));
        search = end - 1;
    }
    blocks
}

/// Changes one character inside the base64 body of signature `index`.
fn corrupt_signature(consensus: &str, index: usize) -> String {
    let begin = "-----BEGIN SIGNATURE-----\n";
    let (start, end) = signature_blocks(consensus)[index];
    let at = start + consensus[start..end].find(begin).unwrap() + begin.len() + 10;
    let mut bytes = consensus.as_bytes().to_vec();
    bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
    String::from_utf8(bytes).unwrap()
}

/// Keeps only the first `keep` signatures.
fn keep_signatures(consensus: &str, keep: usize) -> String {
    let blocks = signature_blocks(consensus);
    let mut out = consensus[..blocks[0].0].to_string();
    for &(start, end) in blocks.iter().take(keep) {
        out.push_str(&consensus[start..end]);
    }
    out
}

fn assert_rejected(docs: &Docs, what: &str, expected: impl Fn(&DirectoryError) -> bool) {
    match docs.verify() {
        Err(e) if expected(&e) => eprintln!("{}: {what}: rejected: {e}", docs.name),
        other => panic!(
            "{}: {what}: expected a rejection, got {:?}",
            docs.name,
            other.map(|d| d.map(|d| d.summary))
        ),
    }
}

#[test]
fn accepts_valid_directories() {
    for docs in networks() {
        let dir = docs
            .verify()
            .unwrap_or_else(|e| panic!("{}: {e}", docs.name));
        if let Some(dir) = dir {
            let s = &dir.summary;
            eprintln!(
                "{}: {} relays, {} usable, {} certificates, {} microdescriptors, {} dropped",
                docs.name,
                s.relays,
                s.usable_relays,
                s.certificates,
                s.microdescriptors,
                s.dropped_microdescriptors
            );
            assert!(s.usable_relays > 0);
            assert_eq!(s.usable_relays, s.microdescriptors);
            assert_eq!(s.dropped_microdescriptors, 0);
            assert!(dir.usable_at(docs.now));
        }
    }
}

#[test]
fn real_snapshot_has_enough_microdescriptors() {
    let Some(docs) = real_network() else {
        eprintln!("WEBTOR_TEST_DIRECTORY not set: skipped");
        return;
    };
    let s = docs.verify().unwrap().unwrap().summary;
    eprintln!(
        "{} microdescriptors for {} relays",
        s.microdescriptors, s.relays
    );
    assert!(s.relays > 5000, "{} relays", s.relays);
    assert!(s.microdescriptors * 100 >= s.relays * 95, "{s:?}");
}

#[test]
fn rejects_a_changed_relay() {
    for mut docs in networks() {
        // Same relay, another address: not what the authorities signed.
        docs.consensus = edit_first_line(&docs.consensus, "r ", |line| {
            let mut fields: Vec<&str> = line.trim_end().split(' ').collect();
            let n = fields.len();
            fields[n - 3] = "192.0.2.1";
            format!("{}\n", fields.join(" "))
        });
        assert_rejected(&docs, "relay address changed", |e| {
            matches!(e, DirectoryError::BadSignature)
        });
    }
}

#[test]
fn rejects_wrong_signatures() {
    for mut docs in networks() {
        let n = signature_blocks(&docs.consensus).len();
        // One bad signature among enough good ones is fine, as in Tor.
        let good = docs.consensus.clone();
        docs.consensus = corrupt_signature(&good, 0);
        if n - 1 > docs.authorities.len() / 2 {
            docs.verify()
                .unwrap_or_else(|e| panic!("{}: one bad signature of {n}: {e}", docs.name));
        }
        // Too many bad ones.
        for i in 0..n {
            docs.consensus = corrupt_signature(&docs.consensus, i);
        }
        assert_rejected(&docs, "every signature changed", |e| {
            matches!(e, DirectoryError::BadSignature)
        });
    }
}

#[test]
fn rejects_missing_signatures() {
    for mut docs in networks() {
        let all = docs.consensus.clone();
        // Half of the authorities is not enough.
        docs.consensus = keep_signatures(&all, docs.authorities.len() / 2);
        assert_rejected(&docs, "half of the signatures", |e| {
            matches!(e, DirectoryError::UnknownAuthorities)
        });
        docs.consensus = keep_signatures(&all, 0);
        assert_rejected(&docs, "no signatures", |_| true);
    }
}

#[test]
fn rejects_authorities_that_are_not_pinned() {
    // Arti's test network is correctly signed by its own three authorities,
    // which are not the pinned ones.
    let mut docs = test_network();
    docs.verify().unwrap();
    docs.authorities = pinned_authorities();
    assert_rejected(&docs, "signed by unknown authorities", |e| {
        matches!(e, DirectoryError::UnknownAuthorities)
    });

    // Certificates that claim to be from the trusted authorities but are
    // signed by other identity keys are refused.
    let mut docs = test_network();
    docs.certs = TEST_CERTS
        .iter()
        .zip(pinned_authorities())
        .map(|(cert, id)| {
            edit_first_line(cert, "fingerprint ", |_| {
                format!("fingerprint {}\n", hex::encode_upper(id.as_bytes()))
            })
        })
        .collect();
    docs.authorities = pinned_authorities();
    assert_rejected(
        &docs,
        "certificates with a pinned fingerprint and another key",
        |e| matches!(e, DirectoryError::UnknownAuthorities),
    );
}

#[test]
fn rejects_certificates_of_unknown_authorities() {
    // The consensus is signed by trusted authorities, but the certificates
    // offered are another network's (identity keys not pinned).
    for mut docs in networks() {
        docs.certs = if docs.name == "test network" {
            real_network().map(|d| d.certs).unwrap_or_default()
        } else {
            TEST_CERTS.concat()
        };
        assert_rejected(&docs, "certificates of other authorities", |e| {
            matches!(e, DirectoryError::MissingCertificates { have: 0, .. })
        });
    }
    // A certificate whose fingerprint line names a trusted authority but whose
    // identity key is another one does not even parse.
    let Some(mut docs) = real_network() else {
        return;
    };
    let pinned = pinned_authorities();
    docs.certs = TEST_CERTS
        .iter()
        .zip(&pinned)
        .map(|(cert, id)| {
            edit_first_line(cert, "fingerprint ", |_| {
                format!("fingerprint {}\n", hex::encode_upper(id.as_bytes()))
            })
        })
        .collect();
    assert_rejected(&docs, "forged certificates", |e| {
        matches!(e, DirectoryError::MissingCertificates { have: 0, .. })
    });
}

#[test]
fn checks_timeliness_with_tor_tolerances() {
    for docs in networks() {
        let start = docs.start();
        let valid_until = docs.time("valid-until");
        // Up to three days after valid-until and one day before it starts.
        for ok in [valid_until + 3 * DAY - MINUTE, start - DAY + MINUTE] {
            docs.verify_at(ok)
                .unwrap_or_else(|e| panic!("{}: {e}", docs.name));
        }
        for late in [valid_until + 3 * DAY + MINUTE, start - DAY - MINUTE] {
            let d = Docs {
                now: late,
                ..docs.clone()
            };
            assert_rejected(&d, "outside the tolerance", |e| {
                matches!(e, DirectoryError::NotTimely(_))
            });
        }
    }
}

#[test]
fn drops_tampered_microdescriptors() {
    let Some(mut docs) = real_network() else {
        eprintln!("WEBTOR_TEST_DIRECTORY not set: skipped");
        return;
    };
    let baseline = docs.verify().unwrap().unwrap().summary;
    // Another ntor key for one relay: its digest no longer matches the one
    // the authorities signed, so it is dropped.
    let mds = docs.microdescs.take().unwrap();
    let forged_key = "ntor-onion-key AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
    docs.microdescs = Some(edit_first_line(&mds, "ntor-onion-key ", |_| {
        forged_key.into()
    }));
    let dir = docs.verify().unwrap().unwrap();
    assert_eq!(dir.summary.dropped_microdescriptors, 1);
    assert_eq!(dir.summary.usable_relays, baseline.usable_relays - 1);
    assert!(dir.netdir.relays().all(|r| {
        use tor_linkspec::{CircTarget, HasRelayIds};
        r.ntor_onion_key().as_bytes() != &[0u8; 32]
    }));
    eprintln!("tampered microdescriptor dropped: {:?}", dir.summary);
}

#[test]
fn rejects_too_few_microdescriptors() {
    let Some(mut docs) = real_network() else {
        eprintln!("WEBTOR_TEST_DIRECTORY not set: skipped");
        return;
    };
    // A tenth of the microdescriptors cannot build enough paths. Each one
    // starts with an `onion-key` line (with a TAP key before consensus
    // method 37, bare since).
    let mds = docs.microdescs.take().unwrap();
    let starts: Vec<usize> = mds
        .match_indices("onion-key\n")
        .map(|(i, _)| i)
        .filter(|&i| i == 0 || mds.as_bytes()[i - 1] == b'\n')
        .collect();
    assert!(starts.len() > 1000, "{} microdescriptors", starts.len());
    docs.microdescs = Some(mds[..starts[starts.len() / 10]].to_string());
    assert_rejected(&docs, "a tenth of the microdescriptors", |e| {
        matches!(e, DirectoryError::NotEnoughMicrodescriptors { .. })
    });
}

#[test]
fn picks_paths_from_the_real_snapshot() {
    let Some(docs) = real_network() else {
        eprintln!("WEBTOR_TEST_DIRECTORY not set: skipped");
        return;
    };
    let dir = Arc::new(docs.verify().unwrap().unwrap());
    let mut manager = RelayManager::new(Vec::new());
    manager.set_directory(dir.clone());
    let bridge = tor_linkspec::OwnedChanTargetBuilder::default()
        .rsa_identity(RsaIdentity::from_hex("2B280B23E1107BB62ABFC40DDCC8824814F80A72").unwrap())
        .build()
        .unwrap();
    let mut exits = HashSet::new();
    let mut negotiate_cc = 0;
    for _ in 0..50 {
        let path = manager.select_path(&bridge, true).unwrap();
        let (middle, exit) = (&path.middle, &path.exit);
        assert_ne!(middle.fingerprint, exit.fingerprint);
        // The targets carry the relays' real protocol lists: ntor v3 and
        // congestion control (FlowCtrl=2) where the relay has them.
        use tor_linkspec::{CircTarget, HasRelayIds};
        use tor_protover::named;
        assert_eq!(
            hex::encode(path.exit_target.rsa_identity().unwrap().as_bytes()),
            exit.fingerprint
        );
        let protocols = path.exit_target.protovers();
        if protocols.supports_named_subver(named::RELAY_NTORV3)
            && protocols.supports_named_subver(named::FLOWCTRL_CC)
        {
            negotiate_cc += 1;
        }
        let exit_id = RsaIdentity::from_hex(&exit.fingerprint).unwrap();
        let relay = dir.netdir.by_id(&exit_id).unwrap();
        assert!(relay.low_level_details().supports_exit_port_ipv4(443));
        assert!(exit.flags.contains("Stable") && middle.flags.contains("Stable"));
        exits.insert(exit.fingerprint.clone());
    }
    eprintln!("{negotiate_cc} of 50 exits support ntor v3 and congestion control");
    assert!(
        negotiate_cc > 40,
        "{negotiate_cc} of 50 exits support ntor v3 and congestion control"
    );
    assert!(matches!(
        manager
            .select_path(&bridge, true)
            .unwrap()
            .params
            .ccontrol
            .alg(),
        tor_proto::ccparams::Algorithm::Vegas(_)
    ));
    assert!(matches!(
        manager
            .select_path(&bridge, false)
            .unwrap()
            .params
            .ccontrol
            .alg(),
        tor_proto::ccparams::Algorithm::FixedWindow(_)
    ));
    // Weighted random choice over the whole network, not a fixed few.
    eprintln!("{} distinct exits in 50 paths", exits.len());
    assert!(
        exits.len() > 20,
        "{} distinct exits in 50 paths",
        exits.len()
    );
}
