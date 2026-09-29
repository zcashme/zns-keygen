//! Durable ceremony progress.
//!
//! The capsule is written before this state file. Every later transition is
//! recorded here before the next irreversible step. `ANCHOR_BUILT` stores the
//! signed transaction before broadcast. `ANCHOR_SUBMITTED` keeps that same
//! transaction while it waits for [`ANCHOR_CONFIRMATIONS`] on the best chain.
//! `ANCHOR_BROADCAST` stores the txid and the inclusion height only after that
//! depth, and never builds or submits another.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zcash_address::ZcashAddress;
use zcash_protocol::consensus::Parameters;

use crate::NETWORK;
use crate::fingerprint::SeedFingerprint;
use crate::keys::TreasuryFundingInfo;

pub const STATE_FILE: &str = "keys/ceremony_state.toml";

const SEALED: &str = "SEALED";
const WAITING_FOR_FUNDS: &str = "WAITING_FOR_FUNDS";
const FUNDED: &str = "FUNDED";
const ANCHOR_BUILT: &str = "ANCHOR_BUILT";
const ANCHOR_SUBMITTED: &str = "ANCHOR_SUBMITTED";
const ANCHOR_BROADCAST: &str = "ANCHOR_BROADCAST";
const COMPLETE: &str = "COMPLETE";

/// Best-chain confirmations required before the inclusion height becomes the birthday.
///
/// One confirmation shows that the anchor entered a block. That block can still
/// be reorged, so it is not the birthday. Ten confirmations is the depth at
/// which this ceremony treats the inclusion height as fixed. The birthday is
/// that block's height, not the chain tip and not the height plus this depth.
pub const ANCHOR_CONFIRMATIONS: u32 = 10;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Sealed,
    WaitingForFunds,
    Funded,
    AnchorBuilt,
    AnchorSubmitted,
    AnchorBroadcast,
    Complete,
}

impl Phase {
    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Sealed => SEALED,
            Phase::WaitingForFunds => WAITING_FOR_FUNDS,
            Phase::Funded => FUNDED,
            Phase::AnchorBuilt => ANCHOR_BUILT,
            Phase::AnchorSubmitted => ANCHOR_SUBMITTED,
            Phase::AnchorBroadcast => ANCHOR_BROADCAST,
            Phase::Complete => COMPLETE,
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            SEALED => Some(Phase::Sealed),
            WAITING_FOR_FUNDS => Some(Phase::WaitingForFunds),
            FUNDED => Some(Phase::Funded),
            ANCHOR_BUILT => Some(Phase::AnchorBuilt),
            ANCHOR_SUBMITTED => Some(Phase::AnchorSubmitted),
            ANCHOR_BROADCAST => Some(Phase::AnchorBroadcast),
            COMPLETE => Some(Phase::Complete),
            _ => None,
        }
    }
}

impl std::fmt::Display for Phase {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a resumed process is allowed to do from the persisted phase.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResumeAction {
    /// Capsule is durable. Request and verify attestation if it is not stored yet.
    Attest,
    /// Attestation is durable. Poll for Treasury funding.
    WaitForFunding,
    /// Funding was observed. Unseal and construct the anchor. Do not broadcast.
    BuildAnchor,
    /// The signed anchor is stored. Learn whether it was broadcast before sending.
    ResolveBroadcast,
    /// The stored anchor was submitted. Wait until its best-chain inclusion is confirmed.
    WaitForConfirmation,
    /// Txid and birthday are durable. Write the manifest and mint config only.
    Finalize,
    /// Ceremony finished. Exit successfully.
    Done,
}

/// What a lookup of the stored anchor txid means for the birthday.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorLookup {
    /// The node does not have this txid in the mempool or the best chain.
    Absent,
    /// In the mempool, or mined on the best chain with fewer than [`ANCHOR_CONFIRMATIONS`].
    ///
    /// `height` is missing for a mempool transaction. `confirmations` is missing
    /// or still below the required depth.
    Pending {
        height: Option<i64>,
        confirmations: Option<u64>,
    },
    /// Zebra still has the transaction, but only on a side chain.
    ///
    /// A negative height, including `-1`, is not a mining candidate. The stored
    /// transaction has to be submitted again so the node can accept it into the
    /// mempool or reject it as expired.
    SideChain,
    /// Best-chain block that contains the anchor, after [`ANCHOR_CONFIRMATIONS`].
    Confirmed { birthday: u32 },
}

/// The next step for a stored anchor. None of these builds a different transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BroadcastAction {
    /// The txid is unknown. Submit the stored raw transaction and no other.
    SendStored,
    /// The txid is known, but its birthday is not confirmed. Do not finalize.
    AwaitConfirmation,
    /// The inclusion height is confirmed. Persist it and finalize.
    Confirmed { birthday: u32 },
}

/// Classify a verbose `getrawtransaction` result.
///
/// A missing height, a missing confirmation count, or fewer than
/// [`ANCHOR_CONFIRMATIONS`] stays pending. A negative height is a side chain.
/// The chain tip is not an input.
pub fn classify_anchor(height: Option<i64>, confirmations: Option<u64>) -> AnchorLookup {
    if matches!(height, Some(height) if height < 0) {
        return AnchorLookup::SideChain;
    }
    if let (Some(height), Some(confirmations)) = (height, confirmations)
        && height >= 0
        && confirmations >= u64::from(ANCHOR_CONFIRMATIONS)
        && let Ok(birthday) = u32::try_from(height)
    {
        return AnchorLookup::Confirmed { birthday };
    }
    AnchorLookup::Pending {
        height,
        confirmations,
    }
}

/// Decide the broadcast step from a lookup that has already been performed.
pub fn broadcast_action(lookup: AnchorLookup) -> BroadcastAction {
    match lookup {
        AnchorLookup::Absent | AnchorLookup::SideChain => BroadcastAction::SendStored,
        AnchorLookup::Pending { .. } => BroadcastAction::AwaitConfirmation,
        AnchorLookup::Confirmed { birthday } => BroadcastAction::Confirmed { birthday },
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CeremonyState {
    phase: Phase,
    fingerprint: SeedFingerprint,
    capsule_hash: [u8; 32],
    treasury_address: String,
    treasury_pubkey: String,
    txid: Option<String>,
    raw_tx: Option<String>,
    birthday: Option<u32>,
}

impl CeremonyState {
    pub fn sealed(
        fingerprint: SeedFingerprint,
        capsule_hash: [u8; 32],
        treasury_address: String,
        treasury_pubkey: String,
    ) -> Self {
        Self {
            phase: Phase::Sealed,
            fingerprint,
            capsule_hash,
            treasury_address,
            treasury_pubkey,
            txid: None,
            raw_tx: None,
            birthday: None,
        }
    }

    pub fn phase(&self) -> Phase {
        self.phase
    }

    pub fn fingerprint(&self) -> &SeedFingerprint {
        &self.fingerprint
    }

    pub fn capsule_hash(&self) -> &[u8; 32] {
        &self.capsule_hash
    }

    pub fn txid(&self) -> Option<&str> {
        self.txid.as_deref()
    }

    pub fn raw_tx(&self) -> Option<&str> {
        self.raw_tx.as_deref()
    }

    pub fn birthday(&self) -> Option<u32> {
        self.birthday
    }

    pub fn resume_action(&self) -> ResumeAction {
        match self.phase {
            Phase::Sealed => ResumeAction::Attest,
            Phase::WaitingForFunds => ResumeAction::WaitForFunding,
            Phase::Funded => ResumeAction::BuildAnchor,
            Phase::AnchorBuilt => ResumeAction::ResolveBroadcast,
            Phase::AnchorSubmitted => ResumeAction::WaitForConfirmation,
            Phase::AnchorBroadcast => ResumeAction::Finalize,
            Phase::Complete => ResumeAction::Done,
        }
    }

    pub fn waiting_for_funds(mut self) -> Self {
        self.phase = Phase::WaitingForFunds;
        self
    }

    pub fn funded(mut self) -> Self {
        self.phase = Phase::Funded;
        self
    }

    pub fn anchor_built(mut self, txid: String, raw_tx: String) -> Self {
        self.phase = Phase::AnchorBuilt;
        self.txid = Some(txid);
        self.raw_tx = Some(raw_tx);
        self
    }

    /// Drop a stored anchor whose expiry has passed and build another.
    ///
    /// This is only for the transaction already stored in `ANCHOR_BUILT` or
    /// `ANCHOR_SUBMITTED`. `FUNDED` resumes at `BuildAnchor`, which unseals the
    /// same capsule and constructs one replacement at the current tip.
    pub fn expired_anchor(mut self) -> Self {
        assert!(
            matches!(self.phase, Phase::AnchorBuilt | Phase::AnchorSubmitted),
            "only an unconfirmed stored anchor can expire"
        );

        self.phase = Phase::Funded;
        self.txid = None;
        self.raw_tx = None;
        self.birthday = None;
        self
    }

    /// The stored transaction has been submitted. Its birthday is not known yet.
    pub fn anchor_submitted(mut self) -> Self {
        assert!(
            matches!(self.phase, Phase::AnchorBuilt | Phase::AnchorSubmitted),
            "only a stored anchor can wait for confirmation"
        );
        assert!(
            self.txid.is_some() && self.raw_tx.is_some(),
            "ANCHOR_SUBMITTED requires the txid and raw transaction"
        );
        self.phase = Phase::AnchorSubmitted;
        self.birthday = None;
        self
    }

    pub fn anchor_broadcast(mut self, birthday: u32) -> Self {
        assert!(
            self.txid.is_some(),
            "ANCHOR_BROADCAST requires the txid persisted with the built anchor"
        );
        self.phase = Phase::AnchorBroadcast;
        self.birthday = Some(birthday);
        self
    }

    pub fn complete(mut self) -> Self {
        assert!(
            self.txid.is_some() && self.birthday.is_some(),
            "COMPLETE requires a persisted txid and birthday"
        );
        self.phase = Phase::Complete;
        self
    }

    pub fn funding_info(&self) -> Result<TreasuryFundingInfo, String> {
        let address = parse_transparent_address(&self.treasury_address)?;
        let pubkey_bytes = decode_fixed_hex::<33>("treasury pubkey", &self.treasury_pubkey)?;
        let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes)
            .map_err(|error| format!("treasury pubkey: {error}"))?;
        Ok(TreasuryFundingInfo::from_public(address, pubkey))
    }
}

#[derive(Serialize, Deserialize)]
struct Record {
    state: String,
    seed_fingerprint: String,
    capsule_hash_blake2b256: String,
    treasury_address: String,
    treasury_pubkey: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    txid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    raw_tx: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    birthday: Option<u32>,
}

/// Load ceremony state.
///
/// `Ok(None)` means neither the state file nor the capsule exists, so a new
/// ceremony may start. A capsule without this file is refused.
pub fn load(state_path: &Path, capsule_path: &Path) -> Result<Option<CeremonyState>, String> {
    let state_exists = path_exists(state_path)?;
    let capsule_exists = path_exists(capsule_path)?;
    match (state_exists, capsule_exists) {
        (false, false) => Ok(None),
        (false, true) => Err(format!(
            "{} exists but {} does not. This ceremony cannot be resumed or replaced. Do not delete the capsule.",
            capsule_path.display(),
            state_path.display()
        )),
        (true, false) => Err(format!(
            "{} exists but {} is missing.",
            state_path.display(),
            capsule_path.display()
        )),
        (true, true) => read_state(state_path).map(Some),
    }
}

/// Atomically replace the state file.
///
/// The temporary file is synced before it is renamed over the previous state.
pub fn store(state_path: &Path, state: &CeremonyState) {
    let record = Record::from(state);
    let bytes = toml::to_string(&record).expect("FATAL: serialize ceremony state");
    let tmp_path = temp_path(state_path);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp_path)
        .unwrap_or_else(|error| panic!("FATAL: create {}: {error}", tmp_path.display()));
    file.write_all(bytes.as_bytes())
        .unwrap_or_else(|error| panic!("FATAL: write {}: {error}", tmp_path.display()));
    file.sync_all()
        .unwrap_or_else(|error| panic!("FATAL: sync {}: {error}", tmp_path.display()));
    drop(file);
    fs::rename(&tmp_path, state_path).unwrap_or_else(|error| {
        panic!(
            "FATAL: rename {} to {}: {error}",
            tmp_path.display(),
            state_path.display()
        )
    });
    sync_parent(state_path);
}

fn read_state(path: &Path) -> Result<CeremonyState, String> {
    let text =
        fs::read_to_string(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    let record: Record =
        toml::from_str(&text).map_err(|error| format!("parse {}: {error}", path.display()))?;
    let state = CeremonyState::try_from(record)?;
    state
        .funding_info()
        .map_err(|error| format!("ceremony state: {error}"))?;
    Ok(state)
}

fn path_exists(path: &Path) -> Result<bool, String> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("inspect {}: {error}", path.display())),
    }
}

fn temp_path(path: &Path) -> PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    PathBuf::from(tmp)
}

fn sync_parent(path: &Path) {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|file| file.sync_all())
        .unwrap_or_else(|error| panic!("FATAL: sync parent of {}: {error}", path.display()));
}

fn parse_transparent_address(
    encoded: &str,
) -> Result<transparent::address::TransparentAddress, String> {
    let parsed: ZcashAddress = encoded
        .parse()
        .map_err(|error| format!("treasury address: {error}"))?;
    parsed
        .convert_if_network(NETWORK.network_type())
        .map_err(|error| format!("treasury address: {error:?}"))
}

fn decode_fixed_hex<const N: usize>(label: &str, hex_text: &str) -> Result<[u8; N], String> {
    let bytes = hex::decode(hex_text).map_err(|error| format!("{label}: {error}"))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{label}: expected {N} bytes, got {}", bytes.len()))
}

fn require_txid(txid: Option<String>) -> Result<String, String> {
    let txid = txid.ok_or("ceremony state is missing txid")?;
    let bytes = hex::decode(&txid).map_err(|error| format!("txid: {error}"))?;
    if bytes.len() != 32 {
        return Err(format!("txid: expected 32 bytes, got {}", bytes.len()));
    }
    Ok(txid)
}

fn require_raw_tx(raw_tx: Option<String>) -> Result<String, String> {
    let raw_tx = raw_tx.ok_or("ceremony state is missing raw_tx")?;
    let bytes = hex::decode(&raw_tx).map_err(|error| format!("raw_tx: {error}"))?;
    if bytes.is_empty() {
        return Err("raw_tx is empty".into());
    }
    Ok(raw_tx)
}

impl From<&CeremonyState> for Record {
    fn from(state: &CeremonyState) -> Self {
        Self {
            state: state.phase.as_str().to_string(),
            seed_fingerprint: state.fingerprint.to_string(),
            capsule_hash_blake2b256: hex::encode(state.capsule_hash),
            treasury_address: state.treasury_address.clone(),
            treasury_pubkey: state.treasury_pubkey.clone(),
            txid: state.txid.clone(),
            raw_tx: state.raw_tx.clone(),
            birthday: state.birthday,
        }
    }
}

impl TryFrom<Record> for CeremonyState {
    type Error = String;

    fn try_from(record: Record) -> Result<Self, Self::Error> {
        let phase = Phase::parse(&record.state)
            .ok_or_else(|| format!("unknown ceremony state {}", record.phase_label()))?;
        let fingerprint = record
            .seed_fingerprint
            .parse::<SeedFingerprint>()
            .map_err(|error| format!("seed fingerprint: {error:?}"))?;
        let capsule_hash = decode_fixed_hex("capsule hash", &record.capsule_hash_blake2b256)?;
        let (txid, raw_tx, birthday) = match phase {
            Phase::Sealed | Phase::WaitingForFunds | Phase::Funded => (None, None, None),
            Phase::AnchorBuilt | Phase::AnchorSubmitted => (
                Some(require_txid(record.txid)?),
                Some(require_raw_tx(record.raw_tx)?),
                None,
            ),
            Phase::AnchorBroadcast | Phase::Complete => {
                let birthday = record
                    .birthday
                    .ok_or("ceremony state is missing birthday")?;
                (Some(require_txid(record.txid)?), None, Some(birthday))
            }
        };
        Ok(Self {
            phase,
            fingerprint,
            capsule_hash,
            treasury_address: record.treasury_address,
            treasury_pubkey: record.treasury_pubkey,
            txid,
            raw_tx,
            birthday,
        })
    }
}

impl Record {
    fn phase_label(&self) -> &str {
        &self.state
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_funding() -> (String, String) {
        let funding = TreasuryFundingInfo::derive(&NETWORK, &[0x11; 32]);
        let address = funding
            .address()
            .to_zcash_address(NETWORK.network_type())
            .encode();
        let pubkey = hex::encode(funding.pubkey().serialize());
        (address, pubkey)
    }

    fn sealed_state() -> CeremonyState {
        let (address, pubkey) = sample_funding();
        CeremonyState::sealed(
            SeedFingerprint::from_bytes([0x22; 32]),
            [0x33; 32],
            address,
            pubkey,
        )
    }

    #[test]
    fn resume_actions_follow_the_ceremony_order() {
        let sealed = sealed_state();
        assert_eq!(sealed.resume_action(), ResumeAction::Attest);

        let waiting = sealed.clone().waiting_for_funds();
        assert_eq!(waiting.resume_action(), ResumeAction::WaitForFunding);

        let funded = waiting.clone().funded();
        assert_eq!(funded.resume_action(), ResumeAction::BuildAnchor);

        let built = funded
            .clone()
            .anchor_built("ab".repeat(32), "00ff".to_string());
        assert_eq!(built.resume_action(), ResumeAction::ResolveBroadcast);

        let txid = "ab".repeat(32);
        let submitted = built.clone().anchor_submitted();
        assert_eq!(submitted.resume_action(), ResumeAction::WaitForConfirmation);
        assert_eq!(submitted.txid(), Some(txid.as_str()));
        assert_eq!(submitted.raw_tx(), Some("00ff"));
        assert_eq!(submitted.birthday(), None);

        let broadcast = submitted.anchor_broadcast(4408922);
        assert_eq!(broadcast.resume_action(), ResumeAction::Finalize);
        assert_eq!(broadcast.birthday(), Some(4408922));
        assert_eq!(broadcast.txid(), Some(txid.as_str()));

        let complete = broadcast.complete();
        assert_eq!(complete.resume_action(), ResumeAction::Done);
    }

    #[test]
    fn expired_anchor_returns_to_funded_without_the_old_transaction() {
        let expired = sealed_state()
            .anchor_built("ab".repeat(32), "00ff".to_string())
            .expired_anchor();
        assert_eq!(expired.phase(), Phase::Funded);
        assert_eq!(expired.resume_action(), ResumeAction::BuildAnchor);
        assert_eq!(expired.txid(), None);
        assert_eq!(expired.raw_tx(), None);
        assert_eq!(expired.birthday(), None);

        let expired = sealed_state()
            .anchor_built("ab".repeat(32), "00ff".to_string())
            .anchor_submitted()
            .expired_anchor();
        assert_eq!(expired.phase(), Phase::Funded);
        assert_eq!(expired.resume_action(), ResumeAction::BuildAnchor);
        assert_eq!(expired.txid(), None);
        assert_eq!(expired.raw_tx(), None);
    }

    #[test]
    fn anchor_broadcast_never_resolves_or_rebuilds() {
        let state = sealed_state()
            .anchor_built("cd".repeat(32), "ab".to_string())
            .anchor_broadcast(10);
        assert_eq!(state.resume_action(), ResumeAction::Finalize);
        assert_ne!(state.resume_action(), ResumeAction::ResolveBroadcast);
        assert_ne!(state.resume_action(), ResumeAction::BuildAnchor);
    }

    #[test]
    fn absent_transaction_is_sent_once_from_storage() {
        assert_eq!(
            broadcast_action(AnchorLookup::Absent),
            BroadcastAction::SendStored
        );
    }

    #[test]
    fn birthday_is_the_confirmed_inclusion_height() {
        let inclusion: i64 = 4408922;
        assert_eq!(
            classify_anchor(Some(inclusion), Some(u64::from(ANCHOR_CONFIRMATIONS))),
            AnchorLookup::Confirmed {
                birthday: inclusion as u32
            }
        );
        assert_eq!(
            broadcast_action(classify_anchor(
                Some(inclusion),
                Some(u64::from(ANCHOR_CONFIRMATIONS))
            )),
            BroadcastAction::Confirmed {
                birthday: inclusion as u32
            }
        );
    }

    #[test]
    fn unconfirmed_anchor_does_not_take_a_birthday() {
        let pending = [
            classify_anchor(None, None),
            classify_anchor(None, Some(0)),
            classify_anchor(Some(4408922), None),
            classify_anchor(Some(4408922), Some(u64::from(ANCHOR_CONFIRMATIONS - 1))),
            classify_anchor(None, Some(100)),
            classify_anchor(Some(i64::from(u32::MAX) + 1), Some(100)),
        ];
        for lookup in pending {
            assert!(matches!(lookup, AnchorLookup::Pending { .. }));
            assert_eq!(broadcast_action(lookup), BroadcastAction::AwaitConfirmation);
        }
    }

    #[test]
    fn side_chain_anchor_is_resubmitted() {
        assert_eq!(classify_anchor(Some(-1), Some(0)), AnchorLookup::SideChain);
        assert_eq!(
            classify_anchor(Some(-1), Some(100)),
            AnchorLookup::SideChain
        );
        assert_eq!(
            broadcast_action(AnchorLookup::SideChain),
            BroadcastAction::SendStored
        );
    }

    #[test]
    fn a_reorg_before_confirmation_keeps_the_later_inclusion_height() {
        assert_eq!(
            broadcast_action(classify_anchor(Some(100), Some(3))),
            BroadcastAction::AwaitConfirmation
        );
        assert_eq!(
            broadcast_action(classify_anchor(
                Some(108),
                Some(u64::from(ANCHOR_CONFIRMATIONS))
            )),
            BroadcastAction::Confirmed { birthday: 108 }
        );
    }

    #[test]
    fn state_roundtrips_and_a_capsule_without_state_is_refused() {
        let dir = std::env::temp_dir().join(format!(
            "zns-keygen-ceremony-{}-{}",
            std::process::id(),
            "roundtrip"
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let state_path = dir.join("ceremony_state.toml");
        let capsule_path = dir.join("zns_seed.capsule");
        fs::write(&capsule_path, b"capsule").unwrap();

        let error = load(&state_path, &capsule_path).unwrap_err();
        assert!(error.contains("Do not delete the capsule"));

        let built = sealed_state().anchor_built("ef".repeat(32), "1234".to_string());
        store(&state_path, &built);
        let loaded = load(&state_path, &capsule_path).unwrap().unwrap();
        assert_eq!(loaded, built);
        assert!(loaded.funding_info().is_ok());

        let submitted = built.anchor_submitted();
        store(&state_path, &submitted);
        let loaded = load(&state_path, &capsule_path).unwrap().unwrap();
        assert_eq!(loaded, submitted);
        assert_eq!(loaded.resume_action(), ResumeAction::WaitForConfirmation);
        assert_eq!(loaded.raw_tx(), Some("1234"));
        assert_eq!(loaded.birthday(), None);

        let broadcast = submitted.anchor_broadcast(4408922);
        store(&state_path, &broadcast);
        let loaded = load(&state_path, &capsule_path).unwrap().unwrap();
        assert_eq!(loaded.phase(), Phase::AnchorBroadcast);
        assert_eq!(loaded.birthday(), Some(4408922));
        assert!(loaded.raw_tx().is_none());
        assert_eq!(loaded.resume_action(), ResumeAction::Finalize);

        fs::remove_file(&capsule_path).unwrap();
        let error = load(&state_path, &capsule_path).unwrap_err();
        assert!(error.contains("is missing"));

        fs::remove_dir_all(&dir).unwrap();
    }
}
