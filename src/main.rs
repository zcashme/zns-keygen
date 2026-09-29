//! zns-keygen — ZNS mint key genesis ceremony.

mod anchor;
mod attestation;
mod ceremony;
mod fingerprint;
mod keys;
mod rpc;

use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
#[cfg(target_os = "linux")]
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use std::fs::{self, File, OpenOptions};
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use std::hint::spin_loop;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;
use zeroize::{Zeroize, Zeroizing};

use fingerprint::SeedFingerprint;
use keys::{AnchorMaterial, TreasuryFundingInfo};

const KEYS_DIR: &str = "keys";
const CAPSULE_FILE: &str = "keys/zns_seed.capsule";
const MANIFEST_FILE: &str = "keys/zns_custody_manifest.toml";
const MINT_CONFIG_FILE: &str = "keys/zns_mint.conf";
const ATTESTATION_FILE: &str = "keys/zns_attestation.bin";

const REPORT_DATA_LEN: usize = 64;
const TREASURY_ACCOUNT: u32 = 0;
const REGISTRY_ACCOUNT: u32 = 1;
const SEED_LEN: usize = 32;
const FINGERPRINT_LEN: usize = 32;
const SEALING_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CIPHERTEXT_LEN: usize = SEED_LEN + TAG_LEN;
const CAPSULE_MAGIC: [u8; 8] = *b"ZNS_SEED";

const _: () = assert!(SEED_LEN >= 32);
const _: () = assert!(SEED_LEN <= 252);
const _: () = assert!(FINGERPRINT_LEN == 32);
const _: () = assert!(SEALING_KEY_LEN == 32);
const _: () = assert!(NONCE_LEN == 24);
const _: () = assert!(TAG_LEN == 16);
const _: () = assert!(CIPHERTEXT_LEN == SEED_LEN + TAG_LEN);

#[cfg(not(feature = "testnet"))]
type Network = zcash_protocol::consensus::MainNetwork;
#[cfg(not(feature = "testnet"))]
const NETWORK: Network = zcash_protocol::consensus::MAIN_NETWORK;
#[cfg(not(feature = "testnet"))]
const NETWORK_LABEL: &str = "mainnet";

#[cfg(feature = "testnet")]
type Network = zcash_protocol::consensus::TestNetwork;
#[cfg(feature = "testnet")]
const NETWORK: Network = zcash_protocol::consensus::TEST_NETWORK;
#[cfg(feature = "testnet")]
const NETWORK_LABEL: &str = "testnet";

const POLL_INTERVAL: Duration = Duration::from_secs(10);

enum Command {
    Help,
    Run,
}

fn main() {
    match command_from(std::env::args()) {
        Ok(Command::Help) => println!("{}", usage()),
        Ok(Command::Run) => run_ceremony(),
        Err(message) => {
            eprintln!("{message}\n\n{}", usage());
            std::process::exit(2);
        }
    }
}

fn usage() -> String {
    format!(
        "\
zns-keygen — one-shot ZNS genesis custody ceremony ({NETWORK_LABEL})

USAGE:
    zns-keygen
    zns-keygen --help

With no arguments, generate a seed, seal it, attest the capsule, wait for
Treasury funding, and broadcast the genesis anchor transaction. A later run
resumes from keys/ceremony_state.toml instead of generating another seed.

The network is chosen at compile time. This binary is {NETWORK_LABEL}.

OPTIONS:
    -h, --help    Print this help and exit
"
    )
}

fn command_from<I, S>(args: I) -> Result<Command, String>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut args = args.into_iter();
    let _program = args.next();
    match args.next() {
        None => Ok(Command::Run),
        Some(arg) if matches!(arg.as_ref(), "-h" | "--help") => match args.next() {
            None => Ok(Command::Help),
            Some(extra) => Err(format!(
                "unexpected argument after --help: {}",
                extra.as_ref()
            )),
        },
        Some(arg) => Err(format!("unrecognized argument: {}", arg.as_ref())),
    }
}

fn run_ceremony() {
    tracing_subscriber::fmt().init();
    tracing::info!("=== ZNS KEY GENESIS ===");
    tracing::info!(network = NETWORK_LABEL, "starting ceremony");

    fs::create_dir_all(KEYS_DIR).expect("FATAL: cannot create keys directory");

    let state_path = Path::new(ceremony::STATE_FILE);
    let capsule_path = Path::new(CAPSULE_FILE);
    let mut state = match ceremony::load(state_path, capsule_path) {
        Ok(Some(state)) => {
            tracing::info!(phase = %state.phase(), "resuming ceremony");
            state
        }
        Ok(None) => begin_ceremony(state_path, capsule_path),
        Err(error) => panic!("FATAL: {error}"),
    };

    loop {
        state = match state.resume_action() {
            ceremony::ResumeAction::Attest => attest(state, state_path),
            ceremony::ResumeAction::WaitForFunding => wait_for_funding(state, state_path),
            ceremony::ResumeAction::BuildAnchor => build_anchor(state, state_path, capsule_path),
            ceremony::ResumeAction::ResolveBroadcast => resolve_broadcast(state, state_path),
            ceremony::ResumeAction::WaitForConfirmation => wait_for_confirmation(state, state_path),
            ceremony::ResumeAction::Finalize => finalize(state, state_path),
            ceremony::ResumeAction::Done => {
                tracing::info!("=== CEREMONY COMPLETE ===");
                return;
            }
        };
    }
}

fn begin_ceremony(state_path: &Path, capsule_path: &Path) -> ceremony::CeremonyState {
    ensure_absent(capsule_path);
    ensure_absent(Path::new(MANIFEST_FILE));
    ensure_absent(Path::new(MINT_CONFIG_FILE));
    ensure_absent(Path::new(ATTESTATION_FILE));
    ensure_absent(state_path);

    let (fingerprint, capsule_hash, funding) = {
        let seed = Seed::generate();
        let fingerprint = seed.fingerprint();
        tracing::info!("seed fingerprint: {fingerprint}");

        let funding = seed.expose(|seed_bytes| TreasuryFundingInfo::derive(&NETWORK, seed_bytes));

        tracing::info!("=== SEALING ===");
        let sealing_key = derive_sealing_key();
        let capsule = seal_seed(&seed, &sealing_key, fingerprint);
        let capsule_bytes = postcard::to_allocvec(&capsule).expect("FATAL: serialize capsule");
        let capsule_hash = blake2b256(&capsule_bytes);
        write_secret_file(capsule_path, &capsule_bytes);
        tracing::info!("capsule persisted; dropping plaintext seed");
        drop(seed);
        drop(sealing_key);
        (fingerprint, capsule_hash, funding)
    };

    let treasury_address = funding
        .address()
        .to_zcash_address(NETWORK.network_type())
        .encode();
    let treasury_pubkey = hex::encode(funding.pubkey().serialize());
    let state = ceremony::CeremonyState::sealed(
        fingerprint,
        capsule_hash,
        treasury_address,
        treasury_pubkey,
    );
    ceremony::store(state_path, &state);
    tracing::info!(phase = %state.phase(), "ceremony state persisted");
    state
}

fn attest(state: ceremony::CeremonyState, state_path: &Path) -> ceremony::CeremonyState {
    let attestation_path = Path::new(ATTESTATION_FILE);
    let expected = attestation::report_data(state.fingerprint(), state.capsule_hash());
    match fs::symlink_metadata(attestation_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            panic!("FATAL: {} is a symlink", attestation_path.display());
        }
        Ok(_) => {
            let bytes = fs::read(attestation_path).expect("FATAL: read attestation");
            let _checked = attestation::stored(bytes, &expected);
            tracing::info!("attestation already persisted");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("=== ATTESTATION ===");
            let attestation = attestation::request(&expected);
            write_atomic(attestation_path, &attestation.report_bytes, 0o644);
            tracing::info!("attestation persisted");
        }
        Err(error) => panic!("FATAL: inspect {}: {error}", attestation_path.display()),
    }
    let state = state.waiting_for_funds();
    ceremony::store(state_path, &state);
    tracing::info!(phase = %state.phase(), "ceremony state persisted");
    state
}

fn wait_for_funding(state: ceremony::CeremonyState, state_path: &Path) -> ceremony::CeremonyState {
    let funding = state
        .funding_info()
        .expect("FATAL: ceremony state has no funding address");
    let taddr_encoded = funding
        .address()
        .to_zcash_address(NETWORK.network_type())
        .encode();
    tracing::info!("=== FUNDING ===");
    tracing::info!("Treasury t-address: {taddr_encoded}");
    tracing::info!("send {NETWORK_LABEL} ZEC to: {taddr_encoded}");
    tracing::info!("minimum 500,000 zat (0.005 ZEC) for 40 anchors + Treasury change");
    let _inputs = poll_until_funded(&funding);
    let state = state.funded();
    ceremony::store(state_path, &state);
    tracing::info!(phase = %state.phase(), "ceremony state persisted");
    state
}

fn build_anchor(
    state: ceremony::CeremonyState,
    state_path: &Path,
    capsule_path: &Path,
) -> ceremony::CeremonyState {
    let funding = state
        .funding_info()
        .expect("FATAL: ceremony state has no funding address");
    let inputs = poll_until_funded(&funding);
    let fingerprint = *state.fingerprint();

    let sealing_key = derive_sealing_key();
    let capsule = read_capsule(capsule_path);
    let seed = unseal_seed(&capsule, &sealing_key).expect("FATAL: unseal capsule");
    assert_eq!(
        seed.fingerprint(),
        fingerprint,
        "FATAL: unsealed seed fingerprint does not match the ceremony fingerprint"
    );

    tracing::info!("=== ANCHOR CREATION ===");
    let (tip_height, _) = rpc::Rpc::tip().expect("FATAL: Zebra unreachable");
    tracing::info!(height = u32::from(tip_height), "chain tip");

    let mut material = seed.expose(|seed_bytes| AnchorMaterial::derive(&NETWORK, seed_bytes));
    drop(seed);
    drop(sealing_key);

    let tx = anchor::build_anchor_transaction(
        &NETWORK,
        &mut material.treasury_signing_key,
        &material.treasury_orchard_fvk,
        &material.registry_orchard_fvk,
        tip_height,
        &inputs,
    );
    drop(material);

    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes).expect("FATAL: serialize tx");
    let raw_tx = hex::encode(&tx_bytes);
    let txid = tx.txid().to_string();
    tracing::info!(txid, "anchor tx built");

    let state = state.anchor_built(txid, raw_tx);
    ceremony::store(state_path, &state);
    tracing::info!(phase = %state.phase(), "ceremony state persisted before broadcast");
    state
}

fn resolve_broadcast(state: ceremony::CeremonyState, state_path: &Path) -> ceremony::CeremonyState {
    let txid = state
        .txid()
        .expect("FATAL: built anchor has no txid")
        .to_string();
    loop {
        let lookup = anchor_lookup(&txid);
        match ceremony::broadcast_action(lookup) {
            ceremony::BroadcastAction::SendStored => {
                tracing::info!(txid, "broadcasting stored anchor");
                match submit_stored_anchor(&state, state_path, &txid) {
                    StoredSubmit::Accepted => return record_submitted(state, state_path, &txid),
                    StoredSubmit::Expired(state) => return state,
                    StoredSubmit::Rejected => std::thread::sleep(POLL_INTERVAL),
                }
            }
            ceremony::BroadcastAction::AwaitConfirmation => {
                tracing::info!(txid, "stored anchor is known; waiting for confirmation");
                return record_submitted(state, state_path, &txid);
            }
            ceremony::BroadcastAction::Confirmed { birthday } => {
                return record_confirmed(state, state_path, &txid, birthday);
            }
        }
    }
}

/// Poll until the stored anchor's best-chain inclusion can be the birthday.
///
/// A restart stays on this transaction. The chain tip is not a birthday. An
/// RPC failure, a mempool entry, or a side chain leaves the ceremony pending.
fn wait_for_confirmation(
    state: ceremony::CeremonyState,
    state_path: &Path,
) -> ceremony::CeremonyState {
    let txid = state
        .txid()
        .expect("FATAL: submitted anchor has no txid")
        .to_string();
    loop {
        let lookup = anchor_lookup(&txid);
        match ceremony::broadcast_action(lookup) {
            ceremony::BroadcastAction::SendStored => {
                tracing::warn!(
                    txid,
                    "stored anchor is not in the mempool or best chain; rebroadcasting the same transaction"
                );
                match submit_stored_anchor(&state, state_path, &txid) {
                    StoredSubmit::Accepted => {
                        tracing::info!(
                            txid,
                            "same anchor rebroadcast; still waiting for inclusion"
                        );
                    }
                    StoredSubmit::Expired(state) => return state,
                    StoredSubmit::Rejected => {}
                }
                std::thread::sleep(POLL_INTERVAL);
            }
            ceremony::BroadcastAction::AwaitConfirmation => {
                let ceremony::AnchorLookup::Pending {
                    height,
                    confirmations,
                } = lookup
                else {
                    panic!("FATAL: confirmation wait expected a pending anchor observation");
                };
                tracing::info!(
                    txid,
                    ?height,
                    ?confirmations,
                    required = ceremony::ANCHOR_CONFIRMATIONS,
                    "anchor not yet confirmed"
                );
                std::thread::sleep(POLL_INTERVAL);
            }
            ceremony::BroadcastAction::Confirmed { birthday } => {
                return record_confirmed(state, state_path, &txid, birthday);
            }
        }
    }
}

fn anchor_lookup(txid: &str) -> ceremony::AnchorLookup {
    loop {
        match rpc::Rpc::transaction_presence(txid) {
            Ok(rpc::TxLookup::Absent) => return ceremony::AnchorLookup::Absent,
            Ok(rpc::TxLookup::Found {
                height,
                confirmations,
            }) => return ceremony::classify_anchor(height, confirmations),
            Err(error) => {
                tracing::warn!(%error, txid, "anchor lookup failed; retrying");
                std::thread::sleep(POLL_INTERVAL);
            }
        }
    }
}

enum StoredSubmit {
    Accepted,
    Expired(ceremony::CeremonyState),
    /// Zebra answered, but did not accept the transaction. Look it up again.
    Rejected,
}

/// Submit the stored raw transaction and no other.
///
/// An expiry rejection is the only reason to discard it. Any other RPC failure
/// stays on this transaction.
fn submit_stored_anchor(
    state: &ceremony::CeremonyState,
    state_path: &Path,
    txid: &str,
) -> StoredSubmit {
    let raw_tx = state
        .raw_tx()
        .expect("FATAL: stored anchor has no raw transaction")
        .to_string();
    match rpc::Rpc::send_raw(&raw_tx) {
        Ok(sent) => {
            if sent != txid {
                panic!("FATAL: broadcast txid {sent} does not match stored {txid}");
            }
            StoredSubmit::Accepted
        }
        Err(error) if rpc::transaction_is_expired(&error) => {
            tracing::warn!(
                txid,
                "stored anchor expired before it was mined; rebuilding"
            );
            let state = state.clone().expired_anchor();
            ceremony::store(state_path, &state);
            tracing::info!(
                phase = %state.phase(),
                "expired anchor discarded; rebuilding from funded state"
            );
            StoredSubmit::Expired(state)
        }
        Err(error) => {
            tracing::warn!(%error, txid, "broadcast of stored anchor failed; retrying");
            StoredSubmit::Rejected
        }
    }
}

fn record_submitted(
    state: ceremony::CeremonyState,
    state_path: &Path,
    txid: &str,
) -> ceremony::CeremonyState {
    let state = state.anchor_submitted();
    ceremony::store(state_path, &state);
    tracing::info!(
        phase = %state.phase(),
        txid,
        "anchor submitted; birthday waits for best-chain confirmation"
    );
    state
}

fn record_confirmed(
    state: ceremony::CeremonyState,
    state_path: &Path,
    txid: &str,
    birthday: u32,
) -> ceremony::CeremonyState {
    let state = state.anchor_broadcast(birthday);
    ceremony::store(state_path, &state);
    tracing::info!(
        phase = %state.phase(),
        txid,
        birthday,
        "anchor confirmed; birthday is its best-chain inclusion height"
    );
    state
}

fn finalize(state: ceremony::CeremonyState, state_path: &Path) -> ceremony::CeremonyState {
    let fingerprint = *state.fingerprint();
    let capsule_hash = *state.capsule_hash();
    let birthday = BlockHeight::from_u32(
        state
            .birthday()
            .expect("FATAL: broadcast anchor has no birthday"),
    );
    let expected = attestation::report_data(&fingerprint, &capsule_hash);
    let report_bytes =
        fs::read(ATTESTATION_FILE).expect("FATAL: attestation missing at finalization");
    let attestation = attestation::stored(report_bytes, &expected);
    let report_data_hash = blake2b256(&expected);
    let attestation_hash = blake2b256(&attestation.report_bytes);
    let measurement = hex::encode(attestation.measurement);
    let manifest = custody_manifest(
        fingerprint,
        &capsule_hash,
        &report_data_hash,
        &attestation_hash,
        &measurement,
        attestation.guest_policy,
        &attestation.tcb_version,
    );
    let mint_config = mint_config_toml_with_birthday(fingerprint, birthday);
    write_atomic_verified(Path::new(MANIFEST_FILE), manifest.as_bytes(), 0o644);
    write_atomic_verified(Path::new(MINT_CONFIG_FILE), mint_config.as_bytes(), 0o600);

    let state = state.complete();
    ceremony::store(state_path, &state);
    tracing::info!(
        birthday = u32::from(birthday),
        "manifest and mint config written"
    );
    state
}

/// Poll Zebra until the Treasury address is funded.
///
/// Takes only the public funding address and pubkey. Spending keys are not
/// in scope for this wait.
fn poll_until_funded(
    funding: &TreasuryFundingInfo,
) -> Vec<transparent::builder::TransparentInputInfo> {
    let pubkey = funding.pubkey();
    loop {
        match check_funding(funding.address()) {
            Some(raw) => {
                let built: Vec<_> = raw.into_iter().map(|u| utxo_to_input(&u, pubkey)).collect();
                tracing::info!(inputs = built.len(), "funding sufficient");
                return built;
            }
            None => std::thread::sleep(POLL_INTERVAL),
        }
    }
}

/// Check for sufficient UTXOs.
///
/// An empty address is "no funding yet". A Zebra failure is logged and
/// retried by the caller. It is not treated as an empty address.
fn check_funding(addr: &transparent::address::TransparentAddress) -> Option<Vec<rpc::AddressUtxo>> {
    let encoded = addr.to_zcash_address(NETWORK.network_type()).encode();
    match funding_utxos(rpc::Rpc::address_utxos(&encoded)) {
        Ok(Some(utxos)) => Some(utxos),
        Ok(None) => {
            tracing::info!("no funding yet");
            None
        }
        Err(error) => {
            tracing::warn!(%error, "Treasury funding check failed; retrying");
            None
        }
    }
}

fn funding_utxos(
    result: Result<Vec<rpc::AddressUtxo>, String>,
) -> Result<Option<Vec<rpc::AddressUtxo>>, String> {
    let utxos = result?;
    if utxos.is_empty() {
        return Ok(None);
    }
    let total: u64 = utxos.iter().map(|u| u.satoshis).sum();
    assert!(
        total >= 500_000,
        "FATAL: insufficient funding: {total} zat, need at least 500,000"
    );
    Ok(Some(utxos))
}

/// Convert RPC UTXO to transparent input.
fn utxo_to_input(
    u: &rpc::AddressUtxo,
    pubkey: secp256k1::PublicKey,
) -> transparent::builder::TransparentInputInfo {
    let mut txid_bytes = hex::decode(&u.txid).expect("FATAL: txid hex");
    txid_bytes.reverse();
    let mut txid_arr = [0u8; 32];
    txid_arr.copy_from_slice(&txid_bytes);

    let outpoint = transparent::bundle::OutPoint::new(txid_arr, u.output_index);
    let value = Zatoshis::from_u64(u.satoshis).expect("FATAL: satoshis");
    let script_bytes = hex::decode(&u.script).expect("FATAL: script hex");
    let script = transparent::address::Script(zcash_script::script::Code(script_bytes));
    let coin = transparent::bundle::TxOut::new(value, script);

    transparent::builder::TransparentInputInfo::from_parts(
        outpoint,
        coin,
        transparent::builder::SpendInfo::P2pkh { pubkey },
    )
    .expect("FATAL: transparent input")
}

// ── Seed ──────────────────────────────────────────────────────────

struct Seed(Zeroizing<[u8; SEED_LEN]>);

impl Seed {
    fn generate() -> Seed {
        let mut seed = Seed(Zeroizing::new([0u8; SEED_LEN]));
        fill_entropy(&mut seed.0[..]);
        assert!(!seed.0.iter().all(|&b| b == 0), "RDSEED all zeros");
        assert!(!seed.0.iter().all(|&b| b == 0xff), "RDSEED all 0xFF");
        seed
    }

    fn expose<R>(&self, f: impl FnOnce(&[u8; SEED_LEN]) -> R) -> R {
        f(&self.0)
    }

    fn fingerprint(&self) -> SeedFingerprint {
        self.expose(|s| SeedFingerprint::from_seed(s).expect("SEED_LEN const-asserted"))
    }

    fn from_bytes(bytes: [u8; SEED_LEN]) -> Seed {
        Seed(Zeroizing::new(bytes))
    }
}

// ── Sealing key ───────────────────────────────────────────────────

struct SealingKey(Zeroizing<[u8; SEALING_KEY_LEN]>);

impl SealingKey {
    fn as_bytes(&self) -> &[u8; SEALING_KEY_LEN] {
        &self.0
    }

    #[cfg(test)]
    fn from_bytes(bytes: [u8; SEALING_KEY_LEN]) -> Self {
        SealingKey(Zeroizing::new(bytes))
    }
}

// ── Capsule ───────────────────────────────────────────────────────

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct SeedCapsule {
    magic: [u8; 8],
    fingerprint: [u8; FINGERPRINT_LEN],
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn seal_seed(seed: &Seed, sealing_key: &SealingKey, fingerprint: SeedFingerprint) -> SeedCapsule {
    let mut nonce = [0u8; NONCE_LEN];
    fill_entropy(&mut nonce);
    let capsule = seal_seed_with_nonce(seed, sealing_key, fingerprint, nonce);
    nonce.zeroize();
    capsule
}

fn seal_seed_with_nonce(
    seed: &Seed,
    sealing_key: &SealingKey,
    fingerprint: SeedFingerprint,
    nonce: [u8; NONCE_LEN],
) -> SeedCapsule {
    let cipher = XChaCha20Poly1305::new_from_slice(sealing_key.as_bytes())
        .expect("key length const-asserted");
    let aad = capsule_aad(fingerprint);
    let nonce_ref = <&XNonce>::from(nonce.as_slice());
    let ciphertext = seed
        .expose(|s| cipher.encrypt(nonce_ref, Payload { msg: s, aad: &aad }))
        .expect("FATAL: encrypt seed");
    assert_eq!(ciphertext.len(), CIPHERTEXT_LEN);
    SeedCapsule {
        magic: CAPSULE_MAGIC,
        fingerprint: fingerprint.to_bytes(),
        nonce: nonce.to_vec(),
        ciphertext,
    }
}

#[derive(Debug, PartialEq, Eq)]
enum UnsealError {
    InvalidMagic,
    InvalidNonce,
    AuthenticationFailed,
    InvalidSeedLength,
    FingerprintMismatch,
}

/// Inverse of `seal_seed`: decrypt the capsule and require the ZIP-32 fingerprint to match.
fn unseal_seed(capsule: &SeedCapsule, sealing_key: &SealingKey) -> Result<Seed, UnsealError> {
    if capsule.magic != CAPSULE_MAGIC {
        return Err(UnsealError::InvalidMagic);
    }
    if capsule.nonce.len() != NONCE_LEN {
        return Err(UnsealError::InvalidNonce);
    }
    let fingerprint = SeedFingerprint::from_bytes(capsule.fingerprint);
    let aad = capsule_aad(fingerprint);
    let cipher = XChaCha20Poly1305::new_from_slice(sealing_key.as_bytes())
        .expect("key length const-asserted");
    let nonce_ref = <&XNonce>::from(capsule.nonce.as_slice());
    let mut plaintext = cipher
        .decrypt(
            nonce_ref,
            Payload {
                msg: &capsule.ciphertext,
                aad: &aad,
            },
        )
        .map_err(|_| UnsealError::AuthenticationFailed)?;
    if plaintext.len() != SEED_LEN {
        plaintext.zeroize();
        return Err(UnsealError::InvalidSeedLength);
    }
    let mut seed_bytes = [0u8; SEED_LEN];
    seed_bytes.copy_from_slice(&plaintext);
    plaintext.zeroize();
    let seed = Seed::from_bytes(seed_bytes);
    seed_bytes.zeroize();
    if seed.fingerprint() != fingerprint {
        return Err(UnsealError::FingerprintMismatch);
    }
    Ok(seed)
}

fn read_capsule(path: &Path) -> SeedCapsule {
    let bytes = fs::read(path).expect("FATAL: read capsule");
    postcard::from_bytes(&bytes).expect("FATAL: deserialize capsule")
}

fn capsule_aad(fingerprint: SeedFingerprint) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CAPSULE_MAGIC.len() + FINGERPRINT_LEN);
    aad.extend_from_slice(&CAPSULE_MAGIC);
    aad.extend_from_slice(&fingerprint.to_bytes());
    aad
}

// ── Manifest ──────────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct CustodyManifest {
    manifest_version: u8,
    network: &'static str,
    seed_fingerprint: String,
    capsule_file: &'static str,
    capsule_hash_blake2b256: String,
    capsule_format: String,
    seed_length: usize,
    treasury_account: u32,
    registry_account: u32,
    sealing: &'static str,
    sealing_root_key: &'static str,
    sealing_guest_fields: &'static str,
    guest_policy: String,
    tcb_version: String,
    rng: &'static str,
    attestation_file: &'static str,
    attestation_hash_blake2b256: String,
    report_data_hash_blake2b256: String,
    measurement: String,
    attestation_sig_algo: &'static str,
    migration: &'static str,
    signer_socket: &'static str,
}

fn custody_manifest(
    fingerprint: SeedFingerprint,
    capsule_hash: &[u8; 32],
    report_data_hash: &[u8; 32],
    attestation_hash: &[u8; 32],
    measurement: &str,
    guest_policy: u64,
    tcb_version: &str,
) -> String {
    let m = CustodyManifest {
        manifest_version: 1,
        network: NETWORK_LABEL,
        seed_fingerprint: fingerprint.to_string(),
        capsule_file: CAPSULE_FILE,
        capsule_hash_blake2b256: hex::encode(capsule_hash),
        capsule_format: String::from_utf8(CAPSULE_MAGIC.to_vec()).expect("FATAL: capsule magic"),
        seed_length: SEED_LEN,
        treasury_account: TREASURY_ACCOUNT,
        registry_account: REGISTRY_ACCOUNT,
        sealing: "amd-sev-snp-derived-key",
        sealing_root_key: "vcek",
        sealing_guest_fields: "guest_policy,measurement",
        guest_policy: format!("0x{guest_policy:016x}"),
        tcb_version: tcb_version.to_string(),
        rng: "rdseed",
        attestation_file: ATTESTATION_FILE,
        attestation_hash_blake2b256: hex::encode(attestation_hash),
        report_data_hash_blake2b256: hex::encode(report_data_hash),
        measurement: measurement.to_string(),
        attestation_sig_algo: "ecdsa-p384-sha384",
        migration: "none",
        signer_socket: "none",
    };
    toml::to_string(&m).expect("FATAL: serialize custody manifest")
}

// ── Mint config ───────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct MintConfigWithBirthday {
    network: &'static str,
    expected_seed_fingerprint: String,
    birthday: u32,
}

fn mint_config_toml_with_birthday(fingerprint: SeedFingerprint, birthday: BlockHeight) -> String {
    toml::to_string(&MintConfigWithBirthday {
        network: NETWORK_LABEL,
        expected_seed_fingerprint: fingerprint.to_string(),
        birthday: u32::from(birthday),
    })
    .expect("FATAL: serialize mint config")
}

// ── Hashing ───────────────────────────────────────────────────────

fn blake2b256(bytes: &[u8]) -> [u8; 32] {
    let digest = Blake2bParams::new()
        .hash_length(32)
        .to_state()
        .update(bytes)
        .finalize();
    digest.as_bytes()[..32].try_into().expect("BLAKE2b fixed")
}

// ── RDSEED ────────────────────────────────────────────────────────

/// RDSEED entropy (x86_64 Linux only).
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn fill_entropy(dest: &mut [u8]) {
    if dest.is_empty() {
        return;
    }
    let mut offset = 0;
    while offset < dest.len() {
        let mut value = 0u64;
        for attempt in 0..10_000 {
            unsafe {
                if core::arch::x86_64::_rdseed64_step(&mut value) == 1 {
                    break;
                }
            }
            if attempt % 1000 == 999 {
                std::thread::yield_now();
            }
            spin_loop();
        }
        if value == 0 {
            panic!("FATAL: RDSEED unavailable");
        }
        let bytes = value.to_ne_bytes();
        let take = std::cmp::min(bytes.len(), dest.len() - offset);
        dest[offset..offset + take].copy_from_slice(&bytes[..take]);
        value.zeroize();
        offset += take;
    }
}

/// Fallback entropy (dev only).
#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn fill_entropy(dest: &mut [u8]) {
    use std::io::Read;
    std::io::stdin()
        .read_exact(dest)
        .expect("FATAL: entropy unavailable");
}

// ── Sealing key derivation ────────────────────────────────────────

#[cfg(target_os = "linux")]
fn derive_sealing_key() -> SealingKey {
    let mut firmware = Firmware::open().expect("FATAL: open /dev/sev-guest");
    let mut gf = GuestFieldSelect::default();
    gf.set_guest_policy(true);
    gf.set_measurement(true);
    let request = DerivedKey::new(false, gf, 0, 0, 0, None);
    let mut key = firmware
        .get_derived_key(Some(1), request)
        .expect("FATAL: derive SEV-SNP sealing key");
    let sk = SealingKey(Zeroizing::new(key));
    key.zeroize();
    sk
}

#[cfg(not(target_os = "linux"))]
fn derive_sealing_key() -> SealingKey {
    SealingKey(Zeroizing::new([0u8; SEALING_KEY_LEN]))
}

// ── File I/O ──────────────────────────────────────────────────────

fn ensure_absent(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(_) => panic!("FATAL: {} already exists", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("FATAL: inspect {}: {e}", path.display()),
    }
}

fn write_secret_file(path: &Path, bytes: &[u8]) {
    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("FATAL: create secret file");
    f.write_all(bytes).expect("FATAL: write file");
    f.sync_all().expect("FATAL: sync file");
    sync_parent(path);
}

/// Create `path` by renaming a synced temporary file into place.
///
/// A crash during the write leaves the previous file, or no file, rather than
/// a short one. `mode` is the permission of the temporary file before the rename.
fn write_atomic(path: &Path, bytes: &[u8], mode: u32) {
    let tmp_path = temp_sibling(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp_path)
        .unwrap_or_else(|error| panic!("FATAL: create {}: {error}", tmp_path.display()));
    file.write_all(bytes)
        .unwrap_or_else(|error| panic!("FATAL: write {}: {error}", tmp_path.display()));
    file.sync_all()
        .unwrap_or_else(|error| panic!("FATAL: sync {}: {error}", tmp_path.display()));
    drop(file);
    fs::rename(&tmp_path, path).unwrap_or_else(|error| {
        panic!(
            "FATAL: rename {} to {}: {error}",
            tmp_path.display(),
            path.display()
        )
    });
    sync_parent(path);
}

/// Create `path` if it is absent. If it already exists, require those exact bytes.
///
/// A short file left by a crash does not match, so finalization will not mark
/// the ceremony complete over it.
fn write_atomic_verified(path: &Path, expected: &[u8], mode: u32) {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            panic!("FATAL: {} is a symlink", path.display());
        }
        Ok(_) => {
            let existing = fs::read(path)
                .unwrap_or_else(|error| panic!("FATAL: read {}: {error}", path.display()));
            assert_eq!(
                existing,
                expected,
                "FATAL: existing {} does not match expected contents",
                path.display()
            );
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            write_atomic(path, expected, mode);
        }
        Err(error) => panic!("FATAL: inspect {}: {error}", path.display()),
    }
}

fn temp_sibling(path: &Path) -> std::path::PathBuf {
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".tmp");
    std::path::PathBuf::from(tmp)
}

fn sync_parent(path: &Path) {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|f| f.sync_all())
        .expect("FATAL: sync parent");
}

// ── Tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn help_does_not_select_the_ceremony() {
        assert!(matches!(
            command_from(["zns-keygen", "--help"]),
            Ok(Command::Help)
        ));
        assert!(matches!(
            command_from(["zns-keygen", "-h"]),
            Ok(Command::Help)
        ));
        assert!(matches!(command_from(["zns-keygen"]), Ok(Command::Run)));
        assert!(command_from(["zns-keygen", "--nope"]).is_err());
    }

    #[test]
    fn usage_names_help_and_the_compiled_network() {
        let text = usage();
        assert!(text.contains("--help"));
        assert!(text.contains(NETWORK_LABEL));
    }

    #[test]
    fn known_seed_matches_zip32_reference_vector() {
        let seed_bytes: [u8; SEED_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let expected: [u8; 32] = [
            0xde, 0xff, 0x60, 0x4c, 0x24, 0x67, 0x10, 0xf7, 0x17, 0x6d, 0xea, 0xd0, 0x2a, 0xa7,
            0x46, 0xf2, 0xfd, 0x8d, 0x53, 0x89, 0xf7, 0x07, 0x25, 0x56, 0xdc, 0xb5, 0x55, 0xfd,
            0xbe, 0x5e, 0x3a, 0xe3,
        ];
        let fp = SeedFingerprint::from_seed(&seed_bytes).unwrap();
        assert_eq!(fp.to_bytes(), expected);
    }

    fn test_seed_and_key() -> (Seed, SealingKey, SeedFingerprint) {
        let seed_bytes: [u8; SEED_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let seed = Seed::from_bytes(seed_bytes);
        let fingerprint = seed.fingerprint();
        let key = SealingKey::from_bytes([0x42; SEALING_KEY_LEN]);
        (seed, key, fingerprint)
    }

    fn roundtrip_capsule(
        seed: &Seed,
        key: &SealingKey,
        fingerprint: SeedFingerprint,
    ) -> SeedCapsule {
        let capsule = seal_seed_with_nonce(seed, key, fingerprint, [0x11; NONCE_LEN]);
        let bytes = postcard::to_allocvec(&capsule).unwrap();
        postcard::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn seal_serialize_deserialize_unseal_returns_original_seed() {
        let (seed, key, fingerprint) = test_seed_and_key();
        let decoded = roundtrip_capsule(&seed, &key, fingerprint);
        let opened = unseal_seed(&decoded, &key).unwrap();
        seed.expose(|original| {
            opened.expose(|recovered| assert_eq!(original, recovered));
        });
    }

    #[test]
    fn modified_ciphertext_fails_authentication() {
        let (seed, key, fingerprint) = test_seed_and_key();
        let mut capsule = roundtrip_capsule(&seed, &key, fingerprint);
        capsule.ciphertext[0] ^= 0x01;
        assert!(matches!(
            unseal_seed(&capsule, &key),
            Err(UnsealError::AuthenticationFailed)
        ));
    }

    #[test]
    fn modified_nonce_fails_authentication() {
        let (seed, key, fingerprint) = test_seed_and_key();
        let mut capsule = roundtrip_capsule(&seed, &key, fingerprint);
        capsule.nonce[0] ^= 0x01;
        assert!(matches!(
            unseal_seed(&capsule, &key),
            Err(UnsealError::AuthenticationFailed)
        ));
    }

    #[test]
    fn modified_fingerprint_fails_authentication() {
        let (seed, key, fingerprint) = test_seed_and_key();
        let mut capsule = roundtrip_capsule(&seed, &key, fingerprint);
        capsule.fingerprint[0] ^= 0x01;
        assert!(matches!(
            unseal_seed(&capsule, &key),
            Err(UnsealError::AuthenticationFailed)
        ));
    }

    #[test]
    fn invalid_capsule_magic_is_rejected() {
        let (seed, key, fingerprint) = test_seed_and_key();
        let mut capsule = roundtrip_capsule(&seed, &key, fingerprint);
        capsule.magic = *b"NOT_SEED";
        assert!(matches!(
            unseal_seed(&capsule, &key),
            Err(UnsealError::InvalidMagic)
        ));
    }

    #[test]
    fn fingerprint_mismatch_after_decrypt_is_rejected() {
        let (seed, key, _) = test_seed_and_key();
        let other = SeedFingerprint::from_bytes([0xAB; FINGERPRINT_LEN]);
        let cipher = XChaCha20Poly1305::new_from_slice(key.as_bytes()).unwrap();
        let nonce = [0x22; NONCE_LEN];
        let aad = capsule_aad(other);
        let nonce_ref = <&XNonce>::from(nonce.as_slice());
        let ciphertext = seed
            .expose(|s| cipher.encrypt(nonce_ref, Payload { msg: s, aad: &aad }))
            .unwrap();
        let capsule = SeedCapsule {
            magic: CAPSULE_MAGIC,
            fingerprint: other.to_bytes(),
            nonce: nonce.to_vec(),
            ciphertext,
        };
        assert!(matches!(
            unseal_seed(&capsule, &key),
            Err(UnsealError::FingerprintMismatch)
        ));
    }

    #[test]
    fn postcard_capsule_layout_matches_documented_fields() {
        let (seed, key, fingerprint) = test_seed_and_key();
        let capsule = seal_seed_with_nonce(&seed, &key, fingerprint, [0x11; NONCE_LEN]);
        let bytes = postcard::to_allocvec(&capsule).unwrap();
        assert_eq!(&bytes[0..8], b"ZNS_SEED");
        assert_eq!(&bytes[8..40], &fingerprint.to_bytes());
        assert_eq!(bytes[40], NONCE_LEN as u8);
        assert_eq!(bytes[41 + NONCE_LEN], CIPHERTEXT_LEN as u8);
    }

    #[test]
    fn capsule_serializes_with_postcard() {
        let capsule = SeedCapsule {
            magic: CAPSULE_MAGIC,
            fingerprint: [0xAA; FINGERPRINT_LEN],
            nonce: vec![0xBB; NONCE_LEN],
            ciphertext: vec![0xCC; CIPHERTEXT_LEN],
        };
        let bytes = postcard::to_allocvec(&capsule).unwrap();
        let decoded: SeedCapsule = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.magic, CAPSULE_MAGIC);
    }

    #[test]
    fn manifest_serializes_to_toml() {
        let seed_bytes: [u8; SEED_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let fp = SeedFingerprint::from_seed(&seed_bytes).unwrap();
        let manifest = custody_manifest(
            fp,
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            "0000000000000000000000000000000000000000000000000000000000000000",
            0x30000,
            "bootloader=0 tee=0 snp=0 microcode=0",
        );
        assert!(manifest.contains("seed_fingerprint"));
    }

    #[test]
    fn mint_config_contains_fingerprint() {
        let seed_bytes: [u8; SEED_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let fp = SeedFingerprint::from_seed(&seed_bytes).unwrap();
        let config = mint_config_toml_with_birthday(fp, BlockHeight::from_u32(0));
        assert!(config.contains("expected_seed_fingerprint"));
    }

    #[test]
    fn atomic_verified_write_rejects_a_short_file() {
        let dir = std::env::temp_dir().join(format!("zns-keygen-finalize-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("zns_mint.conf");
        let expected = b"network = \"testnet\"\nbirthday = 4408922\n";

        write_atomic_verified(&path, expected, 0o600);
        assert_eq!(fs::read(&path).unwrap(), expected);
        assert!(!temp_sibling(&path).exists());

        write_atomic_verified(&path, expected, 0o600);

        fs::write(&path, b"network = \"test").unwrap();
        let mismatched = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            write_atomic_verified(&path, expected, 0o600);
        }));
        assert!(mismatched.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"network = \"test");

        let link = dir.join("zns_custody_manifest.toml");
        std::os::unix::fs::symlink(&path, &link).unwrap();
        let symlink = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            write_atomic_verified(&link, expected, 0o644);
        }));
        assert!(symlink.is_err());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn funding_rpc_error_is_not_an_empty_address() {
        match funding_utxos(Err("RPC error: Method not found".into())) {
            Err(error) => assert!(error.contains("Method not found")),
            Ok(_) => panic!("a Zebra error must not look like an empty address"),
        }
        assert!(funding_utxos(Ok(vec![])).unwrap().is_none());
    }
}
