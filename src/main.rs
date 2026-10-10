//! zns-keygen — ZNS mint key genesis ceremony.

mod anchor;
mod ceremony;
mod keys;
mod rpc;

use blake2b_simd::Params as Blake2bParams;
use rand::RngCore;
use secrecy::{ExposeSecret, Secret};
use std::fs::{self, File, OpenOptions};
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use std::hint::spin_loop;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::value::Zatoshis;
use zeroize::Zeroize;
use zip32::fingerprint::SeedFingerprint;
use zns_canon::capsule::{self, MAGIC as CAPSULE_MAGIC, SEED_LEN};

use keys::{AnchorMaterial, TreasuryFundingInfo};

const KEYS_DIR: &str = "keys";
const CAPSULE_FILE: &str = "keys/zns_seed.capsule";
const MANIFEST_FILE: &str = "keys/zns_custody_manifest.toml";
const MINT_CONFIG_FILE: &str = "keys/zns_mint.conf";
const ATTESTATION_FILE: &str = "keys/zns_attestation.bin";

const TREASURY_ACCOUNT: u32 = 0;
const REGISTRY_ACCOUNT: u32 = 1;

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
        let seed = generate_seed();
        let fingerprint =
            SeedFingerprint::from_seed(seed.expose_secret()).expect("FATAL: seed length");
        tracing::info!("seed fingerprint: {fingerprint}");

        let funding = TreasuryFundingInfo::derive(&NETWORK, seed.expose_secret());

        tracing::info!("=== SEALING ===");
        let sealing_key = zns_canon::sealing::derive_sealing_key(capsule::CAPSULE_KEY_CONTEXT)
            .unwrap_or_else(|error| panic!("FATAL: derive sealing key: {error}"));
        let capsule = capsule::seal_seed(&sealing_key, &seed, &mut RdseedRng)
            .unwrap_or_else(|error| panic!("FATAL: seal capsule: {error}"));
        let capsule_bytes = capsule::serialize_capsule(&capsule)
            .unwrap_or_else(|error| panic!("FATAL: serialize capsule: {error}"));
        let capsule_hash = blake2b256(&capsule_bytes);
        write_secret_file(capsule_path, &capsule_bytes);
        tracing::info!("capsule persisted; dropping plaintext seed");
        drop(seed);
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
    let expected = zns_canon::attestation::report_data(state.fingerprint(), state.capsule_hash());
    match fs::symlink_metadata(attestation_path) {
        Ok(meta) if meta.file_type().is_symlink() => {
            panic!("FATAL: {} is a symlink", attestation_path.display());
        }
        Ok(_) => {
            let bytes = fs::read(attestation_path).expect("FATAL: read attestation");
            zns_canon::attestation::stored(bytes, &expected).expect("FATAL: stored attestation");
            tracing::info!("attestation already persisted");
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!("=== ATTESTATION ===");
            let attestation = zns_canon::attestation::request(&expected);
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

    let capsule_bytes = capsule::read_capsule_file(capsule_path)
        .unwrap_or_else(|error| panic!("FATAL: read capsule: {error}"));
    let capsule = capsule::parse_capsule(&capsule_bytes)
        .unwrap_or_else(|error| panic!("FATAL: parse capsule: {error}"));
    let sealing_key = zns_canon::sealing::derive_sealing_key(capsule::CAPSULE_KEY_CONTEXT)
        .unwrap_or_else(|error| panic!("FATAL: derive sealing key: {error}"));
    let seed = capsule::unseal_seed(&sealing_key, &capsule)
        .unwrap_or_else(|error| panic!("FATAL: unseal capsule: {error}"));
    let unsealed = SeedFingerprint::from_seed(seed.expose_secret()).expect("FATAL: seed length");
    assert_eq!(
        unsealed, fingerprint,
        "FATAL: unsealed seed fingerprint does not match the ceremony fingerprint"
    );

    tracing::info!("=== ANCHOR CREATION ===");
    let (tip_height, _) = rpc::Rpc::tip().expect("FATAL: Zebra unreachable");
    tracing::info!(height = u32::from(tip_height), "chain tip");

    let mut material = AnchorMaterial::derive(&NETWORK, seed.expose_secret());
    drop(seed);

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
                match lookup {
                    ceremony::AnchorLookup::SideChain => tracing::info!(
                        txid,
                        "stored anchor is on a side chain; rebroadcasting the same transaction"
                    ),
                    _ => tracing::info!(txid, "broadcasting stored anchor"),
                }
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
/// RPC failure or a mempool entry leaves the ceremony pending. A side-chain
/// result is submitted again: Zebra can put that same transaction back in the
/// mempool, or reject it as expired so the ceremony builds a replacement.
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
                match lookup {
                    ceremony::AnchorLookup::SideChain => tracing::warn!(
                        txid,
                        "stored anchor is on a side chain; rebroadcasting the same transaction"
                    ),
                    _ => tracing::warn!(
                        txid,
                        "stored anchor is not in the mempool or best chain; rebroadcasting the same transaction"
                    ),
                }
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
    let expected = zns_canon::attestation::report_data(&fingerprint, &capsule_hash);
    let report_bytes =
        fs::read(ATTESTATION_FILE).expect("FATAL: attestation missing at finalization");
    let attestation =
        zns_canon::attestation::stored(report_bytes, &expected).expect("FATAL: stored attestation");
    persist_final_outputs(
        &state,
        &attestation,
        Path::new(MANIFEST_FILE),
        Path::new(MINT_CONFIG_FILE),
    );

    let state = state.complete();
    ceremony::store(state_path, &state);
    tracing::info!(
        birthday = u32::from(birthday),
        "manifest and mint config written"
    );
    state
}

/// Write the custody manifest and mint config from the broadcast state.
///
/// The Treasury address, anchor txid, and birthday come from `state`. An
/// existing file is kept only when the new bytes match, so a resumed
/// finalization is idempotent.
fn persist_final_outputs(
    state: &ceremony::CeremonyState,
    attestation: &zns_canon::attestation::Attestation,
    manifest_path: &Path,
    mint_config_path: &Path,
) {
    let fingerprint = *state.fingerprint();
    let capsule_hash = *state.capsule_hash();
    let birthday = BlockHeight::from_u32(
        state
            .birthday()
            .expect("FATAL: broadcast anchor has no birthday"),
    );
    let expected = zns_canon::attestation::report_data(&fingerprint, &capsule_hash);
    let report_data_hash = blake2b256(&expected);
    let attestation_hash = blake2b256(&attestation.report_bytes);
    let measurement = hex::encode(attestation.measurement);
    let treasury_address = state
        .funding_info()
        .expect("FATAL: ceremony state has no funding address")
        .address()
        .to_zcash_address(NETWORK.network_type())
        .encode();
    let anchor_txid = state
        .txid()
        .expect("FATAL: broadcast anchor has no txid")
        .to_string();
    let manifest = custody_manifest(CustodyManifestInputs {
        fingerprint,
        capsule_hash: &capsule_hash,
        treasury_address: &treasury_address,
        anchor_txid: &anchor_txid,
        birthday: u32::from(birthday),
        report_data_hash: &report_data_hash,
        attestation_hash: &attestation_hash,
        measurement: &measurement,
        guest_policy: attestation.guest_policy,
        tcb_version: &attestation.tcb_version,
    });
    let mint_config = mint_config_toml_with_birthday(fingerprint, birthday);
    write_atomic_verified(manifest_path, manifest.as_bytes(), 0o644);
    write_atomic_verified(mint_config_path, mint_config.as_bytes(), 0o600);
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
    treasury_address: String,
    anchor_txid: String,
    birthday: u32,
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

struct CustodyManifestInputs<'a> {
    fingerprint: SeedFingerprint,
    capsule_hash: &'a [u8; 32],
    treasury_address: &'a str,
    anchor_txid: &'a str,
    birthday: u32,
    report_data_hash: &'a [u8; 32],
    attestation_hash: &'a [u8; 32],
    measurement: &'a str,
    guest_policy: u64,
    tcb_version: &'a str,
}

fn custody_manifest(inputs: CustodyManifestInputs<'_>) -> String {
    let m = CustodyManifest {
        manifest_version: 1,
        network: NETWORK_LABEL,
        seed_fingerprint: inputs.fingerprint.to_string(),
        capsule_file: CAPSULE_FILE,
        capsule_hash_blake2b256: hex::encode(inputs.capsule_hash),
        capsule_format: String::from_utf8(CAPSULE_MAGIC.to_vec()).expect("FATAL: capsule magic"),
        seed_length: SEED_LEN,
        treasury_account: TREASURY_ACCOUNT,
        registry_account: REGISTRY_ACCOUNT,
        treasury_address: inputs.treasury_address.to_string(),
        anchor_txid: inputs.anchor_txid.to_string(),
        birthday: inputs.birthday,
        sealing: "amd-sev-snp-derived-key",
        sealing_root_key: "vcek",
        sealing_guest_fields: "guest_policy,measurement",
        guest_policy: format!("0x{:016x}", inputs.guest_policy),
        tcb_version: inputs.tcb_version.to_string(),
        rng: "rdseed",
        attestation_file: ATTESTATION_FILE,
        attestation_hash_blake2b256: hex::encode(inputs.attestation_hash),
        report_data_hash_blake2b256: hex::encode(inputs.report_data_hash),
        measurement: inputs.measurement.to_string(),
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

/// Draws the ceremony seed from RDSEED and rejects a degenerate output.
fn generate_seed() -> Secret<[u8; SEED_LEN]> {
    let mut seed_bytes = [0u8; SEED_LEN];
    fill_entropy(&mut seed_bytes);
    assert!(
        !seed_bytes.iter().all(|&b| b == 0),
        "FATAL: RDSEED all zeros"
    );
    assert!(
        !seed_bytes.iter().all(|&b| b == 0xff),
        "FATAL: RDSEED all 0xFF"
    );
    let seed = Secret::new(seed_bytes);
    seed_bytes.zeroize();
    seed
}

/// Nonce source for capsule sealing. The seed itself is drawn separately.
struct RdseedRng;

impl RngCore for RdseedRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_ne_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_ne_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_entropy(dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
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

    #[test]
    fn manifest_serializes_to_toml() {
        let seed_bytes: [u8; SEED_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let fp = SeedFingerprint::from_seed(&seed_bytes).unwrap();
        let txid = "ab".repeat(32);
        let manifest = custody_manifest(CustodyManifestInputs {
            fingerprint: fp,
            capsule_hash: &[0u8; 32],
            treasury_address: "tmTestTreasuryAddress",
            anchor_txid: &txid,
            birthday: 4408922,
            report_data_hash: &[0u8; 32],
            attestation_hash: &[0u8; 32],
            measurement: "0000000000000000000000000000000000000000000000000000000000000000",
            guest_policy: 0x30000,
            tcb_version: "bootloader=0 tee=0 snp=0 microcode=0",
        });
        assert!(manifest.contains("seed_fingerprint"));
        assert!(manifest.contains("treasury_address = \"tmTestTreasuryAddress\""));
        assert!(manifest.contains(&format!("anchor_txid = \"{txid}\"")));
        assert!(manifest.contains("birthday = 4408922"));
    }

    #[test]
    fn finalizing_twice_copies_the_broadcast_state_into_the_manifest() {
        let seed = [0x11u8; SEED_LEN];
        let funding = TreasuryFundingInfo::derive(&NETWORK, &seed);
        let fingerprint = SeedFingerprint::from_seed(&seed).unwrap();
        let address = funding
            .address()
            .to_zcash_address(NETWORK.network_type())
            .encode();
        let pubkey = hex::encode(funding.pubkey().serialize());
        let state = ceremony::CeremonyState::sealed(fingerprint, [0x44; 32], address, pubkey)
            .anchor_built("ab".repeat(32), "00ff".to_string())
            .anchor_broadcast(4_408_922);
        let attestation = zns_canon::attestation::Attestation {
            report_bytes: b"snp-report".to_vec(),
            measurement: [0x7a; 48],
            guest_policy: 0x30000,
            tcb_version: "bootloader=1 tee=2 snp=3 microcode=4".to_string(),
            report_data: [0u8; zns_canon::attestation::REPORT_DATA_LEN],
        };

        let dir =
            std::env::temp_dir().join(format!("zns-keygen-final-manifest-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let manifest_path = dir.join("zns_custody_manifest.toml");
        let mint_path = dir.join("zns_mint.conf");

        persist_final_outputs(&state, &attestation, &manifest_path, &mint_path);
        let manifest_bytes = fs::read(&manifest_path).unwrap();
        let mint_bytes = fs::read(&mint_path).unwrap();
        persist_final_outputs(&state, &attestation, &manifest_path, &mint_path);
        assert_eq!(fs::read(&manifest_path).unwrap(), manifest_bytes);
        assert_eq!(fs::read(&mint_path).unwrap(), mint_bytes);

        let manifest: toml::Value =
            toml::from_str(std::str::from_utf8(&manifest_bytes).unwrap()).unwrap();
        let mint: toml::Value = toml::from_str(std::str::from_utf8(&mint_bytes).unwrap()).unwrap();
        let expected_address = state
            .funding_info()
            .unwrap()
            .address()
            .to_zcash_address(NETWORK.network_type())
            .encode();
        assert_eq!(
            manifest["treasury_address"].as_str().unwrap(),
            expected_address
        );
        assert_eq!(
            manifest["anchor_txid"].as_str().unwrap(),
            state.txid().unwrap()
        );
        assert_eq!(
            u32::try_from(manifest["birthday"].as_integer().unwrap()).unwrap(),
            state.birthday().unwrap()
        );
        assert_eq!(
            manifest["seed_fingerprint"].as_str().unwrap(),
            state.fingerprint().to_string()
        );
        assert_eq!(
            manifest["capsule_hash_blake2b256"].as_str().unwrap(),
            hex::encode(state.capsule_hash())
        );
        assert_eq!(
            mint["expected_seed_fingerprint"].as_str().unwrap(),
            state.fingerprint().to_string()
        );
        assert_eq!(
            u32::try_from(mint["birthday"].as_integer().unwrap()).unwrap(),
            state.birthday().unwrap()
        );
        assert_eq!(mint["birthday"], manifest["birthday"]);

        let _ = fs::remove_dir_all(&dir);
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
