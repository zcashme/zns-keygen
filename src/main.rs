//! zns-keygen — ZNS mint key genesis ceremony.

mod anchor;
mod ceremony;
mod keys;
mod rpc;

use blake2b_simd::Params as Blake2bParams;
use rand::{TryCryptoRng, TryRng};
use secrecy::{ExposeSecret, Secret};
use std::fs::{self, File, OpenOptions};
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use std::hint::spin_loop;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use std::time::Duration;
use zcash_protocol::consensus::Parameters;
use zcash_protocol::value::Zatoshis;
use zeroize::Zeroize;
use zip32::fingerprint::SeedFingerprint;
use zns_canon::capsule::{self, MAGIC as CAPSULE_MAGIC, SEED_LEN};

use keys::{AnchorMaterial, TreasuryFundingInfo};

const KEYS_DIR: &str = "keys";
const CAPSULE_FILE: &str = "keys/zns_seed.capsule";
const MANIFEST_FILE: &str = "keys/zns_custody_manifest.toml";
const ATTESTATION_FILE: &str = "keys/zns_attestation.bin";
const ACCESS_CODE_ENC_FILE: &str = "keys/access_code_key.enc";

/// The operator public key the access-code key is wrapped to. Part of the
/// measured image, so the attestation covers the choice of recipient. The
/// matching private key is the operator's 24-word mnemonic; the wrap is
/// canon's `wrap_secret`, and `access-code-tool decrypt` opens the file.
const ISSUER_PUBKEY: [u8; 32] = [
    0xfb, 0xd1, 0x2e, 0xed, 0x08, 0xb8, 0xc1, 0xe3, 0x43, 0xab, 0x4b, 0x98, 0x22, 0x82, 0x1d, 0x51,
    0x13, 0xb0, 0xe3, 0xa7, 0x11, 0x00, 0x1d, 0x81, 0xed, 0xb8, 0xd5, 0xcf, 0xa3, 0x4e, 0xab, 0x52,
];

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

fn main() {
    tracing_subscriber::fmt().init();
    tracing::info!("=== ZNS KEY GENESIS ===");
    tracing::info!(network = NETWORK_LABEL, "starting ceremony");

    if Path::new(MANIFEST_FILE).exists() {
        tracing::info!("custody manifest exists; ceremony already complete");
        return;
    }

    wipe_incomplete();
    fs::create_dir_all(KEYS_DIR).expect("FATAL: cannot create keys directory");

    let sealed = seal_seed();
    let attestation = attest(sealed.fingerprint);
    let inputs = wait_for_funding(&sealed.funding);
    let (txid, raw_tx) = build_anchor(&sealed, &inputs);
    let birthday = broadcast_and_confirm(&txid, &raw_tx);
    finalize(&sealed, &attestation, &txid, birthday);
    tracing::info!("=== CEREMONY COMPLETE ===");
}

/// Facts from the sealing step that the rest of the ceremony consumes.
struct SealedCeremony {
    fingerprint: SeedFingerprint,
    capsule_hash: [u8; 32],
    funding: TreasuryFundingInfo,
}

/// Delete the artifacts of an incomplete ceremony.
///
/// The custody manifest is the completion record: this runs only when it is
/// absent, so everything removed here belongs to a ceremony that never
/// finished and whose capsule is worthless. A missing file is fine. Removing
/// a symlink removes the link, not its target.
fn wipe_incomplete() {
    for path in [
        CAPSULE_FILE,
        ATTESTATION_FILE,
        ACCESS_CODE_ENC_FILE,
        "keys/zns_mint.conf",
        "keys/ceremony_state.toml",
    ] {
        match fs::remove_file(path) {
            Ok(()) => tracing::warn!(path, "removed incomplete ceremony artifact"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("FATAL: remove {path}: {error}"),
        }
    }
}

/// Generate the seed, seal the capsule with the access-code key, derive
/// the Treasury funding info, and wrap the access-code key to the operator.
fn seal_seed() -> SealedCeremony {
    let (fingerprint, capsule_hash, funding) = {
        let seed = generate_seed();
        let fingerprint =
            SeedFingerprint::from_seed(seed.expose_secret()).expect("FATAL: seed length");
        tracing::info!("seed fingerprint: {fingerprint}");

        let funding = TreasuryFundingInfo::derive(&NETWORK, seed.expose_secret());

        // Drawn from RDSEED like the seed, and sealed into the same capsule:
        // the mint unseals both at boot, and migrate re-seals both with the
        // seed. The claim-judging key never exists outside this guest until
        // the operator decrypts their copy.
        let access_code_key = generate_access_code_key();

        tracing::info!("=== SEALING ===");
        let sealing_key = zns_canon::sealing::derive_sealing_key(capsule::CAPSULE_KEY_CONTEXT)
            .unwrap_or_else(|error| panic!("FATAL: derive sealing key: {error}"));
        let capsule = capsule::seal_seed(&sealing_key, &seed, &access_code_key, &mut RdseedRng)
            .unwrap_or_else(|error| panic!("FATAL: seal capsule: {error}"));
        let capsule_bytes = capsule::serialize_capsule(&capsule)
            .unwrap_or_else(|error| panic!("FATAL: serialize capsule: {error}"));
        let capsule_hash = capsule::hash(&capsule_bytes);
        write_secret_file(Path::new(CAPSULE_FILE), &capsule_bytes);
        export_access_code_key(&access_code_key, capsule_hash);
        tracing::info!("capsule persisted; dropping plaintext seed");
        drop(seed);
        drop(access_code_key);
        (fingerprint, capsule_hash, funding)
    };
    SealedCeremony {
        fingerprint,
        capsule_hash,
        funding,
    }
}

/// Draw the access-code key from RDSEED and reject degenerate output, the
/// same as the seed.
fn generate_access_code_key() -> Secret<[u8; 32]> {
    let mut key_bytes = [0u8; 32];
    fill_entropy(&mut key_bytes);
    assert!(
        !key_bytes.iter().all(|&b| b == 0),
        "FATAL: RDSEED all zeros"
    );
    assert!(
        !key_bytes.iter().all(|&b| b == 0xff),
        "FATAL: RDSEED all 0xFF"
    );
    let key = Secret::new(key_bytes);
    key_bytes.zeroize();
    key
}

/// The offer the export wrap binds to: the operator's public key as the
/// recipient, a fixed export domain as the nonce, and the capsule hash so
/// the wrap opens only beside the capsule it was made with.
fn export_offer(capsule_hash: [u8; 32]) -> zns_canon::migration::MigrationOffer {
    zns_canon::migration::MigrationOffer {
        ephemeral_pubkey: ISSUER_PUBKEY,
        nonce: blake2b256(b"ZNS_ACCESS_CODE_EXPORT_V1"),
        manifest_hash: capsule_hash,
    }
}

/// Wrap the access-code key to [`ISSUER_PUBKEY`] and write the 200-byte
/// export file: the offer, then the wrapped secret. The host can read the
/// file and learns nothing; only the operator's private key opens it.
fn export_access_code_key(access_code_key: &Secret<[u8; 32]>, capsule_hash: [u8; 32]) {
    let offer = export_offer(capsule_hash);
    let wrapped = zns_canon::migration::wrap_secret(access_code_key, &offer, &mut RdseedRng)
        .unwrap_or_else(|error| panic!("FATAL: wrap access-code key: {error}"));
    let mut file_bytes = Vec::with_capacity(200);
    file_bytes.extend_from_slice(&offer.ephemeral_pubkey);
    file_bytes.extend_from_slice(&offer.nonce);
    file_bytes.extend_from_slice(&offer.manifest_hash);
    file_bytes.extend_from_slice(&wrapped.sender_ephemeral_pubkey);
    file_bytes.extend_from_slice(&wrapped.nonce);
    file_bytes.extend_from_slice(&wrapped.ciphertext);
    write_secret_file(Path::new(ACCESS_CODE_ENC_FILE), &file_bytes);
    tracing::info!(
        "access-code key sealed into the capsule; operator copy written to {ACCESS_CODE_ENC_FILE}"
    );
}

/// Request the SNP attestation for the capsule and verify it.
fn attest(fingerprint: SeedFingerprint) -> zns_canon::attestation::Attestation {
    tracing::info!("=== ATTESTATION ===");
    let capsule_bytes = fs::read(CAPSULE_FILE).expect("FATAL: read capsule");
    let attestation = zns_canon::attestation::request(&capsule_bytes, &fingerprint);
    write_atomic(
        Path::new(ATTESTATION_FILE),
        &attestation.report_bytes,
        0o644,
    );
    let report_bytes = fs::read(ATTESTATION_FILE).expect("FATAL: read attestation");
    let verified = zns_canon::attestation::verify(&capsule_bytes, &fingerprint, report_bytes)
        .expect("FATAL: stored attestation");
    tracing::info!("attestation persisted and verified");
    verified
}

/// Poll Zebra until the Treasury address is funded and build the spend inputs.
fn wait_for_funding(
    funding: &TreasuryFundingInfo,
) -> Vec<transparent::builder::TransparentInputInfo> {
    let taddr_encoded = funding
        .address()
        .to_zcash_address(NETWORK.network_type())
        .encode();
    tracing::info!("=== FUNDING ===");
    tracing::info!("Treasury t-address: {taddr_encoded}");
    tracing::info!("send {NETWORK_LABEL} ZEC to: {taddr_encoded}");
    tracing::info!("minimum 500,000 zat (0.005 ZEC) for 40 anchors + Treasury change");
    poll_until_funded(funding)
}

/// Unseal the capsule and build the signed anchor transaction.
fn build_anchor(
    sealed: &SealedCeremony,
    inputs: &[transparent::builder::TransparentInputInfo],
) -> (String, String) {
    let capsule_bytes = capsule::read_capsule_file(CAPSULE_FILE)
        .unwrap_or_else(|error| panic!("FATAL: read capsule: {error}"));
    let capsule = capsule::parse_capsule(&capsule_bytes)
        .unwrap_or_else(|error| panic!("FATAL: parse capsule: {error}"));
    let sealing_key = zns_canon::sealing::derive_sealing_key(capsule::CAPSULE_KEY_CONTEXT)
        .unwrap_or_else(|error| panic!("FATAL: derive sealing key: {error}"));
    let opened = capsule::unseal_seed(&sealing_key, &capsule)
        .unwrap_or_else(|error| panic!("FATAL: unseal capsule: {error}"));
    let seed = opened.seed;
    let unsealed = SeedFingerprint::from_seed(seed.expose_secret()).expect("FATAL: seed length");
    assert_eq!(
        unsealed, sealed.fingerprint,
        "FATAL: unsealed seed fingerprint does not match the ceremony fingerprint"
    );
    assert_eq!(
        capsule::hash(&capsule_bytes),
        sealed.capsule_hash,
        "FATAL: capsule file does not match the sealed ceremony"
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
        inputs,
    );
    drop(material);

    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes).expect("FATAL: serialize tx");
    let raw_tx = hex::encode(&tx_bytes);
    let txid = tx.txid().to_string();
    tracing::info!(txid, "anchor tx built");
    (txid, raw_tx)
}

/// Submit the anchor and wait for the birthday.
///
/// Rebroadcasts the same transaction if the node loses it. An expiry
/// rejection fails the run: the next start wipes and builds a fresh ceremony.
fn broadcast_and_confirm(txid: &str, raw_tx: &str) -> u32 {
    tracing::info!(txid, "=== BROADCAST ===");
    send_anchor(txid, raw_tx);
    loop {
        let lookup = anchor_lookup(txid);
        match ceremony::broadcast_action(lookup) {
            ceremony::BroadcastAction::SendStored => {
                tracing::warn!(txid, "anchor absent; rebroadcasting the same transaction");
                send_anchor(txid, raw_tx);
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
            }
            ceremony::BroadcastAction::Confirmed { birthday } => {
                tracing::info!(
                    txid,
                    birthday,
                    "anchor confirmed; birthday is its best-chain inclusion height"
                );
                return birthday;
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
}

fn send_anchor(txid: &str, raw_tx: &str) {
    match rpc::Rpc::send_raw(raw_tx) {
        Ok(sent) if sent == txid => tracing::info!(txid, "anchor accepted"),
        Ok(sent) => panic!("FATAL: broadcast txid {sent} does not match built {txid}"),
        Err(error) if rpc::transaction_is_expired(&error) => {
            panic!(
                "FATAL: anchor expired before it was mined; the next run builds a fresh ceremony"
            )
        }
        Err(error) => tracing::warn!(%error, txid, "broadcast failed; retrying"),
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

/// Write the custody manifest: the mint's ceremony input, and its existence
/// is the completion record.
fn finalize(
    sealed: &SealedCeremony,
    attestation: &zns_canon::attestation::Attestation,
    txid: &str,
    birthday: u32,
) {
    let report_data_hash = blake2b256(&attestation.report_data);
    let attestation_hash = blake2b256(&attestation.report_bytes);
    let measurement = hex::encode(attestation.measurement);
    let access_code_key_enc_hash = blake2b256(
        &fs::read(ACCESS_CODE_ENC_FILE)
            .unwrap_or_else(|error| panic!("FATAL: read {ACCESS_CODE_ENC_FILE}: {error}")),
    );
    let treasury_address = sealed
        .funding
        .address()
        .to_zcash_address(NETWORK.network_type())
        .encode();
    let manifest = custody_manifest(CustodyManifestInputs {
        fingerprint: sealed.fingerprint,
        capsule_hash: &sealed.capsule_hash,
        treasury_address: &treasury_address,
        anchor_txid: txid,
        birthday,
        report_data_hash: &report_data_hash,
        attestation_hash: &attestation_hash,
        measurement: &measurement,
        guest_policy: attestation.guest_policy,
        tcb_version: &attestation.tcb_version,
        access_code_key_enc_hash: &access_code_key_enc_hash,
    });
    write_atomic(Path::new(MANIFEST_FILE), manifest.as_bytes(), 0o644);
    tracing::info!(birthday, "manifest written");
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
    access_code_key_file: &'static str,
    access_code_key_recipient: String,
    access_code_key_enc_hash_blake2b256: String,
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
    access_code_key_enc_hash: &'a [u8; 32],
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
        access_code_key_file: ACCESS_CODE_ENC_FILE,
        access_code_key_recipient: hex::encode(ISSUER_PUBKEY),
        access_code_key_enc_hash_blake2b256: hex::encode(inputs.access_code_key_enc_hash),
        migration: "none",
        signer_socket: "none",
    };
    toml::to_string(&m).expect("FATAL: serialize custody manifest")
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

impl TryRng for RdseedRng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_ne_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_ne_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Self::Error> {
        fill_entropy(dest);
        Ok(())
    }
}

impl TryCryptoRng for RdseedRng {}

// ── File I/O ──────────────────────────────────────────────────────

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
    fn finalize_writes_the_manifest() {
        let seed = [0x11u8; SEED_LEN];
        let funding = TreasuryFundingInfo::derive(&NETWORK, &seed);
        let fingerprint = SeedFingerprint::from_seed(&seed).unwrap();
        let sealed = SealedCeremony {
            fingerprint,
            capsule_hash: [0x44; 32],
            funding,
        };
        let txid = "ab".repeat(32);
        let birthday = 4_408_922u32;
        let attestation = zns_canon::attestation::Attestation {
            report_bytes: b"snp-report".to_vec(),
            measurement: [0x7a; 48],
            guest_policy: 0x30000,
            tcb_version: "bootloader=1 tee=2 snp=3 microcode=4".to_string(),
            report_data: [0u8; zns_canon::attestation::REPORT_DATA_LEN],
        };

        let dir = std::env::temp_dir().join(format!("zns-keygen-finalize-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let manifest_path = dir.join("zns_custody_manifest.toml");

        let report_data_hash = blake2b256(&attestation.report_data);
        let attestation_hash = blake2b256(&attestation.report_bytes);
        let measurement = hex::encode(attestation.measurement);
        let treasury_address = sealed
            .funding
            .address()
            .to_zcash_address(NETWORK.network_type())
            .encode();
        let manifest = custody_manifest(CustodyManifestInputs {
            fingerprint: sealed.fingerprint,
            capsule_hash: &sealed.capsule_hash,
            treasury_address: &treasury_address,
            anchor_txid: &txid,
            birthday,
            report_data_hash: &report_data_hash,
            attestation_hash: &attestation_hash,
            measurement: &measurement,
            guest_policy: attestation.guest_policy,
            tcb_version: &attestation.tcb_version,
            access_code_key_enc_hash: &[0x77; 32],
        });
        write_atomic(&manifest_path, manifest.as_bytes(), 0o644);

        let manifest: toml::Value =
            toml::from_str(std::str::from_utf8(&fs::read(&manifest_path).unwrap()).unwrap())
                .unwrap();
        assert_eq!(
            manifest["treasury_address"].as_str().unwrap(),
            treasury_address
        );
        assert_eq!(manifest["anchor_txid"].as_str().unwrap(), txid);
        assert_eq!(manifest["birthday"].as_integer().unwrap(), birthday as i64);
        assert_eq!(
            manifest["seed_fingerprint"].as_str().unwrap(),
            sealed.fingerprint.to_string()
        );
        assert_eq!(
            manifest["capsule_hash_blake2b256"].as_str().unwrap(),
            hex::encode(sealed.capsule_hash)
        );
        assert_eq!(manifest["network"].as_str().unwrap(), NETWORK_LABEL);
        assert_eq!(
            manifest["access_code_key_file"].as_str().unwrap(),
            ACCESS_CODE_ENC_FILE
        );
        assert_eq!(
            manifest["access_code_key_recipient"].as_str().unwrap(),
            hex::encode(ISSUER_PUBKEY)
        );
        assert_eq!(
            manifest["access_code_key_enc_hash_blake2b256"]
                .as_str()
                .unwrap(),
            hex::encode([0x77; 32])
        );

        let _ = fs::remove_dir_all(&dir);
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
