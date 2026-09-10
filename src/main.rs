//! zns-keygen — ZNS mint key genesis ceremony.

mod anchor;
mod attestation;
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
use zcash_protocol::consensus::BlockHeight;
#[cfg(target_os = "linux")]
use zeroize::{Zeroize, Zeroizing};
#[cfg(not(target_os = "linux"))]
use zeroize::Zeroizing;

use fingerprint::SeedFingerprint;
use keys::CeremonyKeys;
use secrecy::Secret;

const CAPSULE_FILE: &str = "zns_seed.capsule";
const MANIFEST_FILE: &str = "zns_custody_manifest.toml";
const MINT_CONFIG_FILE: &str = "zns_mint.conf";
const ATTESTATION_FILE: &str = "zns_attestation.bin";

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

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
// compile_error!("zns-keygen requires x86_64 Linux");

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
const ANCHOR_CONFIRMATIONS: u32 = 3;

fn main() {
    tracing_subscriber::fmt().init();
    tracing::info!("=== ZNS KEY GENESIS ===");
    tracing::info!(network = NETWORK_LABEL, "starting ceremony");

    let capsule_path = Path::new(CAPSULE_FILE);
    let manifest_path = Path::new(MANIFEST_FILE);
    let mint_config_path = Path::new(MINT_CONFIG_FILE);
    let attestation_path = Path::new(ATTESTATION_FILE);

    ensure_absent(capsule_path);
    ensure_absent(manifest_path);
    ensure_absent(mint_config_path);
    ensure_absent(attestation_path);

    let seed = Seed::generate();
    let fingerprint = seed.fingerprint();
    tracing::info!("seed fingerprint: {fingerprint}");

    let keys = seed.expose(|seed_bytes| {
        let secret = Secret::new(*seed_bytes);
        CeremonyKeys::derive(&NETWORK, &secret)
    });
    let taddr = keys.treasury_taddr(&NETWORK);
    tracing::info!("Treasury t-address: {taddr}");

    let sealing_key = derive_sealing_key();
    let capsule = seal_seed(&seed, &sealing_key, fingerprint);
    let capsule_bytes = postcard::to_allocvec(&capsule).unwrap();
    let capsule_hash = blake2b256(&capsule_bytes);

    let report_data = attestation::report_data(&fingerprint, &capsule_hash);
    let attestation = attestation::request(&report_data);
    let report_data_hash = blake2b256(&report_data);
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
    let mint_config = mint_config_toml(fingerprint);

    write_secret_file(capsule_path, &capsule_bytes);
    write_public_file(manifest_path, manifest.as_bytes());
    write_secret_file(mint_config_path, mint_config.as_bytes());
    write_public_file(attestation_path, &attestation.report_bytes);

    tracing::info!("capsule + manifest + config + attestation written");

    tracing::info!("=== FUNDING ===");
    tracing::info!("send {NETWORK_LABEL} ZEC to: {taddr}");
    tracing::info!("polling Zebra every {}s", POLL_INTERVAL.as_secs());

    let utxos = wait_for_funding(&taddr, &keys);
    tracing::info!(utxos = utxos.len(), "funding detected");

    tracing::info!("=== ANCHOR CREATION ===");
    let (tip_height, _) = rpc::Rpc::tip().expect("FATAL: Zebra unreachable");
    tracing::info!(height = u32::from(tip_height), "chain tip");

    let tx = anchor::build_anchor(&NETWORK, &keys, tip_height, &utxos);
    let mut tx_bytes = Vec::new();
    tx.write(&mut tx_bytes).expect("FATAL: serialize tx");
    let tx_hex = hex::encode(&tx_bytes);
    let txid = tx.txid().to_string();
    tracing::info!(txid, "anchor tx built, submitting");

    let submitted = rpc::Rpc::send_raw(&tx_hex).expect("FATAL: sendrawtransaction");
    tracing::info!(txid = submitted, "anchor tx broadcast");

    let birthday = wait_for_confirmation(&txid);
    tracing::info!(height = u32::from(birthday), "anchor confirmed");

    let final_config = mint_config_toml_with_birthday(fingerprint, birthday);
    fs::write(mint_config_path, final_config.as_bytes())
        .expect("FATAL: rewrite mint config");
    tracing::info!("mint config updated with birthday");

    tracing::info!("=== CEREMONY COMPLETE ===");
    tracing::info!(birthday = u32::from(birthday), "genesis done");
}

fn wait_for_funding(taddr: &str, keys: &CeremonyKeys) -> Vec<anchor::FundingUtxo> {
    let mut last_height = None;
    loop {
        let (tip_height, _) = match rpc::Rpc::tip() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!(error = %e, "Zebra unreachable");
                std::thread::sleep(POLL_INTERVAL);
                continue;
            }
        };

        if last_height != Some(tip_height) {
            tracing::info!(height = u32::from(tip_height), "scanning for funding");
            last_height = Some(tip_height);
        }

        if let Some(utxos) = scan_block_for_funding(tip_height, taddr, keys) {
            if !utxos.is_empty() {
                return utxos;
            }
        }

        std::thread::sleep(POLL_INTERVAL);
    }
}

fn scan_block_for_funding(height: BlockHeight, taddr: &str, keys: &CeremonyKeys) -> Option<Vec<anchor::FundingUtxo>> {
    let block_hex = match rpc::Rpc::block_hex(height) {
        Ok(h) => h,
        Err(e) => {
            tracing::warn!(error = %e, "getblock failed");
            return None;
        }
    };

    let block_bytes = hex::decode(&block_hex).ok()?;
    let block = zcash_primitives::block::Block::read(&block_bytes[..], &NETWORK).ok()?;

    // Derive the expected Treasury address for comparison.
    let treasury_tkey = keys.treasury_transparent();
    let account_pub = treasury_tkey.to_account_pubkey();
    let pubkey = account_pub
        .derive_address_pubkey(
            transparent::keys::TransparentKeyScope::EXTERNAL,
            transparent::keys::NonHardenedChildIndex::from_index(0).unwrap(),
        )
        .expect("FATAL: pubkey derivation");
    let expected_addr = transparent::address::TransparentAddress::from_pubkey(&pubkey);

    let mut found = Vec::new();
    for tx in block.vtx() {
        if let Some(bundle) = tx.transparent_bundle() {
            for (vout, output) in bundle.vout.iter().enumerate() {
                let script = output.script_pubkey();
                let parsed = zcash_script::script::PubKey::parse(&script.0).ok();
                let addr = parsed
                    .as_ref()
                    .and_then(transparent::address::TransparentAddress::from_script_pubkey);
                if addr == Some(expected_addr) {
                    let outpoint = transparent::bundle::OutPoint::new(
                        *tx.txid().as_ref(),
                        vout as u32,
                    );
                    found.push(anchor::FundingUtxo {
                        outpoint,
                        coin: output.clone(),
                        pubkey,
                    });
                }
            }
        }
    }

    if found.is_empty() { None } else { Some(found) }
}

fn wait_for_confirmation(txid: &str) -> BlockHeight {
    loop {
        match rpc::Rpc::raw_tx(txid) {
            Ok(tx) => {
                if tx.confirmations >= ANCHOR_CONFIRMATIONS {
                    let (tip, _) = rpc::Rpc::tip().expect("FATAL: Zebra unreachable");
                    return tip;
                }
                tracing::info!(confirmations = tx.confirmations, "waiting");
            }
            Err(e) => {
                tracing::warn!(error = %e, "getrawtransaction failed");
            }
        }
        std::thread::sleep(POLL_INTERVAL);
    }
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
}

// ── Sealing key ───────────────────────────────────────────────────

struct SealingKey(Zeroizing<[u8; SEALING_KEY_LEN]>);

impl SealingKey {
    fn as_bytes(&self) -> &[u8; SEALING_KEY_LEN] {
        &self.0
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
    let cipher = XChaCha20Poly1305::new_from_slice(sealing_key.as_bytes())
        .expect("key length const-asserted");
    let mut nonce = [0u8; NONCE_LEN];
    fill_entropy(&mut nonce);
    let aad = capsule_aad(fingerprint);
    let nonce_ref = <&XNonce>::try_from(nonce.as_slice()).expect("nonce const-asserted");
    let ciphertext = seed
        .expose(|s| cipher.encrypt(nonce_ref, Payload { msg: s, aad: &aad }))
        .expect("encrypt seed");
    assert_eq!(ciphertext.len(), CIPHERTEXT_LEN);
    SeedCapsule {
        magic: CAPSULE_MAGIC,
        fingerprint: fingerprint.to_bytes(),
        nonce: nonce.to_vec(),
        ciphertext,
    }
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
        capsule_format: String::from_utf8(CAPSULE_MAGIC.to_vec()).unwrap_or_else(|_| "unknown".into()),
        seed_length: SEED_LEN,
        treasury_account: TREASURY_ACCOUNT,
        registry_account: REGISTRY_ACCOUNT,
        sealing: "amd-sev-snp-vcek-chip-bound",
        sealing_root_key: "vcek",
        sealing_guest_fields: "guest_policy,measurement",
        guest_policy: format!("0x{guest_policy:016x}"),
        tcb_version: tcb_version.to_string(),
        rng: "rdseed",
        attestation_file: ATTESTATION_FILE,
        attestation_hash_blake2b256: hex::encode(attestation_hash),
        report_data_hash_blake2b256: hex::encode(report_data_hash),
        measurement: measurement.to_string(),
        attestation_sig_algo: "ecdsa-p256-sha384",
        migration: "none",
        signer_socket: "none",
    };
    toml::to_string(&m).unwrap()
}

// ── Mint config ───────────────────────────────────────────────────

#[derive(serde::Serialize)]
struct MintConfig {
    network: &'static str,
    expected_seed_fingerprint: String,
}

#[derive(serde::Serialize)]
struct MintConfigWithBirthday {
    network: &'static str,
    expected_seed_fingerprint: String,
    birthday: u32,
}

fn mint_config_toml(fingerprint: SeedFingerprint) -> String {
    toml::to_string(&MintConfig {
        network: NETWORK_LABEL,
        expected_seed_fingerprint: fingerprint.to_string(),
    }).unwrap()
}

fn mint_config_toml_with_birthday(fingerprint: SeedFingerprint, birthday: BlockHeight) -> String {
    toml::to_string(&MintConfigWithBirthday {
        network: NETWORK_LABEL,
        expected_seed_fingerprint: fingerprint.to_string(),
        birthday: u32::from(birthday),
    }).unwrap()
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
    if dest.is_empty() { return; }
    let mut offset = 0;
    while offset < dest.len() {
        let mut value = 0u64;
        for attempt in 0..10_000 {
            unsafe {
                if core::arch::x86_64::_rdseed64_step(&mut value) == 1 {
                    break;
                }
            }
            if attempt % 1000 == 999 { std::thread::yield_now(); }
            spin_loop();
        }
        if value == 0 { panic!("RDSEED unavailable"); }
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
    std::io::stdin().read_exact(dest).expect("entropy unavailable");
}

// ── Sealing key derivation ────────────────────────────────────────

#[cfg(target_os = "linux")]
fn derive_sealing_key() -> SealingKey {
    let mut firmware = Firmware::open().expect("open /dev/sev-guest");
    let mut gf = GuestFieldSelect::default();
    gf.set_guest_policy(true);
    gf.set_measurement(true);
    let request = DerivedKey::new(false, gf, 0, 0, 0, None);
    let mut key = firmware
        .get_derived_key(Some(1), request)
        .expect("derive VCEK sealing key");
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
        Ok(_) => panic!("{} already exists", path.display()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => panic!("inspect {}: {e}", path.display()),
    }
}

fn write_secret_file(path: &Path, bytes: &[u8]) {
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o600)
        .open(path).expect("create secret file");
    f.write_all(bytes).expect("write file");
    f.sync_all().expect("sync file");
    sync_parent(path);
}

fn write_public_file(path: &Path, bytes: &[u8]) {
    let mut f = OpenOptions::new().write(true).create_new(true).mode(0o644)
        .open(path).expect("create public file");
    f.write_all(bytes).expect("write file");
    f.sync_all().expect("sync file");
    sync_parent(path);
}

fn sync_parent(path: &Path) {
    let parent = path.parent().filter(|p| !p.as_os_str().is_empty()).unwrap_or(Path::new("."));
    File::open(parent).and_then(|f| f.sync_all()).expect("sync parent");
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
            fp, &[0u8; 32], &[0u8; 32], &[0u8; 32],
            "0000000000000000000000000000000000000000000000000000000000000000",
            0x30000, "bootloader=0 tee=0 snp=0 microcode=0",
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
        let config = mint_config_toml(fp);
        assert!(config.contains("expected_seed_fingerprint"));
    }
}