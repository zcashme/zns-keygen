//! zns-keygen — one-shot genesis custody tool for ZNS.
//!
//! Runs once inside an AMD SEV-SNP guest. Creates the seed, seals it,
//! requests an attestation report, writes everything to disk, and exits.
//! Does not expose a socket, does not sign messages, does not support
//! migration. If anything goes wrong, it panics.

mod fingerprint;

use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use sev::firmware::guest::{AttestationReport, DerivedKey, Firmware, GuestFieldSelect};
use std::fs::{self, File, OpenOptions};
use std::hint::spin_loop;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::{Zeroize, Zeroizing};

use fingerprint::SeedFingerprint;

const CAPSULE_FILE: &str = "zns_seed.capsule";
const MANIFEST_FILE: &str = "zns_custody_manifest.toml";
const MINT_CONFIG_FILE: &str = "zns_mint.conf";
const ATTESTATION_FILE: &str = "zns_attestation.bin";

const REPORT_DATA_LEN: usize = 64;

const NETWORK: &str = "mainnet";
const TREASURY_ACCOUNT: u32 = 0;
const REGISTRY_ACCOUNT: u32 = 1;

const SEED_LEN: usize = 32;
const FINGERPRINT_LEN: usize = 32;
const SEALING_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CIPHERTEXT_LEN: usize = SEED_LEN + TAG_LEN;

const CAPSULE_MAGIC: &[u8; 8] = b"ZNSCAPS1";
const CAPSULE_CONTEXT: &[u8] = b"ZcashNames mainnet; treasury=0; registry=1; sealing=amd-sev-snp-vmrk-instance-bound";

const _: () = assert!(SEED_LEN >= 32, "SEED_LEN must be within ZIP 32 range");
const _: () = assert!(SEED_LEN <= 252, "SEED_LEN must be within ZIP 32 range");
const _: () = assert!(FINGERPRINT_LEN == 32, "fingerprint is a 32-byte BLAKE2b digest");
const _: () = assert!(SEALING_KEY_LEN == 32, "XChaCha20Poly1305 key is 32 bytes");
const _: () = assert!(NONCE_LEN == 24, "XChaCha20Poly1305 nonce is 24 bytes");
const _: () = assert!(TAG_LEN == 16, "Poly1305 tag is 16 bytes");
const _: () = assert!(CIPHERTEXT_LEN == SEED_LEN + TAG_LEN, "ciphertext = plaintext + tag");

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
compile_error!("zns-keygen requires x86_64 Linux with RDSEED and /dev/sev-guest");

fn main() {
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
    let sealing_key = derive_instance_bound_sev_sealing_key();
    let capsule = seal_seed(&seed, &sealing_key, fingerprint);
    let capsule_bytes = postcard::to_allocvec(&capsule).unwrap();
    let capsule_hash = blake2b256(&capsule_bytes);

    let report_data = attestation_report_data(fingerprint, &capsule_hash);
    let report_bytes = request_attestation_report(&report_data);
    let report = AttestationReport::from_bytes(&report_bytes).unwrap();
    let report_data_hash = blake2b256(&report_data);
    let attestation_hash = blake2b256(&report_bytes);
    let measurement = hex::encode(report.measurement);

    let manifest = custody_manifest(
        fingerprint,
        &capsule_hash,
        &report_data_hash,
        &attestation_hash,
        &measurement,
    );
    let mint_config = mint_config_toml(fingerprint);

    write_new_file(capsule_path, &capsule_bytes);
    write_new_file(manifest_path, manifest.as_bytes());
    write_new_file(mint_config_path, mint_config.as_bytes());
    write_new_file(attestation_path, &report_bytes);

    println!("ZNS genesis capsule created");
    println!("capsule: {}", capsule_path.display());
    println!("manifest: {}", manifest_path.display());
    println!("mint_config: {}", mint_config_path.display());
    println!("attestation: {}", attestation_path.display());
    println!("seed_fingerprint: {fingerprint}");
    println!("capsule_hash_blake2b256: {}", hex::encode(capsule_hash));
    println!("attestation_hash_blake2b256: {}", hex::encode(attestation_hash));
    println!("measurement: {measurement}");
    println!("report_data_hash_blake2b256: {}", hex::encode(report_data_hash));
    println!("migration: none");
    println!("signer_socket: none");
}

struct Seed(Zeroizing<[u8; SEED_LEN]>);

impl Seed {
    fn generate() -> Seed {
        let mut seed = Seed(Zeroizing::new([0u8; SEED_LEN]));
        fill_entropy(&mut seed.0[..]);
        seed
    }

    fn expose<R>(&self, f: impl FnOnce(&[u8; SEED_LEN]) -> R) -> R {
        f(&self.0)
    }

    fn fingerprint(&self) -> SeedFingerprint {
        self.expose(|seed_bytes| {
            SeedFingerprint::from_seed(seed_bytes)
                .expect("SEED_LEN is const-asserted to be within ZIP 32 range [32, 252]")
        })
    }
}

struct SealingKey(Zeroizing<[u8; SEALING_KEY_LEN]>);

impl SealingKey {
    fn as_bytes(&self) -> &[u8; SEALING_KEY_LEN] {
        &self.0
    }
}

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct SeedCapsule {
    magic: [u8; 8],
    fingerprint: [u8; FINGERPRINT_LEN],
    nonce: Vec<u8>,
    ciphertext: Vec<u8>,
}

fn seal_seed(
    seed: &Seed,
    sealing_key: &SealingKey,
    fingerprint: SeedFingerprint,
) -> SeedCapsule {
    let cipher = XChaCha20Poly1305::new_from_slice(sealing_key.as_bytes())
        .expect("sealing key length is const-asserted to 32 bytes");

    let mut nonce = [0u8; NONCE_LEN];
    fill_entropy(&mut nonce);
    let aad = capsule_aad(fingerprint);
    let nonce_ref = <&XNonce>::try_from(nonce.as_slice())
        .expect("nonce length is const-asserted to 24 bytes");

    let ciphertext = seed.expose(|seed_bytes| {
        cipher.encrypt(
            nonce_ref,
            Payload {
                msg: seed_bytes,
                aad: &aad,
            },
        )
    }).expect("failed to encrypt seed");

    assert_eq!(
        ciphertext.len(),
        CIPHERTEXT_LEN,
        "capsule ciphertext length mismatch: expected {CIPHERTEXT_LEN}, got {}",
        ciphertext.len()
    );

    SeedCapsule {
        magic: *CAPSULE_MAGIC,
        fingerprint: fingerprint.to_bytes(),
        nonce: nonce.to_vec(),
        ciphertext,
    }
}

fn capsule_aad(fingerprint: SeedFingerprint) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CAPSULE_MAGIC.len() + FINGERPRINT_LEN + CAPSULE_CONTEXT.len());
    aad.extend_from_slice(CAPSULE_MAGIC);
    aad.extend_from_slice(&fingerprint.to_bytes());
    aad.extend_from_slice(CAPSULE_CONTEXT);
    aad
}

#[derive(serde::Serialize)]
struct CustodyManifest {
    manifest_version: u8,
    network: &'static str,
    seed_fingerprint: String,
    capsule_file: &'static str,
    capsule_hash_blake2b256: String,
    capsule_format: String,
    capsule_context: String,
    seed_length: usize,
    treasury_account: u32,
    registry_account: u32,
    sealing: &'static str,
    sealing_root_key: &'static str,
    sealing_guest_fields: &'static str,
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
) -> String {
    let manifest = CustodyManifest {
        manifest_version: 1,
        network: NETWORK,
        seed_fingerprint: fingerprint.to_string(),
        capsule_file: CAPSULE_FILE,
        capsule_hash_blake2b256: hex::encode(capsule_hash),
        capsule_format: String::from_utf8_lossy(CAPSULE_MAGIC).into_owned(),
        capsule_context: String::from_utf8_lossy(CAPSULE_CONTEXT).into_owned(),
        seed_length: SEED_LEN,
        treasury_account: TREASURY_ACCOUNT,
        registry_account: REGISTRY_ACCOUNT,
        sealing: "amd-sev-snp-vmrk-instance-bound",
        sealing_root_key: "vmrk",
        sealing_guest_fields: "guest_policy,image_id,family_id,measurement",
        rng: "rdseed",
        attestation_file: ATTESTATION_FILE,
        attestation_hash_blake2b256: hex::encode(attestation_hash),
        report_data_hash_blake2b256: hex::encode(report_data_hash),
        measurement: measurement.to_string(),
        attestation_sig_algo: "ecdsa-p256-sha384",
        migration: "none",
        signer_socket: "none",
    };
    toml::to_string(&manifest).unwrap()
}

#[derive(serde::Serialize)]
struct MintConfig {
    network: &'static str,
    expected_seed_fingerprint: String,
}

fn mint_config_toml(fingerprint: SeedFingerprint) -> String {
    let config = MintConfig {
        network: NETWORK,
        expected_seed_fingerprint: fingerprint.to_string(),
    };
    toml::to_string(&config).unwrap()
}

fn blake2b256(bytes: &[u8]) -> [u8; 32] {
    let digest = Blake2bParams::new()
        .hash_length(32)
        .to_state()
        .update(bytes)
        .finalize();
    digest.as_bytes()[..32]
        .try_into()
        .expect("BLAKE2b output length is fixed")
}

/// Compute the 64-byte report_data for the SEV-SNP attestation report.
///
/// report_data = BLAKE2b-512(seed_fingerprint || capsule_hash)
///
/// This binds the attestation to this specific capsule so a verifier
/// can confirm the report was produced for THIS run, not replayed.
fn attestation_report_data(
    fingerprint: SeedFingerprint,
    capsule_hash: &[u8; 32],
) -> [u8; REPORT_DATA_LEN] {
    let mut input = Vec::with_capacity(FINGERPRINT_LEN + 32);
    input.extend_from_slice(&fingerprint.to_bytes());
    input.extend_from_slice(capsule_hash);

    let digest = Blake2bParams::new()
        .hash_length(REPORT_DATA_LEN)
        .to_state()
        .update(&input)
        .finalize();

    let mut report_data = [0u8; REPORT_DATA_LEN];
    report_data.copy_from_slice(digest.as_bytes());
    report_data
}

/// Request a SEV-SNP attestation report from the AMD PSP.
///
/// The report is signed by the VCEK (ECDSA-P256). Verifiers fetch
/// the VCEK cert from AMD's KDS using chip_id and reported_tcb.
fn request_attestation_report(report_data: &[u8; REPORT_DATA_LEN]) -> Vec<u8> {
    let mut firmware = Firmware::open().expect("failed to open /dev/sev-guest");
    firmware
        .get_report(None, Some(*report_data), None)
        .expect("failed to request SEV-SNP attestation report")
}

fn fill_entropy(dest: &mut [u8]) {
    if dest.is_empty() {
        return;
    }

    let mut offset = 0;
    while offset < dest.len() {
        let mut value = 0u64;

        for _ in 0..10_000 {
            unsafe {
                if core::arch::x86_64::_rdseed64_step(&mut value) == 1 {
                    break;
                }
            }
            spin_loop();
        }

        if value == 0 {
            panic!("RDSEED hardware entropy was unavailable after 10000 retries");
        }

        let bytes = value.to_ne_bytes();
        let take = std::cmp::min(bytes.len(), dest.len() - offset);
        dest[offset..offset + take].copy_from_slice(&bytes[..take]);
        value.zeroize();
        offset += take;
    }
}

fn derive_instance_bound_sev_sealing_key() -> SealingKey {
    let mut firmware = Firmware::open().expect("failed to open /dev/sev-guest");

    let mut guest_fields = GuestFieldSelect::default();
    guest_fields.set_guest_policy(true);
    guest_fields.set_image_id(true);
    guest_fields.set_family_id(true);
    guest_fields.set_measurement(true);

    let request = DerivedKey::new(true, guest_fields, 0, 0, 0, None);
    let mut key = firmware
        .get_derived_key(None, request)
        .expect("failed to derive SEV-SNP VMRK sealing key");

    let sealing_key = SealingKey(Zeroizing::new(key));
    key.zeroize();
    sealing_key
}

fn ensure_absent(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(_) => panic!("{} already exists; refusing to create another genesis capsule", path.display()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => panic!("failed to inspect {}: {err}", path.display()),
    }
}

fn write_new_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .expect("failed to create file");

    file.write_all(bytes).expect("failed to write file");
    file.sync_all().expect("failed to sync file");

    sync_parent(path);
}

fn sync_parent(path: &Path) {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));

    File::open(parent)
        .and_then(|file| file.sync_all())
        .expect("failed to sync parent directory");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_seed_matches_zip32_reference_vector() {
        let seed_bytes: [u8; SEED_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let expected: [u8; 32] = [
            0xde, 0xff, 0x60, 0x4c, 0x24, 0x67, 0x10, 0xf7, 0x17, 0x6d, 0xea,
            0xd0, 0x2a, 0xa7, 0x46, 0xf2, 0xfd, 0x8d, 0x53, 0x89, 0xf7, 0x07,
            0x25, 0x56, 0xdc, 0xb5, 0x55, 0xfd, 0xbe, 0x5e, 0x3a, 0xe3,
        ];
        let fp = SeedFingerprint::from_seed(&seed_bytes).unwrap();
        assert_eq!(fp.to_bytes(), expected);
        assert_eq!(
            fp.to_string(),
            "zip32seedfp1mmlkqnpyvug0w9mdatgz4f6x7t7c65uf7urj24kuk42lm0j78t3sne2h0z"
        );
    }

    #[test]
    fn capsule_serializes_with_postcard() {
        let capsule = SeedCapsule {
            magic: *CAPSULE_MAGIC,
            fingerprint: [0xAA; FINGERPRINT_LEN],
            nonce: vec![0xBB; NONCE_LEN],
            ciphertext: vec![0xCC; CIPHERTEXT_LEN],
        };
        let bytes = postcard::to_allocvec(&capsule).unwrap();
        let decoded: SeedCapsule = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(decoded.magic, *CAPSULE_MAGIC);
        assert_eq!(decoded.fingerprint, [0xAA; FINGERPRINT_LEN]);
        assert_eq!(decoded.nonce, vec![0xBB; NONCE_LEN]);
        assert_eq!(decoded.ciphertext, vec![0xCC; CIPHERTEXT_LEN]);
    }

    #[test]
    fn manifest_serializes_to_toml() {
        let seed_bytes: [u8; SEED_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let fp = SeedFingerprint::from_seed(&seed_bytes).unwrap();
        let manifest = custody_manifest(
            fp,
            &[0u8; 32],
            &[0u8; 32],
            &[0u8; 32],
            "0000000000000000000000000000000000000000000000000000000000000000",
        );
        assert!(manifest.contains("seed_fingerprint"));
        assert!(manifest.contains("mainnet"));
        assert!(manifest.contains("attestation_file"));
        assert!(manifest.contains("measurement"));
    }

    #[test]
    fn mint_config_contains_fingerprint() {
        let seed_bytes: [u8; SEED_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
            0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
            0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let fp = SeedFingerprint::from_seed(&seed_bytes).unwrap();
        let config = mint_config_toml(fp);
        assert!(config.contains("expected_seed_fingerprint"));
    }
}