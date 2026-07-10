//! zns-keygen — signing-key genesis tool for Zcash Name Service
//!
//! 1. Generates a random 32-byte seed using the CPU's RDSEED instruction
//! 2. Computes a ZIP-32 seed fingerprint (BLAKE2b-256) so the seed can be
//!    identified later without revealing it.
//! 3. Derives a sealing key from the AMD SEV-SNP hardware
//! 4. Encrypts the seed with XChaCha20Poly1305 using that sealing key,
//!    producing a "capsule" that can only be decrypted by this VM.
//! 5. Requests an attestation report from the AMD PSP (Platform Security
//!    Processor) — a hardware-signed proof that this code ran on genuine
//!    SEV-SNP hardware with a specific measurement (code hash).
//! 6. Writes four files to disk: the capsule, a public manifest, a mint
//!    config, and the attestation report.
//! 7. Exits. It never runs again.
//!

mod fingerprint;

// ── Dependencies ───────────────────────────────────────────────────────
// BLAKE2b is used for hashing (seed fingerprint, capsule hash, report_data).
use blake2b_simd::Params as Blake2bParams;
// XChaCha20Poly1305 is the AEAD cipher used to encrypt the seed into the
// capsule. It provides both confidentiality (encryption) and integrity
// (authentication tag), so any tampering with the ciphertext is detected.
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
// The `sev` crate provides access to the AMD SEV-SNP firmware interface
// (/dev/sev-guest) for two things: deriving a VM-bound key, and requesting
// an attestation report signed by the AMD PSP.
use sev::firmware::guest::{AttestationReport, DerivedKey, Firmware, GuestFieldSelect};
// Standard library I/O for reading/writing files.
use std::fs::{self, File, OpenOptions};
use std::hint::spin_loop;
use std::io::Write;
// On Unix, we use OpenOptionsExt to set file permissions (0o600 = owner
// read/write only) when creating files.
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
// Zeroize ensures secrets are wiped from memory when they go out of scope,
// so the seed and sealing key don't linger in RAM longer than necessary.
use zeroize::{Zeroize, Zeroizing};

use fingerprint::SeedFingerprint;

// ── Output file names ─────────────────────────────────────────────────
// These are the four files zns-keygen writes. They must not already exist
// when the tool runs — if any do, it panics (see ensure_absent below).
const CAPSULE_FILE: &str = "zns_seed.capsule";
const MANIFEST_FILE: &str = "zns_custody_manifest.toml";
const MINT_CONFIG_FILE: &str = "zns_mint.conf";
const ATTESTATION_FILE: &str = "zns_attestation.bin";

// ── Cryptographic constants ───────────────────────────────────────────
// The SEV-SNP attestation report has a 64-byte report_data field that the
// guest can fill with arbitrary data. We use it to bind the attestation to
// this specific capsule (see attestation_report_data below).
const REPORT_DATA_LEN: usize = 64;

// ZNS network and account layout. The seed is a ZIP-32 master seed; child
// keys are derived from it by account index. Account 0 is the treasury,
// account 1 is the registry (the mint's spending key).
const NETWORK: &str = "mainnet";
const TREASURY_ACCOUNT: u32 = 0;
const REGISTRY_ACCOUNT: u32 = 1;

// These are the sizes of the cryptographic materials. They are checked at
// compile time by the const asserts below.
const SEED_LEN: usize = 32; // ZIP-32 requires 32–252 bytes
const FINGERPRINT_LEN: usize = 32; // BLAKE2b-256 output
const SEALING_KEY_LEN: usize = 32; // XChaCha20Poly1305 key length
const NONCE_LEN: usize = 24; // XChaCha20 uses an extended 24-byte nonce
const TAG_LEN: usize = 16; // Poly1305 authentication tag
const CIPHERTEXT_LEN: usize = SEED_LEN + TAG_LEN; // ciphertext = plaintext + tag

// The capsule magic identifies the file format. If the first 8 bytes of a
// file aren't "ZNSCAPS1", it's not a ZNS capsule.
const CAPSULE_MAGIC: &[u8; 8] = b"ZNSCAPS1";

// Compile-time checks: if any of these sizes are wrong, the build fails.
// This catches mistakes before the tool ever runs.
const _: () = assert!(SEED_LEN >= 32, "SEED_LEN must be within ZIP 32 range");
const _: () = assert!(SEED_LEN <= 252, "SEED_LEN must be within ZIP 32 range");
const _: () = assert!(
    FINGERPRINT_LEN == 32,
    "fingerprint is a 32-byte BLAKE2b digest"
);
const _: () = assert!(SEALING_KEY_LEN == 32, "XChaCha20Poly1305 key is 32 bytes");
const _: () = assert!(NONCE_LEN == 24, "XChaCha20Poly1305 nonce is 24 bytes");
const _: () = assert!(TAG_LEN == 16, "Poly1305 tag is 16 bytes");
const _: () = assert!(
    CIPHERTEXT_LEN == SEED_LEN + TAG_LEN,
    "ciphertext = plaintext + tag"
);

// zns-keygen only works on x86_64 Linux because RDSEED and /dev/sev-guest
// are x86_64 Linux-specific. On any other platform, the build fails.
#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
compile_error!("zns-keygen requires x86_64 Linux with RDSEED and /dev/sev-guest");

// ── Main entry point ──────────────────────────────────────────────────
//
// The entire tool is one linear function. There is no error handling —
// if any step fails, it panics with a descriptive message. This is
// intentional: this is a one-shot ceremony tool, and partial output is
// worse than no output.

fn main() {
    // Paths for the four output files.
    let capsule_path = Path::new(CAPSULE_FILE);
    let manifest_path = Path::new(MANIFEST_FILE);
    let mint_config_path = Path::new(MINT_CONFIG_FILE);
    let attestation_path = Path::new(ATTESTATION_FILE);

    // Safety check: refuse to run if any output file already exists.
    // This prevents accidentally overwriting a previous genesis capsule,
    // which would silently invalidate the mint.
    ensure_absent(capsule_path);
    ensure_absent(manifest_path);
    ensure_absent(mint_config_path);
    ensure_absent(attestation_path);

    // Step 1: Generate the seed from hardware entropy (RDSEED).
    let seed = Seed::generate();

    // Step 2: Compute the ZIP-32 seed fingerprint. This is a public,
    // non-reversible hash of the seed. It lets anyone identify which
    // seed produced this capsule without knowing the seed itself.
    let fingerprint = seed.fingerprint();

    // Step 3: Derive a sealing key from the AMD SEV-SNP hardware.
    // This key is unique to this specific VM launch — a different VM
    // (even with the same image) would get a different key. This is
    // what makes the capsule "sealed" to this VM instance.
    let sealing_key = derive_instance_bound_sev_sealing_key();

    // Step 4: Encrypt the seed into the capsule. The capsule contains
    // the ciphertext (encrypted seed + auth tag), the nonce, and the
    // fingerprint (in plaintext, for identification).
    let capsule = seal_seed(&seed, &sealing_key, fingerprint);

    // Serialize the capsule to bytes (using postcard, a compact binary
    // format) and hash it for the manifest.
    let capsule_bytes = postcard::to_allocvec(&capsule).unwrap();
    let capsule_hash = blake2b256(&capsule_bytes);

    // Step 5: Request an attestation report from the AMD PSP.
    // The report_data binds the attestation to this specific seed
    // fingerprint and capsule hash, so a verifier can confirm the
    // report was produced for THIS capsule — not replayed.
    let report_data = attestation_report_data(fingerprint, &capsule_hash);
    let report_bytes = request_attestation_report(&report_data);

    // Parse the attestation report to extract the measurement (the hash
    // of the VM's initial code). This goes into the manifest so verifiers
    // know what measurement to expect without parsing the binary report.
    let report = AttestationReport::from_bytes(&report_bytes).unwrap();
    let report_data_hash = blake2b256(&report_data);
    let attestation_hash = blake2b256(&report_bytes);
    let measurement = hex::encode(report.measurement);

    // Step 6: Build the manifest (public TOML metadata) and mint config.
    let manifest = custody_manifest(
        fingerprint,
        &capsule_hash,
        &report_data_hash,
        &attestation_hash,
        &measurement,
    );
    let mint_config = mint_config_toml(fingerprint);

    // Step 7: Write all four files to disk (with sync, mode 0o600).
    write_new_file(capsule_path, &capsule_bytes);
    write_new_file(manifest_path, manifest.as_bytes());
    write_new_file(mint_config_path, mint_config.as_bytes());
    write_new_file(attestation_path, &report_bytes);

    // Print a summary of what was produced. This output is also useful
    // for logging the ceremony — record it somewhere durable.
    println!("ZNS genesis capsule created");
    println!("capsule: {}", capsule_path.display());
    println!("manifest: {}", manifest_path.display());
    println!("mint_config: {}", mint_config_path.display());
    println!("attestation: {}", attestation_path.display());
    println!("seed_fingerprint: {fingerprint}");
    println!("capsule_hash_blake2b256: {}", hex::encode(capsule_hash));
    println!(
        "attestation_hash_blake2b256: {}",
        hex::encode(attestation_hash)
    );
    println!("measurement: {measurement}");
    println!(
        "report_data_hash_blake2b256: {}",
        hex::encode(report_data_hash)
    );
    println!("migration: none");
    println!("signer_socket: none");
}

// ── Seed wrapper ──────────────────────────────────────────────────────
// Seed wraps a 32-byte array inside Zeroizing, which zeroizes the memory
// when the Seed is dropped. This ensures the raw seed bytes don't linger
// in RAM after they're no longer needed.
//
// The seed is the master secret — from it, all ZNS spending keys are
// derived via ZIP-32. If the seed is compromised, the attacker can
// control the entire ZNS registry.

struct Seed(Zeroizing<[u8; SEED_LEN]>);

impl Seed {
    /// Generate a new seed from hardware entropy (RDSEED).
    /// Panics if RDSEED is unavailable or fails after 10,000 retries.
    fn generate() -> Seed {
        let mut seed = Seed(Zeroizing::new([0u8; SEED_LEN]));
        fill_entropy(&mut seed.0[..]);
        seed
    }

    /// Temporarily expose the raw seed bytes for a computation, then
    /// the Zeroizing wrapper ensures they're wiped when done.
    /// Used for fingerprint computation and encryption.
    fn expose<R>(&self, f: impl FnOnce(&[u8; SEED_LEN]) -> R) -> R {
        f(&self.0)
    }

    /// Compute the ZIP-32 seed fingerprint: a BLAKE2b-256 hash of the seed,
    /// encoded as Bech32m with the human-readable prefix "zip32seedfp".
    /// This is public — it identifies the seed without revealing it.
    fn fingerprint(&self) -> SeedFingerprint {
        self.expose(|seed_bytes| {
            SeedFingerprint::from_seed(seed_bytes)
                .expect("SEED_LEN is const-asserted to be within ZIP 32 range [32, 252]")
        })
    }
}

// ── Sealing key wrapper ───────────────────────────────────────────────
// Same pattern as Seed: the sealing key is wrapped in Zeroizing so it's
// wiped from memory when it goes out of scope.

struct SealingKey(Zeroizing<[u8; SEALING_KEY_LEN]>);

impl SealingKey {
    fn as_bytes(&self) -> &[u8; SEALING_KEY_LEN] {
        &self.0
    }
}

// ── Capsule (encrypted seed) ─────────────────────────────────────────
// The capsule is the encrypted seed. It can be published publicly —
// without the sealing key (which only exists inside this VM), it's
// just random bytes.
//
// The fingerprint is stored in plaintext so that zns-mint can quickly
// identify which capsule it has without needing to decrypt first.

#[derive(serde::Serialize, serde::Deserialize, Clone)]
struct SeedCapsule {
    magic: [u8; 8],                     // "ZNSCAPS1" — identifies the file format
    fingerprint: [u8; FINGERPRINT_LEN], // ZIP-32 seed fingerprint (plaintext, not secret)
    nonce: Vec<u8>, // 24-byte XChaCha20Poly1305 nonce (random, stored in plaintext by design)
    ciphertext: Vec<u8>, // 48 bytes: 32-byte encrypted seed + 16-byte Poly1305 auth tag
}

/// Encrypt the seed into a capsule using the SEV-SNP-derived sealing key.
///
/// The encryption uses XChaCha20Poly1305, an AEAD (Authenticated Encryption
/// with Associated Data) cipher. The "associated data" (AAD) is just the
/// capsule magic and the seed fingerprint. This means:
///
/// - Tampering with the ciphertext is detected (Poly1305 tag fails to verify)
/// - The capsule can't be swapped with another capsule's ciphertext
///   (fingerprint in AAD won't match)
///
/// Network binding (testnet vs mainnet) and sealing policy are NOT in the
/// AAD — they are enforced by the SEV-SNP key derivation itself. Different
/// VM launches get different keys, so a capsule sealed on one VM can't be
/// decrypted on another. The AAD only needs to bind the ciphertext to the
/// capsule format and this specific seed.
fn seal_seed(seed: &Seed, sealing_key: &SealingKey, fingerprint: SeedFingerprint) -> SeedCapsule {
    // Create the cipher instance from the sealing key.
    let cipher = XChaCha20Poly1305::new_from_slice(sealing_key.as_bytes())
        .expect("sealing key length is const-asserted to 32 bytes");

    // Generate a random nonce. The nonce must be unique per encryption
    // under the same key — XChaCha20's 24-byte nonce makes collisions
    // astronomically unlikely even with random generation.
    let mut nonce = [0u8; NONCE_LEN];
    fill_entropy(&mut nonce);

    // Build the AAD (additional authenticated data). This is NOT encrypted,
    // but it IS authenticated — if any byte changes, decryption fails.
    // This binds the ciphertext to the capsule format and this specific seed.
    let aad = capsule_aad(fingerprint);

    // XChaCha20Poly1305 needs the nonce as a specific type reference.
    let nonce_ref =
        <&XNonce>::try_from(nonce.as_slice()).expect("nonce length is const-asserted to 24 bytes");

    // Encrypt the seed. The closure temporarily exposes the raw seed
    // bytes for encryption, then the Zeroizing wrapper wipes them.
    let ciphertext = seed
        .expose(|seed_bytes| {
            cipher.encrypt(
                nonce_ref,
                Payload {
                    msg: seed_bytes,
                    aad: &aad,
                },
            )
        })
        .expect("failed to encrypt seed");

    // Sanity check: the ciphertext should be exactly 48 bytes
    // (32-byte seed + 16-byte Poly1305 tag).
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

/// Build the AAD (additional authenticated data) for the capsule encryption.
///
/// AAD = magic || fingerprint
///
/// The magic identifies the file format (prevents mixing capsule types).
/// The fingerprint binds the ciphertext to this specific seed (prevents
/// swapping ciphertexts between capsules).
///
/// Network and sealing-policy binding are NOT here — they are enforced by
/// the SEV-SNP key derivation, not by the AAD. Putting them in the AAD
/// would be a redundant label, not an enforcement.
fn capsule_aad(fingerprint: SeedFingerprint) -> Vec<u8> {
    let mut aad = Vec::with_capacity(CAPSULE_MAGIC.len() + FINGERPRINT_LEN);
    aad.extend_from_slice(CAPSULE_MAGIC);
    aad.extend_from_slice(&fingerprint.to_bytes());
    aad
}

// ── Custody manifest (public TOML metadata) ──────────────────────────
// The manifest is a public TOML file that records everything about the
// capsule: the seed fingerprint, capsule hash, sealing policy, attestation
// info, etc. It never contains the seed or the sealing key.
//
// Anyone can read the manifest to learn what the capsule is, how it was
// sealed, and how to verify the attestation.

#[derive(serde::Serialize)]
struct CustodyManifest {
    manifest_version: u8,                // Format version (1)
    network: &'static str,               // "mainnet"
    seed_fingerprint: String,            // Bech32m ZIP-32 fingerprint
    capsule_file: &'static str,          // "zns_seed.capsule"
    capsule_hash_blake2b256: String,     // Hash of the capsule file
    capsule_format: String,              // "ZNSCAPS1"
    seed_length: usize,                  // 32 bytes
    treasury_account: u32,               // ZIP-32 account 0
    registry_account: u32,               // ZIP-32 account 1
    sealing: &'static str,               // "amd-sev-snp-vmrk-instance-bound"
    sealing_root_key: &'static str,      // "vmrk" (which SEV-SNP root key was used)
    sealing_guest_fields: &'static str,  // Which guest fields were bound into the key
    rng: &'static str,                   // "rdseed"
    attestation_file: &'static str,      // "zns_attestation.bin"
    attestation_hash_blake2b256: String, // Hash of the attestation report
    report_data_hash_blake2b256: String, // Hash of the report_data we put in the report
    measurement: String,                 // VM launch measurement (hex) — the code hash
    attestation_sig_algo: &'static str,  // "ecdsa-p256-sha384"
    migration: &'static str,             // "none" — no migration path in v1
    signer_socket: &'static str,         // "none" — keygen doesn't sign
}

/// Build the manifest TOML string from the ceremony's outputs.
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

// ── Mint config (for zns-mint) ────────────────────────────────────────
// This file is read by zns-mint at startup. It contains the expected seed
// fingerprint so the mint can verify it decrypted the correct seed.
// If the decrypted seed's fingerprint doesn't match, the mint refuses
// to run. This file must be part of the measured launch state.

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

// ── Hashing utility ───────────────────────────────────────────────────

/// Compute BLAKE2b-256 (32-byte digest). Used for capsule hash, attestation
/// hash, report_data hash — all the hashes that go in the manifest.
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

// ── Attestation report_data ───────────────────────────────────────────

/// Compute the 64-byte report_data for the SEV-SNP attestation report.
///
/// report_data = BLAKE2b-512(seed_fingerprint || capsule_hash)
///
/// The AMD PSP signs the attestation report, and the report includes this
/// report_data. This cryptographically binds the attestation to this
/// specific capsule: a verifier can recompute BLAKE2b-512 from the
/// manifest's seed_fingerprint and capsule_hash, and check it matches
/// the report_data inside the attestation report.
///
/// Without this binding, an attacker could take a valid attestation from
/// one ceremony and claim it was for a different capsule.
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

// ── SEV-SNP attestation report request ────────────────────────────────

/// Request a SEV-SNP attestation report from the AMD PSP.
///
/// The PSP (Platform Security Processor) is a separate secure processor
/// on the AMD chip. It signs the attestation report with the VCEK
/// (Versioned Chip Endorsement Key), an ECDSA-P256 key whose certificate
/// chains to AMD's root CA.
///
/// The report contains:
/// - The VM's measurement (hash of the guest's initial code — proves
///   what software was running)
/// - The guest policy, image_id, family_id (launch parameters)
/// - The report_data we supplied (our binding to the capsule)
/// - The chip_id and reported_tcb (needed to fetch the VCEK cert from
///   AMD's KDS for verification)
/// - The ECDSA-P256 signature over all of the above
///
/// To verify the report, a third party:
/// 1. Parses the report to extract chip_id and reported_tcb
/// 2. Fetches the VCEK cert from https://kdsintf.amd.com/vcek/v1/...
/// 3. Verifies the ARK → ASK → VCEK certificate chain
/// 4. Verifies the ECDSA-P256 signature on the report
/// 5. Checks the measurement matches the expected zns-keygen binary
/// 6. Checks the report_data matches BLAKE2b-512(fingerprint || capsule_hash)
fn request_attestation_report(report_data: &[u8; REPORT_DATA_LEN]) -> Vec<u8> {
    let mut firmware = Firmware::open().expect("failed to open /dev/sev-guest");
    firmware
        .get_report(None, Some(*report_data), None)
        .expect("failed to request SEV-SNP attestation report")
}

// ── Hardware entropy (RDSEED) ────────────────────────────────────────

/// Fill a buffer with random bytes using the x86_64 RDSEED instruction.
///
/// RDSEED reads directly from the CPU's hardware entropy source (not a
/// software DRBG). This is the most fundamental source of randomness
/// available on the platform — it's what NIST SP 800-90B calls a "full
/// entropy source."
///
/// RDSEED can occasionally return "not ready" (the entropy pool is
/// temporarily exhausted). We retry up to 10,000 times with a CPU spin
/// loop between attempts. If it still fails, we panic — no software
/// fallback, no /dev/urandom, nothing. If the hardware entropy source
/// is broken, we stop.
fn fill_entropy(dest: &mut [u8]) {
    if dest.is_empty() {
        return;
    }

    let mut offset = 0;
    while offset < dest.len() {
        let mut value = 0u64;

        // Try RDSEED up to 10,000 times. The instruction returns 1 on
        // success (value is filled) or 0 on failure (try again).
        for _ in 0..10_000 {
            unsafe {
                if core::arch::x86_64::_rdseed64_step(&mut value) == 1 {
                    break;
                }
            }
            spin_loop();
        }

        // If value is still 0, RDSEED failed 10,000 times. The hardware
        // entropy source is broken or unavailable — stop immediately.
        if value == 0 {
            panic!("RDSEED hardware entropy was unavailable after 10000 retries");
        }

        // Copy the 8 random bytes into the destination buffer, then
        // zeroize the local variable.
        let bytes = value.to_ne_bytes();
        let take = std::cmp::min(bytes.len(), dest.len() - offset);
        dest[offset..offset + take].copy_from_slice(&bytes[..take]);
        value.zeroize();
        offset += take;
    }
}

// ── SEV-SNP sealing key derivation ────────────────────────────────────

/// Derive an instance-bound sealing key from the AMD SEV-SNP hardware.
///
/// The SEV-SNP firmware has a VMRK (VM Root Key) that is unique to each
/// VM launch. We request a derived key that incorporates:
///
/// - The guest policy (VM configuration flags)
/// - The image ID (set at launch time)
/// - The family ID (set at launch time)
/// - The measurement (hash of the guest's initial code)
///
/// This means the sealing key is bound to:
/// - This specific VM launch (VMRK is per-launch)
/// - The specific guest image (measurement)
/// - The specific launch configuration (policy, image_id, family_id)
///
/// A different VM, a different launch, or a different image would get a
/// different key and could not decrypt the capsule.
///
/// The key is wrapped in Zeroizing so it's wiped from memory when done.
fn derive_instance_bound_sev_sealing_key() -> SealingKey {
    let mut firmware = Firmware::open().expect("failed to open /dev/sev-guest");

    // Select which guest fields to include in the key derivation.
    // All four fields are included so the key is maximally bound to
    // this specific VM launch configuration.
    let mut guest_fields = GuestFieldSelect::default();
    guest_fields.set_guest_policy(true);
    guest_fields.set_image_id(true);
    guest_fields.set_family_id(true);
    guest_fields.set_measurement(true);

    // The first parameter (true) means "include the guest policy in the
    // key derivation." The three zeros are VMPL, root_key_select, and
    // an optional override — we use defaults for all.
    let request = DerivedKey::new(true, guest_fields, 0, 0, 0, None);

    let mut key = firmware
        .get_derived_key(None, request)
        .expect("failed to derive SEV-SNP VMRK sealing key");

    // Wrap in Zeroizing and wipe the raw key bytes.
    let sealing_key = SealingKey(Zeroizing::new(key));
    key.zeroize();
    sealing_key
}

// ── File I/O utilities ────────────────────────────────────────────────

/// Panic if the given path already exists. This prevents accidentally
/// overwriting a previous genesis capsule or any other output file.
/// Partial output from a failed run could be dangerously misleading,
/// so we refuse to start if anything is already there.
fn ensure_absent(path: &Path) {
    match fs::symlink_metadata(path) {
        Ok(_) => panic!(
            "{} already exists; refusing to create another genesis capsule",
            path.display()
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => panic!("failed to inspect {}: {err}", path.display()),
    }
}

/// Write bytes to a new file with mode 0600 (owner read/write only),
/// then sync to disk. Panics if the file can't be created or written.
///
/// The sync is important: without it, the file might only be in the
/// OS page cache, not actually on disk. A power failure after write
/// but before sync could lose the data. We also sync the parent
/// directory so the file's directory entry is durable.
fn write_new_file(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true) // Fail if the file already exists
        .mode(0o600) // Owner read/write only
        .open(path)
        .expect("failed to create file");

    file.write_all(bytes).expect("failed to write file");
    file.sync_all().expect("failed to sync file");

    // Also sync the parent directory so the file's metadata
    // (name, permissions) is persisted to disk.
    sync_parent(path);
}

/// Sync the parent directory of a file. This ensures the directory
/// entry (the filename and its metadata) is durably written to disk,
/// not just the file's contents.
fn sync_parent(path: &Path) {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));

    File::open(parent)
        .and_then(|file| file.sync_all())
        .expect("failed to sync parent directory");
}

// ── Tests ─────────────────────────────────────────────────────────────
// These tests verify the cryptographic correctness of the components
// without needing actual SEV-SNP hardware (they don't call the firmware
// or use RDSEED).

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that our BLAKE2b seed fingerprint matches the ZIP-32
    /// reference test vector. This ensures our fingerprint computation
    /// is correct and interoperable with other ZIP-32 implementations.
    #[test]
    fn known_seed_matches_zip32_reference_vector() {
        // Test seed: sequential bytes 0x00 through 0x1f
        let seed_bytes: [u8; SEED_LEN] = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        // Expected fingerprint (from the ZIP-32 spec)
        let expected: [u8; 32] = [
            0xde, 0xff, 0x60, 0x4c, 0x24, 0x67, 0x10, 0xf7, 0x17, 0x6d, 0xea, 0xd0, 0x2a, 0xa7,
            0x46, 0xf2, 0xfd, 0x8d, 0x53, 0x89, 0xf7, 0x07, 0x25, 0x56, 0xdc, 0xb5, 0x55, 0xfd,
            0xbe, 0x5e, 0x3a, 0xe3,
        ];
        let fp = SeedFingerprint::from_seed(&seed_bytes).unwrap();
        assert_eq!(fp.to_bytes(), expected);
        assert_eq!(
            fp.to_string(),
            "zip32seedfp1mmlkqnpyvug0w9mdatgz4f6x7t7c65uf7urj24kuk42lm0j78t3sne2h0z"
        );
    }

    /// Verify that the capsule serializes and deserializes correctly
    /// with the postcard format. If this breaks, zns-mint won't be able
    /// to read capsules produced by zns-keygen.
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

    /// Verify that the manifest serializes to TOML and includes the
    /// new attestation fields. This catches regressions if someone
    /// changes the manifest struct without updating the test.
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
        );
        assert!(manifest.contains("seed_fingerprint"));
        assert!(manifest.contains("mainnet"));
        assert!(manifest.contains("attestation_file"));
        assert!(manifest.contains("measurement"));
    }

    /// Verify that the mint config includes the expected seed fingerprint.
    /// zns-mint reads this on startup and refuses to run if the decrypted
    /// seed's fingerprint doesn't match.
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
