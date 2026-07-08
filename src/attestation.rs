use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use sev::firmware::guest::{AttestationReport, DerivedKey, Firmware, GuestFieldSelect};
use sev::parser::ByteParser;
use std::hint::spin_loop;
use zeroize::Zeroize;

use crate::seedhash::SeedFingerprint;

pub const SEALED_SEED_LEN: usize = 60;

/// 1. The Entropy: Pull pure hardware entropy directly from AMD silicon.
#[cfg(target_arch = "x86_64")]
pub fn generate_rdseed_bytes(dest: &mut [u8]) {
    assert!(dest.len() % 8 == 0);
    let chunks = dest.len() / 8;

    let mut i = 0;
    while i < chunks {
        let mut val: u64 = 0;
        let mut retries = 0;
        let mut success = false;

        while retries < 10_000 {
            unsafe {
                if core::arch::x86_64::_rdseed64_step(&mut val) == 1 {
                    let bytes = val.to_ne_bytes();
                    dest[i * 8..(i + 1) * 8].copy_from_slice(&bytes);
                    success = true;
                    break;
                } else {
                    spin_loop();
                    retries += 1;
                }
            }
        }

        if !success {
            panic!(
                "Hardware entropy pool (RDSEED) exhausted after 10,000 retries. Aborting ceremony."
            );
        }
        i += 1;
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn generate_rdseed_bytes(_dest: &mut [u8]) {
    panic!("This software must be run on an x86_64 AMD SEV-SNP capable CPU.");
}

/// 2. The Proof: Generate an AMD SEV-SNP Attestation Report embedding the fingerprint.
pub fn generate_attestation_proof(
    firmware: &mut Firmware,
    fingerprint: &SeedFingerprint,
) -> Vec<u8> {
    generate_attestation_proof_with_challenge(firmware, fingerprint, [0u8; 32])
}

pub fn generate_attestation_proof_with_challenge(
    firmware: &mut Firmware,
    fingerprint: &SeedFingerprint,
    challenge: [u8; 32],
) -> Vec<u8> {
    println!("Requesting Attestation Report from AMD Secure Processor...");

    let report_data = report_data(fingerprint, challenge);

    let report = firmware
        .get_report(None, Some(report_data), None)
        .expect("Failed to get Attestation Report from /dev/sev-guest");

    report
        .to_bytes()
        .expect("Failed to serialize Attestation Report")
        .to_vec()
}

pub fn report_data(fingerprint: &SeedFingerprint, challenge: [u8; 32]) -> [u8; 64] {
    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(&fingerprint.to_bytes());
    report_data[32..64].copy_from_slice(&challenge);
    report_data
}

pub fn verify_report_binding(
    report_bytes: &[u8],
    fingerprint: &SeedFingerprint,
    challenge: [u8; 32],
) -> Result<(), String> {
    let report = AttestationReport::from_bytes(report_bytes)
        .map_err(|err| format!("failed to parse SEV-SNP report: {err}"))?;
    let expected = report_data(fingerprint, challenge);

    if report.report_data != expected {
        return Err("report_data does not bind the expected fingerprint/challenge".to_string());
    }

    Ok(())
}

/// 3. The Hardware Storage: Ask the AMD silicon for a key derived from our exact ISO hash.
pub fn seal_to_hardware(
    firmware: &mut Firmware,
    seed: &[u8; 32],
    fingerprint: &SeedFingerprint,
) -> [u8; SEALED_SEED_LEN] {
    println!("Requesting derived sealing key from AMD Secure Processor...");

    let mut hardware_key = derive_sealing_key(firmware);

    println!("Encrypting seed with AMD hardware-derived key...");

    let cipher =
        ChaCha20Poly1305::new_from_slice(hardware_key.as_slice()).expect("Invalid key length");
    hardware_key.zeroize();

    let mut nonce_bytes = [0u8; 12];
    let mut raw_nonce_buf = [0u8; 16];
    generate_rdseed_bytes(&mut raw_nonce_buf);
    nonce_bytes.copy_from_slice(&raw_nonce_buf[0..12]);
    let nonce = Nonce::from(nonce_bytes);

    let payload = Payload {
        msg: seed.as_slice(),
        aad: &seal_aad(fingerprint),
    };
    let ciphertext = cipher.encrypt(&nonce, payload).expect("Encryption failure");

    assert_eq!(ciphertext.len(), 48, "Ciphertext + MAC must be 48 bytes");

    let mut sealed_blob = [0u8; SEALED_SEED_LEN];
    sealed_blob[0..12].copy_from_slice(&nonce_bytes);
    sealed_blob[12..SEALED_SEED_LEN].copy_from_slice(&ciphertext);

    sealed_blob
}

pub fn unseal_from_hardware(
    firmware: &mut Firmware,
    sealed_blob: &[u8; SEALED_SEED_LEN],
    fingerprint: &SeedFingerprint,
) -> [u8; 32] {
    println!("Requesting derived sealing key from AMD Secure Processor...");

    let mut hardware_key = derive_sealing_key(firmware);
    let cipher =
        ChaCha20Poly1305::new_from_slice(hardware_key.as_slice()).expect("Invalid key length");
    hardware_key.zeroize();

    let nonce_bytes: [u8; 12] = sealed_blob[0..12]
        .try_into()
        .expect("nonce length is fixed");
    let nonce = Nonce::from(nonce_bytes);
    let payload = Payload {
        msg: &sealed_blob[12..SEALED_SEED_LEN],
        aad: &seal_aad(fingerprint),
    };
    let mut plaintext = cipher
        .decrypt(&nonce, payload)
        .expect("Failed to decrypt sealed seed");

    let seed: [u8; 32] = plaintext
        .as_slice()
        .try_into()
        .expect("sealed seed plaintext must be 32 bytes");
    plaintext.zeroize();
    seed
}

fn derive_sealing_key(firmware: &mut Firmware) -> [u8; 32] {
    let mut guest_field = GuestFieldSelect::default();
    guest_field.set_measurement(true);
    let request = DerivedKey::new(false, guest_field, 0, 0, 0, None);

    firmware
        .get_derived_key(None, request)
        .expect("Failed to derive hardware key from /dev/sev-guest")
}

fn seal_aad(fingerprint: &SeedFingerprint) -> [u8; 48] {
    let mut aad = [0u8; 48];
    aad[0..16].copy_from_slice(b"ZNS_KEYS_SEED_V1");
    aad[16..48].copy_from_slice(&fingerprint.to_bytes());
    aad
}
