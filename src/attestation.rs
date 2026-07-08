use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use std::hint::spin_loop;
use zeroize::Zeroize;

use crate::seedhash::SeedFingerprint;

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
            panic!("Hardware entropy pool (RDSEED) exhausted after 10,000 retries. Aborting ceremony.");
        }
        i += 1;
    }
}

#[cfg(not(target_arch = "x86_64"))]
pub fn generate_rdseed_bytes(_dest: &mut [u8]) {
    panic!("This software must be run on an x86_64 AMD SEV-SNP capable CPU.");
}

/// 2. The Proof: Generate an AMD SEV-SNP Attestation Report embedding the fingerprint.
pub fn generate_attestation_proof(firmware: &mut Firmware, fingerprint: &SeedFingerprint) -> Vec<u8> {
    println!("Requesting Attestation Report from AMD Secure Processor...");
    
    let mut report_data = [0u8; 64];
    report_data[0..32].copy_from_slice(&fingerprint.to_bytes());
    
    let report = firmware
        .get_report(None, Some(report_data), None)
        .expect("Failed to get Attestation Report from /dev/sev-guest");
    
    let report_bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(
            (&report as *const _) as *const u8,
            std::mem::size_of_val(&report),
        )
    };
    
    report_bytes.to_vec()
}

/// 3. The Hardware Storage: Ask the AMD silicon for a key derived from our exact ISO hash.
pub fn seal_to_hardware(firmware: &mut Firmware, seed: &[u8; 32]) -> [u8; 60] {
    println!("Requesting derived sealing key from AMD Secure Processor...");
    
    let request = DerivedKey::new(false, GuestFieldSelect::MEASUREMENT, 0, 0, 0);
    
    let mut hardware_key = firmware
        .get_derived_key(None, request)
        .expect("Failed to derive hardware key from /dev/sev-guest");

    println!("Encrypting seed with AMD hardware-derived key...");
    
    let cipher = ChaCha20Poly1305::new(hardware_key.as_slice().into());
    hardware_key.zeroize();
    
    let mut nonce_bytes = [0u8; 12];
    let mut raw_nonce_buf = [0u8; 16];
    generate_rdseed_bytes(&mut raw_nonce_buf);
    nonce_bytes.copy_from_slice(&raw_nonce_buf[0..12]);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    let ciphertext = cipher
        .encrypt(nonce, seed.as_slice())
        .expect("Encryption failure");
        
    assert_eq!(ciphertext.len(), 48, "Ciphertext + MAC must be 48 bytes");
    
    let mut sealed_blob = [0u8; 60];
    sealed_blob[0..12].copy_from_slice(&nonce_bytes);
    sealed_blob[12..60].copy_from_slice(&ciphertext);
    
    sealed_blob
}
