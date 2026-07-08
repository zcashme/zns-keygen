use std::fs;
use sev::firmware::guest::Firmware;
use zeroize::Zeroize;

use zns_keygen::seedhash::SeedFingerprint;
use zns_keygen::attestation::{generate_rdseed_bytes, generate_attestation_proof, seal_to_hardware};

fn main() {
    println!("=== ZNS Mint: AMD SEV-SNP Key Generation Ceremony ===");
    
    #[cfg(not(target_arch = "x86_64"))]
    panic!("This software must be run on an x86_64 AMD SEV-SNP capable CPU.");

    // DANGER: `seed` is naked key material. Do NOT print, format, or serialize this variable.
    // It must be manually zeroized at the end of this scope.
    let mut raw_seed = [0u8; 32];
    generate_rdseed_bytes(&mut raw_seed);
    
    let fingerprint = SeedFingerprint::from_seed(&raw_seed)
        .expect("Seed is 32 bytes");
        
    println!("✅ Generated true hardware entropy via RDSEED.");
    println!("✅ Derived Public Fingerprint: {}", fingerprint);
    
    let mut firmware = Firmware::open().expect("Failed to open /dev/sev-guest");

    // Step 2: Cryptographic Proof
    let report_bytes = generate_attestation_proof(&mut firmware, &fingerprint);
    fs::write("zns_attestation.report", report_bytes)
        .expect("Failed to write attestation report");
    println!("✅ Saved AMD hardware signature proof to `zns_attestation.report`");

    // Step 3: Hardware Sealing
    let sealed_blob = seal_to_hardware(&mut firmware, &raw_seed);
    fs::write("sealed_seed.bin", sealed_blob)
        .expect("Failed to write sealed seed");
    println!("✅ Saved 60-byte hardware-sealed encrypted seed to `sealed_seed.bin`");
    
    println!("=====================================================");
    println!("Ceremony complete. Destroying seed in memory.");
    
    // CRITICAL: Manually destroy the key material before exiting to prevent memory remnants.
    raw_seed.zeroize();
}
