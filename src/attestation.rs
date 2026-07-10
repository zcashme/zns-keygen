//! SEV-SNP attestation: request, parse, and self-verify.
//!
//! This module isolates all interaction with the AMD PSP (Platform Security
//! Processor) into one place so that `main.rs` stays a linear ceremony script
//! and the attestation logic is independently testable and auditable.
//!
//! Flow:
//!   1. `report_data()` — compute the 64-byte blob that binds the attestation
//!      to this specific capsule (BLAKE2b-512 of fingerprint ‖ capsule_hash).
//!   2. `request()` — call the PSP via `/dev/sev-guest` to get a signed
//!      attestation report with that report_data embedded.
//!   3. The returned `Attestation` struct carries the raw report bytes (for
//!      writing to disk) plus the parsed fields the manifest needs.
//!   4. `Attestation::verify_report_data()` — self-check that the PSP actually
//!      embedded the report_data we requested, catching PSP garbage before
//!      we write anything to disk.

use blake2b_simd::Params as Blake2bParams;
use sev::firmware::guest::{AttestationReport, Firmware};
use sev::parser::ByteParser;

use crate::fingerprint::SeedFingerprint;
use crate::{FINGERPRINT_LEN, REPORT_DATA_LEN};

/// Parsed attestation report with the fields zns-keygen needs.
///
/// `report_bytes` is the raw 1184-byte report exactly as the PSP signed it.
/// The other fields are extracted from the parsed report for convenience
/// and for the custody manifest.
pub struct Attestation {
    /// Raw attestation report bytes (signed by the PSP, written to disk as-is).
    pub report_bytes: Vec<u8>,
    /// VM launch measurement — hash of the guest's initial code (48 bytes, hex in manifest).
    pub measurement: [u8; 48],
    /// Guest policy value (u64, hex in manifest).
    pub guest_policy: u64,
    /// Image ID set at launch (16 bytes, hex in manifest).
    pub image_id: [u8; 16],
    /// Family ID set at launch (16 bytes, hex in manifest).
    pub family_id: [u8; 16],
    /// The report_data we supplied (kept for self-verification).
    pub report_data: [u8; REPORT_DATA_LEN],
}

impl Attestation {
    /// Self-verify that the report_data inside the attestation report
    /// matches what we requested. This catches PSP garbage or a firmware
    /// bug before we write anything to disk.
    ///
    /// Panics on mismatch — this is a one-shot ceremony tool, and a
    /// mismatched attestation is worse than no attestation.
    pub fn verify_report_data(&self) {
        let report = AttestationReport::from_bytes(&self.report_bytes)
            .expect("failed to parse attestation report for self-verification");

        assert_eq!(
            report.report_data, self.report_data,
            "attestation report_data mismatch: the PSP did not embed the report_data we requested"
        );

        // Sanity: measurement must not be all zeros (would indicate a broken launch).
        assert!(
            report.measurement.iter().any(|&b| b != 0),
            "attestation measurement is all zeros — VM may not have been properly launched"
        );
    }
}

/// Compute the 64-byte `report_data` for the SEV-SNP attestation report.
///
/// `report_data = BLAKE2b-512(seed_fingerprint ‖ capsule_hash)`
///
/// The AMD PSP signs the attestation report, and the report includes this
/// `report_data`. This cryptographically binds the attestation to this
/// specific capsule: a verifier can recompute BLAKE2b-512 from the
/// manifest's `seed_fingerprint` and `capsule_hash`, and check it matches
/// the `report_data` inside the attestation report.
///
/// Without this binding, an attacker could take a valid attestation from
/// one ceremony and claim it was for a different capsule.
pub fn report_data(fingerprint: &SeedFingerprint, capsule_hash: &[u8; 32]) -> [u8; REPORT_DATA_LEN] {
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
/// The PSP is a separate secure processor on the AMD chip. It signs the
/// attestation report with the VCEK (Versioned Chip Endorsement Key), an
/// ECDSA-P256 key whose certificate chains to AMD's root CA.
///
/// To verify the report, a third party:
/// 1. Parses the report to extract `chip_id` and `reported_tcb`
/// 2. Fetches the VCEK cert from `https://kdsintf.amd.com/vcek/v1/...`
/// 3. Verifies the ARK → ASK → VCEK certificate chain
/// 4. Verifies the ECDSA-P256 signature on the report
/// 5. Checks the measurement matches the expected `zns-keygen` binary
/// 6. Checks the `report_data` matches
///    `BLAKE2b-512(fingerprint ‖ capsule_hash)`
pub fn request(requested_report_data: &[u8; REPORT_DATA_LEN]) -> Attestation {
    let mut firmware = Firmware::open().expect("failed to open /dev/sev-guest");

    let report_bytes = firmware
        .get_report(None, Some(*requested_report_data), None)
        .expect("failed to request SEV-SNP attestation report");

    // Parse the report to extract the fields the manifest needs.
    let report = AttestationReport::from_bytes(&report_bytes)
        .expect("failed to parse SEV-SNP attestation report");

    let attestation = Attestation {
        report_bytes,
        measurement: report.measurement,
        guest_policy: report.policy.into(),
        image_id: report.image_id,
        family_id: report.family_id,
        report_data: *requested_report_data,
    };

    // Self-verify before returning.
    attestation.verify_report_data();

    attestation
}