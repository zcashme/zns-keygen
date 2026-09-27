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
//!   4. `verify_vcek_report()` — require a VCEK signature under a pinned AMD
//!      ARK. `Attestation::verify_report_data()` then checks `report_data` and
//!      that the measurement is not zero. Both run before anything is written
//!      to disk.

use blake2b_simd::Params as Blake2bParams;
use sev::certs::snp::ca::Chain as CaChain;
use sev::certs::snp::{Certificate, Chain, Verifiable, builtin};
use sev::firmware::guest::AttestationReport;
#[cfg(target_os = "linux")]
use sev::firmware::guest::Firmware;
use sev::firmware::host::{CertTableEntry, CertType};
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
    /// VM launch measurement. Commits to the measured guest launch state
    /// (48 bytes, hex in manifest). It is not itself a hash of the `zns-keygen` binary.
    pub measurement: [u8; 48],
    /// Guest policy value (u64, hex in manifest).
    pub guest_policy: u64,
    /// Platform TCB at report time (components formatted for the manifest).
    pub tcb_version: String,
    /// The report_data we supplied (kept for the sanity check).
    ///
    /// Unused on non-Linux, where `request` returns a stub report.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub report_data: [u8; REPORT_DATA_LEN],
}

impl Attestation {
    /// Check that the report embeds the `report_data` we requested and that
    /// the launch measurement is not all zeros.
    ///
    /// This is not the AMD signature check. Call `verify_vcek_report` for that.
    ///
    /// Panics on mismatch — this is a one-shot ceremony tool, and a
    /// mismatched attestation is worse than no attestation.
    ///
    /// Called only on Linux, where a real PSP report is available.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
pub fn report_data(
    fingerprint: &SeedFingerprint,
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
/// The PSP is a separate secure processor on the AMD chip. It signs the
/// attestation report with the VCEK (Versioned Chip Endorsement Key), an
/// ECDSA P-384 key whose certificate chains to AMD's root CA. The guest does
/// not receive the VCEK private key. The seed-sealing key is a separate
/// SEV-SNP derived key, not the VCEK.
///
/// On Linux, `request` asks for the extended report, which includes the
/// host-supplied certificate table. Before the report is returned:
/// 1. The report must say it was signed by the VCEK, not the VLEK.
/// 2. The table must contain ARK, ASK, and VCEK certificates. A VLEK is rejected.
/// 3. The ASK must be signed by a pinned AMD ARK (Milan, Genoa, or Turin).
/// 4. That ASK must sign the VCEK.
/// 5. The VCEK's ECDSA P-384 / SHA-384 signature must cover the report.
/// 6. `report_data` must match what we requested, and the measurement must
///    not be all zeros.
///
/// The AMD PSP records the launch measurement. A verifier outside the guest
/// compares it to the built image.
pub fn request(requested_report_data: &[u8; REPORT_DATA_LEN]) -> Attestation {
    #[cfg(not(target_os = "linux"))]
    {
        Attestation {
            report_bytes: Vec::new(),
            measurement: [0u8; 48],
            guest_policy: 0,
            tcb_version: "dev".into(),
            report_data: *requested_report_data,
        }
    }
    #[cfg(target_os = "linux")]
    {
        let mut firmware = Firmware::open().expect("failed to open /dev/sev-guest");

        let (report_bytes, certs) = firmware
            .get_ext_report(None, Some(*requested_report_data), None)
            .expect("failed to request SEV-SNP extended attestation report");
        let certs = certs.expect("FATAL: extended attestation report has no certificate table");

        // Parse the report to extract the fields the manifest needs.
        let report = AttestationReport::from_bytes(&report_bytes)
            .expect("failed to parse SEV-SNP attestation report");
        verify_vcek_report(&report, &certs).expect("FATAL: attestation signature verification");

        let tcb = report.current_tcb;
        let attestation = Attestation {
            report_bytes,
            measurement: report.measurement,
            guest_policy: report.policy.into(),
            tcb_version: format!(
                "bootloader={} tee={} snp={} microcode={}",
                tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
            ),
            report_data: *requested_report_data,
        };

        // report_data and measurement, after the signature check.
        attestation.verify_report_data();

        attestation
    }
}

/// Verify that `report` was signed by a VCEK whose ASK chains to a pinned AMD ARK.
///
/// The certificate table is the one returned with the extended attestation
/// report. Its ARK is not trusted by itself: the ASK must verify under the
/// Milan, Genoa, or Turin ARK built into the `sev` crate.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn verify_vcek_report(
    report: &AttestationReport,
    certs: &[CertTableEntry],
) -> Result<(), String> {
    if report.key_info.mask_chip_key() {
        return Err("attestation report signature is masked".into());
    }
    if report.key_info.signing_key() != 0 {
        return Err("attestation report was not signed by the VCEK".into());
    }
    if certs.iter().any(|entry| entry.cert_type == CertType::VLEK) {
        return Err("VLEK certificates are not accepted".into());
    }

    let ask = one_cert(certs, CertType::ASK)?;
    let vcek = one_cert(certs, CertType::VCEK)?;
    // Present so the extended report actually carried a root, then ignored
    // in favor of the pinned AMD copy.
    let _table_ark = one_cert(certs, CertType::ARK)?;

    let chain = chain_under_pinned_ark(ask, vcek)?;
    (&chain, report)
        .verify()
        .map_err(|e| format!("VCEK signature verification failed: {e}"))?;
    Ok(())
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn one_cert(certs: &[CertTableEntry], kind: CertType) -> Result<Certificate, String> {
    let mut found = None;
    for entry in certs {
        if entry.cert_type != kind {
            continue;
        }
        if found.is_some() {
            return Err(format!("more than one {kind:?} certificate"));
        }
        found = Some(
            Certificate::from_der(&entry.data)
                .map_err(|e| format!("invalid {kind:?} certificate: {e}"))?,
        );
    }
    found.ok_or_else(|| format!("{kind:?} certificate missing"))
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn chain_under_pinned_ark(ask: Certificate, vcek: Certificate) -> Result<Chain, String> {
    let roots = [
        builtin::milan::ark(),
        builtin::genoa::ark(),
        builtin::turin::ark(),
    ];
    for root in roots {
        let ark = root.map_err(|e| format!("pinned AMD ARK: {e}"))?;
        let chain = Chain {
            ca: CaChain {
                ark,
                ask: ask.clone(),
            },
            vek: vcek.clone(),
        };
        if chain.verify().is_ok() {
            return Ok(chain);
        }
    }
    Err("ASK is not signed by a pinned AMD ARK (Milan, Genoa, or Turin)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    const MILAN_VCEK_DER: &[u8] = include_bytes!("testdata/vcek_milan.der");
    const MILAN_REPORT_HEX: &[u8] = include_bytes!("testdata/report_milan.hex");

    fn milan_certs() -> Vec<CertTableEntry> {
        let ark = builtin::milan::ark().unwrap().to_der().unwrap();
        let ask = builtin::milan::ask().unwrap().to_der().unwrap();
        vec![
            CertTableEntry::new(CertType::ARK, ark),
            CertTableEntry::new(CertType::ASK, ask),
            CertTableEntry::new(CertType::VCEK, MILAN_VCEK_DER.to_vec()),
        ]
    }

    fn milan_report() -> AttestationReport {
        let bytes = hex::decode(MILAN_REPORT_HEX).unwrap();
        AttestationReport::from_bytes(&bytes).unwrap()
    }

    #[test]
    fn milan_vcek_report_verifies() {
        verify_vcek_report(&milan_report(), &milan_certs()).unwrap();
    }

    #[test]
    fn modified_report_fails_vcek_signature() {
        let mut bytes = hex::decode(MILAN_REPORT_HEX).unwrap();
        bytes[21] ^= 0x80;
        let report = AttestationReport::from_bytes(&bytes).unwrap();
        assert!(verify_vcek_report(&report, &milan_certs()).is_err());
    }

    #[test]
    fn vlek_certificate_is_rejected() {
        let mut certs = milan_certs();
        certs.push(CertTableEntry::new(CertType::VLEK, MILAN_VCEK_DER.to_vec()));
        assert!(verify_vcek_report(&milan_report(), &certs).is_err());
    }

    #[test]
    fn missing_vcek_is_rejected() {
        let certs: Vec<_> = milan_certs()
            .into_iter()
            .filter(|entry| entry.cert_type != CertType::VCEK)
            .collect();
        assert!(verify_vcek_report(&milan_report(), &certs).is_err());
    }
}
