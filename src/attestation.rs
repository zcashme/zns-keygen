//! SEV-SNP attestation: request, parse, and self-verify.
//!
//! This module isolates all interaction with the AMD PSP (Platform Security
//! Processor) into one place so that `main.rs` stays a linear ceremony script
//! and the attestation logic is independently testable and auditable.
//!
//! Flow:
//!   1. `report_data()` — compute the 64-byte blob that binds the attestation
//!      to this specific capsule (BLAKE2b-512 of fingerprint ‖ capsule_hash).
//!   2. `request()` — call the PSP via `/dev/sev-guest` for a normal SNP
//!      report. That report is the VCEK-signed evidence.
//!   3. Fetch the public VCEK and ASK from AMD's Key Distribution Service.
//!      The ARK in that response is not the trust anchor.
//!   4. `verify_vcek_report()` — require the ASK to chain to a pinned AMD
//!      ARK, and the VCEK signature to cover the report.
//!      `Attestation::verify_report_data()` then checks `report_data` and
//!      that the measurement is not zero. Both run before the attestation
//!      report is written to disk. `stored()` repeats the KDS fetch and the
//!      signature check before a report already on disk is used.

use blake2b_simd::Params as Blake2bParams;
use sev::Generation;
use sev::certs::snp::ca::Chain as CaChain;
use sev::certs::snp::{Certificate, Chain, Verifiable, builtin};
use sev::firmware::guest::AttestationReport;
#[cfg(target_os = "linux")]
use sev::firmware::guest::Firmware;
use sev::firmware::host::TcbVersion;
use sev::parser::ByteParser;
use std::io::Read;

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
/// On Linux, `request` asks the PSP for a normal SNP report, then fetches the
/// VCEK and the ASK/ARK bundle from AMD KDS. Before the report is returned:
/// 1. The report must say it was signed by the VCEK, not the VLEK.
/// 2. The chip id must be present so the VCEK can be fetched.
/// 3. The ASK from KDS must be signed by a pinned AMD ARK (Milan, Genoa, or Turin).
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
        let report_bytes = firmware
            .get_report(None, Some(*requested_report_data), None)
            .expect("failed to request SEV-SNP attestation report");
        let report = AttestationReport::from_bytes(&report_bytes)
            .expect("failed to parse SEV-SNP attestation report");
        let (ask, vcek) =
            fetch_endorsement(&report).unwrap_or_else(|error| panic!("FATAL: {error}"));
        verify_vcek_report(&report, &ask, &vcek)
            .expect("FATAL: attestation signature verification");

        let attestation = attestation_from_report(report_bytes, *requested_report_data);
        attestation.verify_report_data();
        attestation
    }
}

/// Load an attestation report and verify it again before its fields are used.
///
/// On Linux this parses the stored report, fetches the VCEK and ASK from AMD
/// KDS, and checks the signature, `report_data`, and measurement. It does not
/// call the PSP again. The file lives on host-backed storage, so an earlier
/// check is not reused.
///
/// On other platforms the ceremony uses the same development stub as `request`.
pub fn stored(report_bytes: Vec<u8>, expected_report_data: &[u8; REPORT_DATA_LEN]) -> Attestation {
    #[cfg(target_os = "linux")]
    {
        let report = AttestationReport::from_bytes(&report_bytes)
            .expect("failed to parse stored SEV-SNP attestation report");
        let (ask, vcek) =
            fetch_endorsement(&report).unwrap_or_else(|error| panic!("FATAL: {error}"));
        verify_vcek_report(&report, &ask, &vcek)
            .expect("FATAL: stored attestation signature verification");

        let attestation = attestation_from_report(report_bytes, *expected_report_data);
        attestation.verify_report_data();
        attestation
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = report_bytes;
        Attestation {
            report_bytes: Vec::new(),
            measurement: [0u8; 48],
            guest_policy: 0,
            tcb_version: "dev".into(),
            report_data: *expected_report_data,
        }
    }
}

#[cfg(target_os = "linux")]
fn attestation_from_report(
    report_bytes: Vec<u8>,
    report_data: [u8; REPORT_DATA_LEN],
) -> Attestation {
    let report = AttestationReport::from_bytes(&report_bytes)
        .expect("failed to parse SEV-SNP attestation report");
    let tcb = report.current_tcb;
    Attestation {
        report_bytes,
        measurement: report.measurement,
        guest_policy: report.policy.into(),
        tcb_version: format!(
            "bootloader={} tee={} snp={} microcode={}",
            tcb.bootloader, tcb.tee, tcb.snp, tcb.microcode
        ),
        report_data,
    }
}

/// Verify that `report` was signed by `vcek`, and that `ask` chains to a pinned AMD ARK.
///
/// `ask` and `vcek` are public certificates obtained from AMD KDS. The ARK
/// served beside the ASK is not trusted by itself: the ASK must verify under
/// the Milan, Genoa, or Turin ARK built into the `sev` crate.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub fn verify_vcek_report(
    report: &AttestationReport,
    ask: &Certificate,
    vcek: &Certificate,
) -> Result<(), String> {
    vcek_signing_key(report)?;
    let chain = chain_under_pinned_ark(ask.clone(), vcek.clone())?;
    (&chain, report)
        .verify()
        .map_err(|e| format!("VCEK signature verification failed: {e}"))?;
    Ok(())
}

fn vcek_signing_key(report: &AttestationReport) -> Result<(), String> {
    if report.key_info.mask_chip_key() {
        return Err("attestation report signature is masked".into());
    }
    if report.key_info.signing_key() != 0 {
        return Err("attestation report was not signed by the VCEK".into());
    }
    if report.chip_id.iter().all(|byte| *byte == 0) {
        return Err("attestation report chip id is zero".into());
    }
    Ok(())
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

const KDS_ORIGIN: &str = "https://kdsintf.amd.com/vcek/v1";

/// AMD KDS product name for the CPUID family and model in an SNP report.
///
/// Siena and Bergamo use the Genoa key hierarchy. Venice has no pinned ARK here.
fn kds_product_name(family: u8, model: u8) -> Result<&'static str, String> {
    match Generation::try_from((family, model)) {
        Ok(Generation::Milan) => Ok("Milan"),
        Ok(Generation::Genoa) => Ok("Genoa"),
        Ok(Generation::Turin) => Ok("Turin"),
        Ok(generation) => Err(format!("no pinned AMD ARK for {}", generation.titlecase())),
        Err(error) => Err(format!(
            "attestation CPU family {family:#x} model {model:#x}: {error}"
        )),
    }
}

fn kds_product(report: &AttestationReport) -> Result<&'static str, String> {
    let family = report
        .cpuid_fam_id
        .ok_or("attestation report has no CPU family")?;
    let model = report
        .cpuid_mod_id
        .ok_or("attestation report has no CPU model")?;
    kds_product_name(family, model)
}

/// VCEK URL for the reported TCB. That is the TCB the VCEK was derived from.
fn vcek_url(product: &str, chip_id: &[u8; 64], tcb: &TcbVersion) -> String {
    let mut url = format!(
        "{KDS_ORIGIN}/{product}/{}?blSPL={}&teeSPL={}&snpSPL={}&ucodeSPL={}",
        hex::encode(chip_id),
        tcb.bootloader,
        tcb.tee,
        tcb.snp,
        tcb.microcode
    );
    if let Some(fmc) = tcb.fmc {
        url.push_str(&format!("&fmcSPL={fmc}"));
    }
    url
}

fn cert_chain_url(product: &str) -> String {
    format!("{KDS_ORIGIN}/{product}/cert_chain")
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn fetch_endorsement(report: &AttestationReport) -> Result<(Certificate, Certificate), String> {
    vcek_signing_key(report)?;
    let product = kds_product(report)?;
    tracing::info!(product, "fetching VCEK and ASK from AMD KDS");

    let vcek_bytes = https_get(&vcek_url(product, &report.chip_id, &report.reported_tcb))?;
    let vcek = Certificate::from_der(&vcek_bytes)
        .or_else(|_| Certificate::from_pem(&vcek_bytes))
        .map_err(|error| format!("AMD KDS VCEK: {error}"))?;

    let chain_bytes = https_get(&cert_chain_url(product))?;
    let chain_certs = pem_certificates(&chain_bytes)?;
    let ask = ask_from_kds_chain(&chain_certs, &vcek)?;
    Ok((ask, vcek))
}

/// The cert-chain bundle holds the ASK and the KDS ARK. Return the ASK that
/// chains to a pinned ARK and signs this VCEK.
fn ask_from_kds_chain(
    chain_certs: &[Certificate],
    vcek: &Certificate,
) -> Result<Certificate, String> {
    let mut chain_error = String::from("AMD KDS cert chain contained no ASK");
    for ask in chain_certs {
        match chain_under_pinned_ark(ask.clone(), vcek.clone()) {
            Ok(_) => return Ok(ask.clone()),
            Err(error) => chain_error = error,
        }
    }
    Err(chain_error)
}

fn pem_certificates(bundle: &[u8]) -> Result<Vec<Certificate>, String> {
    let text =
        std::str::from_utf8(bundle).map_err(|_| "AMD KDS cert chain is not UTF-8".to_string())?;
    let mut certificates = Vec::new();
    for block in text.split("-----END CERTIFICATE-----") {
        let Some(start) = block.find("-----BEGIN CERTIFICATE-----") else {
            continue;
        };
        let pem = format!("{}-----END CERTIFICATE-----\n", &block[start..]);
        let certificate = Certificate::from_pem(pem.as_bytes())
            .map_err(|error| format!("AMD KDS certificate: {error}"))?;
        certificates.push(certificate);
    }
    if certificates.is_empty() {
        return Err("AMD KDS cert chain contained no certificates".into());
    }
    Ok(certificates)
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn https_get(url: &str) -> Result<Vec<u8>, String> {
    let response = ureq::get(url)
        .timeout(std::time::Duration::from_secs(30))
        .call()
        .map_err(|error| format!("AMD KDS request failed: {error}"))?;
    let mut body = Vec::new();
    response
        .into_reader()
        .take(1024 * 1024)
        .read_to_end(&mut body)
        .map_err(|error| format!("AMD KDS response: {error}"))?;
    if body.is_empty() {
        return Err("AMD KDS response was empty".into());
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MILAN_VCEK_DER: &[u8] = include_bytes!("testdata/vcek_milan.der");
    const MILAN_REPORT_HEX: &[u8] = include_bytes!("testdata/report_milan.hex");

    fn milan_report() -> AttestationReport {
        let bytes = hex::decode(MILAN_REPORT_HEX).unwrap();
        AttestationReport::from_bytes(&bytes).unwrap()
    }

    fn milan_ask_and_vcek() -> (Certificate, Certificate) {
        let ask = builtin::milan::ask().unwrap();
        let vcek = Certificate::from_der(MILAN_VCEK_DER).unwrap();
        (ask, vcek)
    }

    #[test]
    fn milan_vcek_report_verifies() {
        let (ask, vcek) = milan_ask_and_vcek();
        verify_vcek_report(&milan_report(), &ask, &vcek).unwrap();
    }

    #[test]
    fn modified_report_fails_vcek_signature() {
        let (ask, vcek) = milan_ask_and_vcek();
        let mut bytes = hex::decode(MILAN_REPORT_HEX).unwrap();
        bytes[21] ^= 0x80;
        let report = AttestationReport::from_bytes(&bytes).unwrap();
        assert!(verify_vcek_report(&report, &ask, &vcek).is_err());
    }

    #[test]
    fn vlek_signing_key_is_rejected() {
        let (ask, vcek) = milan_ask_and_vcek();
        let mut report = milan_report();
        report.key_info = sev::firmware::guest::KeyInfo::from(1 << 2);
        let error = verify_vcek_report(&report, &ask, &vcek).unwrap_err();
        assert!(error.contains("VCEK"), "{error}");
    }

    #[test]
    fn masked_signature_is_rejected() {
        let (ask, vcek) = milan_ask_and_vcek();
        let mut report = milan_report();
        report.key_info = sev::firmware::guest::KeyInfo::from(1 << 1);
        let error = verify_vcek_report(&report, &ask, &vcek).unwrap_err();
        assert!(error.contains("masked"), "{error}");
    }

    #[test]
    fn ask_from_another_generation_is_rejected() {
        let vcek = Certificate::from_der(MILAN_VCEK_DER).unwrap();
        let ask = builtin::turin::ask().unwrap();
        assert!(verify_vcek_report(&milan_report(), &ask, &vcek).is_err());
    }

    #[test]
    fn kds_chain_selects_the_ask_when_the_ark_comes_first() {
        let (ask, vcek) = milan_ask_and_vcek();
        let ark = builtin::milan::ark().unwrap();
        let bundle = [ark.to_pem().unwrap(), ask.to_pem().unwrap()].concat();
        let certificates = pem_certificates(&bundle).unwrap();
        assert_eq!(certificates.len(), 2);
        let selected = ask_from_kds_chain(&certificates, &vcek).unwrap();
        verify_vcek_report(&milan_report(), &selected, &vcek).unwrap();
    }

    #[test]
    fn kds_product_names_match_the_pinned_roots() {
        assert_eq!(kds_product_name(0x19, 0x01).unwrap(), "Milan");
        assert_eq!(kds_product_name(0x19, 0x11).unwrap(), "Genoa");
        // EPYC 8024P (Siena) is in the Genoa key hierarchy.
        assert_eq!(kds_product_name(0x19, 0xA0).unwrap(), "Genoa");
        assert_eq!(kds_product_name(0x1A, 0x00).unwrap(), "Turin");
        assert!(kds_product_name(0x1A, 0x50).is_err());
    }

    #[test]
    fn vcek_url_uses_the_reported_tcb_and_chip_id() {
        let chip_id = [0xAB; 64];
        let tcb = TcbVersion {
            fmc: None,
            bootloader: 1,
            tee: 2,
            snp: 3,
            microcode: 4,
        };
        let url = vcek_url("Genoa", &chip_id, &tcb);
        assert_eq!(
            url,
            format!(
                "https://kdsintf.amd.com/vcek/v1/Genoa/{}?blSPL=1&teeSPL=2&snpSPL=3&ucodeSPL=4",
                hex::encode(chip_id)
            )
        );
        assert_eq!(
            cert_chain_url("Genoa"),
            "https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain"
        );

        let turin = TcbVersion {
            fmc: Some(7),
            ..tcb
        };
        assert!(vcek_url("Turin", &chip_id, &turin).ends_with("&fmcSPL=7"));
    }
}
