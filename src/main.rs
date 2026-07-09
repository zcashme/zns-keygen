mod fingerprint;

use blake2b_simd::Params as Blake2bParams;
use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
use sev::firmware::guest::{DerivedKey, Firmware, GuestFieldSelect};
use std::fs::{self, File, OpenOptions};
#[cfg(target_arch = "x86_64")]
use std::hint::spin_loop;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;
use zeroize::Zeroizing;

use fingerprint::SeedFingerprint;

const CAPSULE_FILE: &str = "zns_seed.capsule";
const MANIFEST_FILE: &str = "zns_custody_manifest.toml";
const MINT_CONFIG_FILE: &str = "zns_mint.conf";

const NETWORK: &str = "mainnet";
const ISSUER_EPOCH: u8 = 1;
const TREASURY_ACCOUNT: u32 = 0;
const REGISTRY_ACCOUNT: u32 = 1;

const SEED_LEN: usize = 32;
const FINGERPRINT_LEN: usize = 32;
const SEALING_KEY_LEN: usize = 32;
const NONCE_LEN: usize = 24;
const TAG_LEN: usize = 16;
const CIPHERTEXT_LEN: usize = SEED_LEN + TAG_LEN;

const CAPSULE_MAGIC: &[u8; 8] = b"ZNSCAPS1";
const CAPSULE_CONTEXT: &[u8] = b"ZcashNames mainnet issuer epoch 1; treasury=0; registry=1; sealing=amd-sev-snp-vmrk-instance-bound";

type ZnsResult<T> = Result<T, String>;

fn main() {
    if let Err(err) = run() {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

fn run() -> ZnsResult<()> {
    let capsule_path = Path::new(CAPSULE_FILE);
    let manifest_path = Path::new(MANIFEST_FILE);
    let mint_config_path = Path::new(MINT_CONFIG_FILE);

    ensure_absent(capsule_path)?;
    ensure_absent(manifest_path)?;
    ensure_absent(mint_config_path)?;

    let seed = Seed::generate()?;
    let fingerprint = seed.fingerprint();
    let sealing_key = derive_instance_bound_sev_sealing_key()?;
    let capsule = seal_seed(&seed, &sealing_key, fingerprint)?;
    let capsule_bytes = postcard::to_allocvec(&capsule)
        .map_err(|err| format!("failed to serialize capsule: {err}"))?;
    let capsule_hash = blake2b256(&capsule_bytes);
    let manifest = custody_manifest(fingerprint, &capsule_hash);
    let mint_config = mint_config_toml(fingerprint);

    write_new_file(capsule_path, &capsule_bytes)?;
    write_new_file(manifest_path, manifest.as_bytes())?;
    write_new_file(mint_config_path, mint_config.as_bytes())?;

    println!("ZNS genesis capsule created");
    println!("capsule: {}", capsule_path.display());
    println!("manifest: {}", manifest_path.display());
    println!("mint_config: {}", mint_config_path.display());
    println!("seed_fingerprint: {fingerprint}");
    println!("capsule_hash_blake2b256: {}", hex::encode(capsule_hash));
    println!("migration: none");
    println!("signer_socket: none");

    Ok(())
}

struct Seed(Zeroizing<[u8; SEED_LEN]>);

impl Seed {
    fn generate() -> ZnsResult<Seed> {
        let mut seed = Seed(Zeroizing::new([0u8; SEED_LEN]));
        fill_entropy(&mut seed.0[..])?;
        Ok(seed)
    }

    fn expose<R>(&self, f: impl FnOnce(&[u8; SEED_LEN]) -> R) -> R {
        f(&self.0)
    }

    fn fingerprint(&self) -> SeedFingerprint {
        self.expose(|seed_bytes| {
            SeedFingerprint::from_seed(seed_bytes)
                .expect("32-byte seed is within ZIP 32 range")
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
) -> ZnsResult<SeedCapsule> {
    let cipher = XChaCha20Poly1305::new_from_slice(sealing_key.as_bytes())
        .map_err(|_| "invalid sealing key length".to_string())?;

    let mut nonce = [0u8; NONCE_LEN];
    fill_entropy(&mut nonce)?;
    let aad = capsule_aad(fingerprint);
    let nonce_ref =
        <&XNonce>::try_from(nonce.as_slice()).map_err(|_| "invalid nonce length".to_string())?;

    let ciphertext = seed.expose(|seed_bytes| {
        cipher.encrypt(
            nonce_ref,
            Payload {
                msg: seed_bytes,
                aad: &aad,
            },
        )
    });
    let ciphertext = ciphertext.map_err(|_| "failed to encrypt seed".to_string())?;

    if ciphertext.len() != CIPHERTEXT_LEN {
        return Err(format!(
            "capsule ciphertext length mismatch: expected {CIPHERTEXT_LEN}, got {}",
            ciphertext.len()
        ));
    }

    Ok(SeedCapsule {
        magic: *CAPSULE_MAGIC,
        fingerprint: fingerprint.to_bytes(),
        nonce: nonce.to_vec(),
        ciphertext,
    })
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
    issuer_epoch: u8,
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
    migration: &'static str,
    signer_socket: &'static str,
}

fn custody_manifest(fingerprint: SeedFingerprint, capsule_hash: &[u8; 32]) -> String {
    let manifest = CustodyManifest {
        manifest_version: 1,
        network: NETWORK,
        issuer_epoch: ISSUER_EPOCH,
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
        migration: "none",
        signer_socket: "none",
    };
    toml::to_string(&manifest).unwrap_or_else(|err| {
        panic!("failed to serialize manifest: {err}")
    })
}

#[derive(serde::Serialize)]
struct MintConfig {
    network: &'static str,
    issuer_epoch: u8,
    expected_seed_fingerprint: String,
}

fn mint_config_toml(fingerprint: SeedFingerprint) -> String {
    let config = MintConfig {
        network: NETWORK,
        issuer_epoch: ISSUER_EPOCH,
        expected_seed_fingerprint: fingerprint.to_string(),
    };
    toml::to_string(&config).unwrap_or_else(|err| {
        panic!("failed to serialize mint config: {err}")
    })
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

#[cfg(target_arch = "x86_64")]
fn fill_entropy(dest: &mut [u8]) -> ZnsResult<()> {
    if dest.is_empty() {
        return Ok(());
    }

    let mut offset = 0;
    while offset < dest.len() {
        let mut value = 0u64;
        let mut success = false;

        for _ in 0..10_000 {
            unsafe {
                if core::arch::x86_64::_rdseed64_step(&mut value) == 1 {
                    success = true;
                    break;
                }
            }
            spin_loop();
        }

        if !success {
            return Err("RDSEED hardware entropy was unavailable".to_string());
        }

        let bytes = value.to_ne_bytes();
        let take = std::cmp::min(bytes.len(), dest.len() - offset);
        dest[offset..offset + take].copy_from_slice(&bytes[..take]);
        value.zeroize();
        offset += take;
    }

    Ok(())
}

#[cfg(not(target_arch = "x86_64"))]
fn fill_entropy(_dest: &mut [u8]) -> ZnsResult<()> {
    Err("zns-keygen requires x86_64 RDSEED entropy".to_string())
}

#[cfg(all(target_arch = "x86_64", target_os = "linux"))]
fn derive_instance_bound_sev_sealing_key() -> ZnsResult<SealingKey> {
    let mut firmware =
        Firmware::open().map_err(|err| format!("failed to open /dev/sev-guest: {err}"))?;
    let mut guest_fields = GuestFieldSelect::default();
    guest_fields.set_guest_policy(true);
    guest_fields.set_image_id(true);
    guest_fields.set_family_id(true);
    guest_fields.set_measurement(true);

    let request = DerivedKey::new(true, guest_fields, 0, 0, 0, None);
    let mut key = firmware.get_derived_key(None, request).map_err(|err| {
        format!("failed to derive instance-bound SEV-SNP VMRK sealing key: {err}")
    })?;

    let sealing_key = SealingKey(Zeroizing::new(key));
    key.zeroize();
    Ok(sealing_key)
}

#[cfg(not(all(target_arch = "x86_64", target_os = "linux")))]
fn derive_instance_bound_sev_sealing_key() -> ZnsResult<SealingKey> {
    Err("SEV-SNP VMRK sealing requires Linux x86_64 with /dev/sev-guest".to_string())
}

fn ensure_absent(path: &Path) -> ZnsResult<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => Err(format!(
            "{} already exists; refusing to create another genesis capsule",
            path.display()
        )),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("failed to inspect {}: {err}", path.display())),
    }
}

fn write_new_file(path: &Path, bytes: &[u8]) -> ZnsResult<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|err| format!("failed to create file {}: {err}", path.display()))?;

    file.write_all(bytes)
        .map_err(|err| format!("failed to write file {}: {err}", path.display()))?;
    file.sync_all()
        .map_err(|err| format!("failed to sync file {}: {err}", path.display()))?;

    sync_parent(path)?;
    Ok(())
}

fn sync_parent(path: &Path) -> ZnsResult<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(|err| {
            format!(
                "failed to sync parent directory {}: {err}",
                parent.display()
            )
        })
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
        let manifest = custody_manifest(fp, &[0u8; 32]);
        assert!(manifest.contains("seed_fingerprint"));
        assert!(manifest.contains("mainnet"));
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
