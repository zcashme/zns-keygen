use std::fs::File;
use std::io::Read;
use std::path::Path;
use zeroize::Zeroize;

use crate::attestation::{SEALED_SEED_LEN, generate_rdseed_bytes};
use crate::seedhash::SeedFingerprint;

const KEY_FILE_MAGIC: &[u8; 8] = b"ZNSKEYS1";
const KEY_FILE_VERSION: u32 = 1;
const KEY_FILE_LEN: usize = 8 + 4 + 32 + SEALED_SEED_LEN;

pub struct PlainSeed([u8; 32]);

impl PlainSeed {
    pub fn generate() -> PlainSeed {
        let mut seed = [0u8; 32];
        generate_rdseed_bytes(&mut seed);
        PlainSeed(seed)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> PlainSeed {
        PlainSeed(bytes)
    }

    pub fn fingerprint(&self) -> SeedFingerprint {
        SeedFingerprint::from_seed(&self.0).expect("seed is 32 bytes")
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Drop for PlainSeed {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[derive(Clone, Copy)]
pub struct SealedSeed([u8; SEALED_SEED_LEN]);

impl SealedSeed {
    pub fn from_bytes(bytes: [u8; SEALED_SEED_LEN]) -> SealedSeed {
        SealedSeed(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SEALED_SEED_LEN] {
        &self.0
    }
}

#[derive(Clone, Copy)]
pub struct KeyFile {
    fingerprint: SeedFingerprint,
    sealed_seed: SealedSeed,
}

impl KeyFile {
    pub fn new(fingerprint: SeedFingerprint, sealed_seed: SealedSeed) -> KeyFile {
        KeyFile {
            fingerprint,
            sealed_seed,
        }
    }

    pub fn fingerprint(&self) -> SeedFingerprint {
        self.fingerprint
    }

    pub fn sealed_seed(&self) -> &SealedSeed {
        &self.sealed_seed
    }

    pub fn encode(&self) -> [u8; KEY_FILE_LEN] {
        let mut out = [0u8; KEY_FILE_LEN];
        out[0..8].copy_from_slice(KEY_FILE_MAGIC);
        out[8..12].copy_from_slice(&KEY_FILE_VERSION.to_le_bytes());
        out[12..44].copy_from_slice(&self.fingerprint.to_bytes());
        out[44..KEY_FILE_LEN].copy_from_slice(self.sealed_seed.as_bytes());
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<KeyFile, String> {
        if bytes.len() != KEY_FILE_LEN {
            return Err(format!(
                "invalid key file length: expected {KEY_FILE_LEN}, got {}",
                bytes.len()
            ));
        }
        if &bytes[0..8] != KEY_FILE_MAGIC {
            return Err("invalid key file magic".to_string());
        }

        let version = u32::from_le_bytes(bytes[8..12].try_into().expect("version length fixed"));
        if version != KEY_FILE_VERSION {
            return Err(format!("unsupported key file version: {version}"));
        }

        let fingerprint = SeedFingerprint::from_bytes(
            bytes[12..44].try_into().expect("fingerprint length fixed"),
        );
        let sealed_seed = SealedSeed::from_bytes(
            bytes[44..KEY_FILE_LEN]
                .try_into()
                .expect("sealed seed length fixed"),
        );

        Ok(KeyFile::new(fingerprint, sealed_seed))
    }

    pub fn read(path: &Path) -> Result<KeyFile, String> {
        let mut bytes = Vec::new();
        File::open(path)
            .map_err(|err| format!("failed to open key file {}: {err}", path.display()))?
            .read_to_end(&mut bytes)
            .map_err(|err| format!("failed to read key file {}: {err}", path.display()))?;
        KeyFile::decode(&bytes)
    }
}
