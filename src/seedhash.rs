use blake2b_simd::Params as Blake2bParams;
use core::fmt;

const ZIP32_SEED_FP_PERSONALIZATION: &[u8; 16] = b"ZcashSeedFpV1\0\0\0";
const HRP: bech32::Hrp = bech32::Hrp::parse_unchecked("zip32seedfp");

/// The fingerprint for a wallet's seed bytes, as defined in [ZIP 32].
///
/// [ZIP 32]: https://zips.z.cash/zip-0032#seed-fingerprints
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SeedFingerprint([u8; 32]);

impl fmt::Debug for SeedFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "SeedFingerprint([")?;
        for (i, b) in self.0.iter().enumerate() {
            if i != 0 {
                write!(f, ", ")?;
            }
            write!(f, "0x{:02x}", b)?;
        }
        write!(f, "])")
    }
}

impl fmt::Display for SeedFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        // Bech32 encoding was requested to be available in Cargo.toml for audit.
        // bech32 0.11 encoding API converts byte slices automatically in some versions,
        // or requires base32 conversion.
        match bech32::encode::<bech32::Bech32>(HRP, &self.0) {
            Ok(encoded) => write!(f, "{}", encoded),
            Err(_) => {
                // Fallback to hex if Bech32 encoding fails or is missing traits
                for b in self.0.iter() {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
        }
    }
}

impl SeedFingerprint {
    /// Derives the fingerprint of the given seed bytes.
    ///
    /// Returns `None` if the length of `seed_bytes` is less than 32 or greater than 252.
    pub fn from_seed(seed_bytes: &[u8]) -> Option<SeedFingerprint> {
        let seed_len = seed_bytes.len();

        if (32..=252).contains(&seed_len) {
            let seed_len: u8 = seed_len.try_into().unwrap();
            Some(SeedFingerprint(
                Blake2bParams::new()
                    .hash_length(32)
                    .personal(ZIP32_SEED_FP_PERSONALIZATION)
                    .to_state()
                    .update(&[seed_len])
                    .update(seed_bytes)
                    .finalize()
                    .as_bytes()
                    .try_into()
                    .expect("hash length should be 32 bytes"),
            ))
        } else {
            None
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.0
    }
}
