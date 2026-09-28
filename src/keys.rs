//! Key derivation from seed.

use transparent::keys::{IncomingViewingKey, NonHardenedChildIndex, TransparentKeyScope};
use zcash_protocol::consensus::{NetworkConstants, Parameters};

use crate::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use zip32::AccountId;

/// Public Treasury data needed to display the funding address and later
/// identify the funding UTXO. Holds no spending-key material.
pub struct TreasuryFundingInfo {
    address: transparent::address::TransparentAddress,
    pubkey: secp256k1::PublicKey,
}

impl TreasuryFundingInfo {
    /// Derive only the Treasury transparent address and external pubkey.
    ///
    /// The account private key is dropped before this returns. Callers must
    /// not retain spending-key material across the funding wait.
    pub fn derive<P: Parameters>(network: &P, seed: &[u8; 32]) -> Self {
        let (address, pubkey) = {
            let privkey = treasury_account_key(network, seed);
            let account_pub = privkey.to_account_pubkey();
            let external_ivk = account_pub
                .derive_external_ivk()
                .expect("FATAL: Treasury IVK");
            let address = external_ivk.default_address().0;
            let pubkey = account_pub
                .derive_address_pubkey(
                    TransparentKeyScope::EXTERNAL,
                    NonHardenedChildIndex::from_index(0).unwrap(),
                )
                .expect("FATAL: pubkey derivation");
            (address, pubkey)
        };
        Self { address, pubkey }
    }

    pub fn address(&self) -> &transparent::address::TransparentAddress {
        &self.address
    }

    pub fn pubkey(&self) -> secp256k1::PublicKey {
        self.pubkey
    }

    /// Restore the public funding record from a persisted ceremony state.
    ///
    /// The address and pubkey are public. This does not derive or unseal a seed.
    pub(crate) fn from_public(
        address: transparent::address::TransparentAddress,
        pubkey: secp256k1::PublicKey,
    ) -> Self {
        Self { address, pubkey }
    }
}

/// Key material the anchor transaction actually uses.
///
/// The only transparent private key here is the external index-0 child. The
/// Treasury account private key is dropped as soon as that child is derived.
/// Sapling is not derived.
pub struct AnchorMaterial {
    pub treasury_signing_key: secp256k1::SecretKey,
    pub treasury_orchard_fvk: orchard::keys::FullViewingKey,
    pub registry_orchard_fvk: orchard::keys::FullViewingKey,
}

impl Drop for AnchorMaterial {
    fn drop(&mut self) {
        self.treasury_signing_key.non_secure_erase();
    }
}

impl AnchorMaterial {
    /// Derive the Treasury signing key and both Orchard full viewing keys.
    ///
    /// Each Orchard spending key exists only long enough to produce its full
    /// viewing key.
    pub fn derive<P: Parameters>(network: &P, seed: &[u8; 32]) -> Self {
        let treasury_signing_key = {
            let account = treasury_account_key(network, seed);
            account
                .derive_secret_key(
                    TransparentKeyScope::EXTERNAL,
                    NonHardenedChildIndex::from_index(0).expect("index 0"),
                )
                .expect("FATAL: transparent key")
        };
        Self {
            treasury_signing_key,
            treasury_orchard_fvk: orchard_fvk(network, seed, TREASURY_ACCOUNT),
            registry_orchard_fvk: orchard_fvk(network, seed, REGISTRY_ACCOUNT),
        }
    }
}

fn treasury_account_key<P: Parameters>(
    network: &P,
    seed: &[u8; 32],
) -> transparent::keys::AccountPrivKey {
    transparent::keys::AccountPrivKey::from_seed(
        network,
        seed,
        AccountId::try_from(TREASURY_ACCOUNT).unwrap(),
    )
    .expect("FATAL: Treasury key derivation")
}

fn orchard_fvk<P: Parameters>(
    network: &P,
    seed: &[u8],
    account: u32,
) -> orchard::keys::FullViewingKey {
    let sk = orchard::keys::SpendingKey::from_zip32_seed(
        seed,
        network.coin_type(),
        AccountId::try_from(account).unwrap(),
    )
    .expect("FATAL: Orchard key derivation");
    (&sk).into()
}

#[cfg(test)]
mod tests {
    use zcash_protocol::consensus::MAIN_NETWORK;

    use super::*;

    fn reference_seed() -> [u8; 32] {
        [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ]
    }

    #[test]
    fn funding_info_matches_treasury_account_key() {
        let seed = reference_seed();
        let funding = TreasuryFundingInfo::derive(&MAIN_NETWORK, &seed);
        let account = treasury_account_key(&MAIN_NETWORK, &seed);
        let account_pub = account.to_account_pubkey();
        let address = account_pub
            .derive_external_ivk()
            .expect("Treasury IVK")
            .default_address()
            .0;
        let pubkey = account_pub
            .derive_address_pubkey(
                TransparentKeyScope::EXTERNAL,
                NonHardenedChildIndex::from_index(0).unwrap(),
            )
            .expect("pubkey");
        assert_eq!(funding.address(), &address);
        assert_eq!(funding.pubkey(), pubkey);
    }

    #[test]
    fn anchor_material_matches_unified_spending_key() {
        use zcash_keys::keys::UnifiedSpendingKey;

        let seed = reference_seed();
        let material = AnchorMaterial::derive(&MAIN_NETWORK, &seed);
        let treasury = UnifiedSpendingKey::from_seed(
            &MAIN_NETWORK,
            &seed,
            AccountId::try_from(TREASURY_ACCOUNT).unwrap(),
        )
        .expect("Treasury USK");
        let registry = UnifiedSpendingKey::from_seed(
            &MAIN_NETWORK,
            &seed,
            AccountId::try_from(REGISTRY_ACCOUNT).unwrap(),
        )
        .expect("Registry USK");

        let usk_signing_key = treasury
            .transparent()
            .derive_secret_key(
                TransparentKeyScope::EXTERNAL,
                NonHardenedChildIndex::from_index(0).unwrap(),
            )
            .expect("USK child key");
        assert!(material.treasury_signing_key == usk_signing_key);

        let funding = TreasuryFundingInfo::derive(&MAIN_NETWORK, &seed);
        let account_pub = treasury.transparent().to_account_pubkey();
        let address = account_pub
            .derive_external_ivk()
            .expect("Treasury IVK")
            .default_address()
            .0;
        let pubkey = account_pub
            .derive_address_pubkey(
                TransparentKeyScope::EXTERNAL,
                NonHardenedChildIndex::from_index(0).unwrap(),
            )
            .expect("pubkey");
        assert_eq!(funding.address(), &address);
        assert_eq!(funding.pubkey(), pubkey);

        let treasury_fvk = orchard::keys::FullViewingKey::from(treasury.orchard());
        let registry_fvk = orchard::keys::FullViewingKey::from(registry.orchard());
        assert_eq!(material.treasury_orchard_fvk, treasury_fvk);
        assert_eq!(material.registry_orchard_fvk, registry_fvk);
    }
}
