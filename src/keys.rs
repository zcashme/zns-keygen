//! Key derivation from seed.

use secrecy::{ExposeSecret, Secret};
use transparent::keys::{IncomingViewingKey, NonHardenedChildIndex, TransparentKeyScope};
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Parameters;

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
    /// not retain a `CeremonyKeys` value across the funding wait.
    pub fn derive<P: Parameters>(network: &P, seed: &[u8; 32]) -> Self {
        let (address, pubkey) = {
            let privkey = transparent::keys::AccountPrivKey::from_seed(
                network,
                seed,
                AccountId::try_from(TREASURY_ACCOUNT).unwrap(),
            )
            .expect("FATAL: Treasury key derivation");
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
}

/// Both accounts' spending keys. Construct only for the anchor-signing phase.
pub struct CeremonyKeys {
    treasury: UnifiedSpendingKey,
    registry: UnifiedSpendingKey,
}

impl CeremonyKeys {
    /// Derive both accounts.
    pub fn derive<P: Parameters>(network: &P, seed: &Secret<[u8; 32]>) -> Self {
        let treasury = UnifiedSpendingKey::from_seed(
            network,
            seed.expose_secret(),
            AccountId::try_from(TREASURY_ACCOUNT).unwrap(),
        )
        .expect("FATAL: Treasury key derivation");
        let registry = UnifiedSpendingKey::from_seed(
            network,
            seed.expose_secret(),
            AccountId::try_from(REGISTRY_ACCOUNT).unwrap(),
        )
        .expect("FATAL: Registry key derivation");
        Self { treasury, registry }
    }

    /// Treasury transparent priv key.
    pub fn treasury_transparent(&self) -> &transparent::keys::AccountPrivKey {
        self.treasury.transparent()
    }

    /// Treasury P2PKH address.
    #[cfg(test)]
    pub fn treasury_taddr<P: Parameters>(
        &self,
        _network: &P,
    ) -> transparent::address::TransparentAddress {
        let account_pub = self.treasury_transparent().to_account_pubkey();
        let external_ivk = account_pub
            .derive_external_ivk()
            .expect("FATAL: Treasury IVK");
        external_ivk.default_address().0
    }

    /// External index-0 pubkey used to spend the Treasury funding output.
    #[cfg(test)]
    pub fn treasury_external_pubkey(&self) -> secp256k1::PublicKey {
        self.treasury_transparent()
            .to_account_pubkey()
            .derive_address_pubkey(
                TransparentKeyScope::EXTERNAL,
                NonHardenedChildIndex::from_index(0).unwrap(),
            )
            .expect("FATAL: pubkey derivation")
    }

    /// Registry Orchard FVK.
    pub fn registry_orchard_fvk(&self) -> orchard::keys::FullViewingKey {
        self.registry.orchard().into()
    }

    /// Treasury Orchard FVK.
    pub fn treasury_orchard_fvk(&self) -> orchard::keys::FullViewingKey {
        self.treasury.orchard().into()
    }
}

#[cfg(test)]
mod tests {
    use secrecy::Secret;
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
    fn funding_info_does_not_require_ceremony_keys() {
        let seed = reference_seed();
        let funding = TreasuryFundingInfo::derive(&MAIN_NETWORK, &seed);
        let keys = CeremonyKeys::derive(&MAIN_NETWORK, &Secret::new(seed));
        assert_eq!(funding.address(), &keys.treasury_taddr(&MAIN_NETWORK));
        assert_eq!(funding.pubkey(), keys.treasury_external_pubkey());
    }
}
