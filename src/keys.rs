//! Key derivation from seed.

use secrecy::{ExposeSecret, Secret};
use transparent::keys::IncomingViewingKey;
use zcash_keys::keys::UnifiedSpendingKey;
use zcash_protocol::consensus::Parameters;

use crate::{REGISTRY_ACCOUNT, TREASURY_ACCOUNT};
use zip32::AccountId;

/// Both accounts' spending keys.
pub struct CeremonyKeys {
    treasury: UnifiedSpendingKey,
    registry: UnifiedSpendingKey,
}

impl CeremonyKeys {
    /// Derive both accounts.
    pub fn derive<P: Parameters>(network: &P, seed: &Secret<[u8; 32]>) -> Self {
        let treasury = UnifiedSpendingKey::from_seed(network, seed.expose_secret(), AccountId::try_from(TREASURY_ACCOUNT).unwrap())
            .expect("FATAL: Treasury key derivation");
        let registry = UnifiedSpendingKey::from_seed(network, seed.expose_secret(), AccountId::try_from(REGISTRY_ACCOUNT).unwrap())
            .expect("FATAL: Registry key derivation");
        Self { treasury, registry }
    }

/// Treasury transparent priv key.
    pub fn treasury_transparent(&self) -> &transparent::keys::AccountPrivKey {
        self.treasury.transparent()
    }

    /// Treasury P2PKH address.
    pub fn treasury_taddr<P: Parameters>(&self, _network: &P) -> transparent::address::TransparentAddress {
        let account_pub = self.treasury_transparent().to_account_pubkey();
        let external_ivk = account_pub
            .derive_external_ivk()
            .expect("FATAL: Treasury IVK");
        external_ivk.default_address().0
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