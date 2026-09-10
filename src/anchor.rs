//! Anchor transaction builder.

use std::sync::OnceLock;

use sapling::circuit::{OutputParameters, SpendParameters};
use transparent::bundle::{OutPoint, TxOut};
use transparent::builder::{SpendInfo, TransparentInputInfo, TransparentSigningSet};
use zcash_primitives::transaction::builder::{BuildConfig, Builder, BundlePadding};
use zcash_primitives::transaction::fees::zip317::FeeRule as Zip317FeeRule;
use zcash_protocol::consensus::{BlockHeight, Parameters};
use zcash_protocol::memo::MemoBytes;
use zcash_protocol::value::Zatoshis;

use crate::keys::CeremonyKeys;

const LOGICAL_ACTION_FEE: u64 = 10_000;

struct Params {
    spend: SpendParameters,
    output: OutputParameters,
}

static PARAMS: OnceLock<Params> = OnceLock::new();

const SPEND_HASH: &str = "8270785a1a0d0bc77196f000ee6d221c9c9894f55307bd9357c3f0105d31ca63991ab91324160d8f53e2bbd3c2633a6eb8bdf5205d822e7f3f73edac51b2b70c";
const OUTPUT_HASH: &str = "657e3d38dbb5cb5e7dd2970e8b03d69b4787dd907285b5a7f0790dcc8072f60bf593b32cc2d1c030e00ff5ae64bf84c5c3beb84ddc841d48264b4a171744d028";
const SPEND_BYTES: u64 = 47_958_396;
const OUTPUT_BYTES: u64 = 3_592_860;

fn load_params() -> &'static Params {
    PARAMS.get_or_init(|| {
        let dir = params_dir();
        let spend_bytes = read_verified(&dir.join("sapling-spend.params"), SPEND_HASH, SPEND_BYTES);
        let output_bytes = read_verified(&dir.join("sapling-output.params"), OUTPUT_HASH, OUTPUT_BYTES);
        Params {
            spend: SpendParameters::read(&spend_bytes[..], false)
                .expect("FATAL: spend params"),
            output: OutputParameters::read(&output_bytes[..], false)
                .expect("FATAL: output params"),
        }
    })
}

fn params_dir() -> std::path::PathBuf {
    if let Ok(dir) = std::env::var("ZCASH_PARAMS_DIR") {
        return std::path::PathBuf::from(dir);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
    std::path::PathBuf::from(home).join(".zcash-params")
}

fn read_verified(path: &std::path::Path, expected_hash: &str, expected_bytes: u64) -> Vec<u8> {
    use std::io::Read;
    let size = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
    assert_eq!(size, expected_bytes, "params size mismatch: {}", path.display());
    let mut file = std::fs::File::open(path)
        .unwrap_or_else(|e| panic!("FATAL: cannot open {}: {e}", path.display()));
    let mut bytes = Vec::with_capacity(size as usize);
    file.read_to_end(&mut bytes)
        .unwrap_or_else(|e| panic!("FATAL: cannot read {}: {e}", path.display()));
    let hash = blake2b_simd::Params::new().hash_length(64).hash(&bytes);
    let hash_hex = hex::encode(hash.as_bytes());
    assert_eq!(hash_hex, expected_hash, "params hash mismatch: {}", path.display());
    bytes
}

/// A detected funding UTXO.
pub struct FundingUtxo {
    pub outpoint: OutPoint,
    pub coin: TxOut,
    pub pubkey: secp256k1::PublicKey,
}

/// Build the anchor tx.
pub fn build_anchor<P: Parameters>(
    network: &P,
    keys: &CeremonyKeys,
    target_height: BlockHeight,
    utxos: &[FundingUtxo],
) -> zcash_primitives::transaction::Transaction {
    let params = load_params();

    let total_funded: u64 = utxos.iter().map(|u| u.coin.value().into_u64()).sum();
    tracing::info!(total_funded, "building anchor tx");

    let treasury_tkey = keys.treasury_transparent();
    let mut signing_set = TransparentSigningSet::new();

    // Re-derive the secret key for each UTXO to add to the signing set.
    // The pubkey from the UTXO must match the derived key's pubkey.
    let scope = transparent::keys::TransparentKeyScope::EXTERNAL;
    for utxo in utxos {
        // Derive at index 0 — the keygen only uses the default address.
        let idx = transparent::keys::NonHardenedChildIndex::from_index(0)
            .expect("FATAL: address index");
        let sk = treasury_tkey
            .derive_secret_key(scope, idx)
            .expect("FATAL: transparent key derivation");
        signing_set.add_key(sk);
    }

    let registry_fvk = keys.registry_orchard_fvk();
    let treasury_fvk = keys.treasury_orchard_fvk();

    let num_inputs = utxos.len() as u64;
    let max_n = (total_funded / LOGICAL_ACTION_FEE).saturating_sub(num_inputs + 1);
    assert!(max_n > 0, "FATAL: insufficient funding for any anchors");
    let n = max_n as usize;
    let num_ironwood = n as u64 + 1;
    let fee = Zatoshis::const_from_u64((num_inputs + num_ironwood) * LOGICAL_ACTION_FEE);
    let change = Zatoshis::const_from_u64(total_funded - fee.into_u64());

    tracing::info!(anchors = n, fee = fee.into_u64(), change = change.into_u64(), "anchor tx economics");

    let mut builder = Builder::new(
        network.clone(),
        target_height,
        BuildConfig::Standard {
            sapling_anchor: None,
            orchard_anchor: None,
            ironwood_anchor: None,
            orchard_padding: BundlePadding::DEFAULT,
            ironwood_padding: BundlePadding::DEFAULT,
        },
    );

    for utxo in utxos {
        let input = TransparentInputInfo::from_parts(
            utxo.outpoint.clone(),
            utxo.coin.clone(),
            SpendInfo::P2pkh { pubkey: utxo.pubkey },
        )
        .expect("FATAL: transparent input");
        builder.add_transparent_input(input);
    }

    let registry_addr = registry_fvk.address_at(0u32, orchard::keys::Scope::External);
    let registry_ovk = registry_fvk.to_ovk(orchard::keys::Scope::External);
    for _ in 0..n {
        builder
            .add_ironwood_output::<zcash_primitives::transaction::fees::zip317::FeeError>(
                Some(registry_ovk.clone()),
                registry_addr,
                Zatoshis::ZERO,
                MemoBytes::empty(),
            )
            .expect("FATAL: anchor output");
    }

    if change > Zatoshis::ZERO {
        let treasury_addr = treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal);
        let treasury_ovk = treasury_fvk.to_ovk(orchard::keys::Scope::Internal);
        builder
            .add_ironwood_output::<zcash_primitives::transaction::fees::zip317::FeeError>(
                Some(treasury_ovk),
                treasury_addr,
                change,
                MemoBytes::empty(),
            )
            .expect("FATAL: change output");
    }

    let built = builder
        .build(
            &signing_set,
            &[],
            &[
                orchard::keys::SpendAuthorizingKey::from(keys.treasury().orchard()),
                orchard::keys::SpendAuthorizingKey::from(keys.registry().orchard()),
            ],
            &mut rand::rngs::OsRng,
            &params.spend,
            &params.output,
            &Zip317FeeRule::standard(),
        )
        .expect("FATAL: anchor tx build");

    built.transaction().clone()
}