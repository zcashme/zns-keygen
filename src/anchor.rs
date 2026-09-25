//! Anchor transaction builder.

use orchard::builder::{Builder as OrchardBuilder, BundleType};
use orchard::bundle::BundleVersion;
use orchard::circuit::{OrchardCircuitVersion, ProvingKey};
use transparent::builder::{TransparentBuilder, TransparentInputInfo, TransparentSigningSet};
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::fees::transparent::InputView as _;
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::{
    self, Authorization, TransactionData,
    sighash::{SignableInput, signature_hash},
    txid::TxIdDigester,
};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::value::{ZatBalance, Zatoshis};

use crate::keys::CeremonyKeys;

const NUM_ANCHORS: usize = 40;
const DEFAULT_TX_EXPIRY_DELTA: u32 = 40;

/// Custom auth for the unauthorized tx.
struct UnauthorizedTx;
impl Authorization for UnauthorizedTx {
    type TransparentAuth = transparent::builder::Unauthorized;
    type SaplingAuth = sapling::bundle::Authorized;
    type OrchardAuth =
        orchard::builder::InProgress<orchard::builder::Unproven, orchard::builder::Unauthorized>;
}

/// Build the anchor transaction.
///
/// Creates NUM_ANCHORS zero-value Ironwood outputs to the Registry
/// address, plus one Ironwood change output to Treasury internal.
/// Funded by transparent inputs from the operator.
pub fn build_anchor_transaction<P: Parameters>(
    network: &P,
    keys: &CeremonyKeys,
    target_height: BlockHeight,
    inputs: &[TransparentInputInfo],
) -> zcash_primitives::transaction::Transaction {
    let total_funded: u64 = inputs.iter().map(|i| i.coin().value().into_u64()).sum();
    tracing::info!(total_funded, inputs = inputs.len(), "building anchor tx");

    let branch_id = BranchId::for_height(network, target_height);
    let expiry = target_height + DEFAULT_TX_EXPIRY_DELTA;

    // Fee: NUM_ANCHORS + 1 change = 41 Ironwood actions, plus transparent inputs.
    let ironwood_actions = NUM_ANCHORS + 1;
    let fee = FeeRule::standard()
        .fee_required(
            network,
            target_height,
            inputs.iter().map(|i| i.serialized_size()),
            std::iter::empty::<usize>(),
            0,
            0,
            0,
            ironwood_actions,
        )
        .expect("FATAL: fee calculation");
    tracing::info!(fee = fee.into_u64(), "fee");

    let change = Zatoshis::const_from_u64(total_funded - fee.into_u64());
    assert!(change > Zatoshis::ZERO, "FATAL: no change after fees");
    tracing::info!(
        anchors = NUM_ANCHORS,
        change = change.into_u64(),
        "economics"
    );

    let registry_fvk = keys.registry_orchard_fvk();
    let treasury_fvk = keys.treasury_orchard_fvk();

    // ── 1. Build Ironwood bundle (unproven, unsigned) ───────────
    let bundle_version = BundleVersion::ironwood_v3();
    let flags = bundle_version.default_flags();
    let anchor = orchard::Anchor::empty_tree();

    let mut orchard_builder =
        OrchardBuilder::new(BundleType::UNPADDED, bundle_version, flags, anchor)
            .expect("FATAL: orchard builder");

    let registry_addr = registry_fvk.address_at(0u32, orchard::keys::Scope::External);
    let registry_ovk = registry_fvk.to_ovk(orchard::keys::Scope::External);
    for _ in 0..NUM_ANCHORS {
        orchard_builder
            .add_output(
                Some(registry_ovk.clone()),
                registry_addr,
                orchard::value::NoteValue::from_raw(0),
                [0u8; 512],
            )
            .expect("FATAL: anchor output");
    }

    let treasury_addr = treasury_fvk.address_at(0u32, orchard::keys::Scope::Internal);
    let treasury_ovk = treasury_fvk.to_ovk(orchard::keys::Scope::Internal);
    orchard_builder
        .add_output(
            Some(treasury_ovk),
            treasury_addr,
            orchard::value::NoteValue::from_raw(change.into_u64()),
            [0u8; 512],
        )
        .expect("FATAL: change output");

    let (ironwood_bundle, _meta) = orchard_builder
        .build::<ZatBalance>(&mut rand::rngs::OsRng)
        .expect("FATAL: ironwood build")
        .expect("FATAL: bundle exists");

    assert_eq!(
        ironwood_bundle.actions().len(),
        ironwood_actions,
        "FATAL: action count mismatch"
    );

    // ── 2. Build transparent bundle (unsigned) ──────────────────
    let mut t_builder = TransparentBuilder::empty();
    for input in inputs {
        t_builder.add_input(input.clone());
    }
    let transparent_bundle = t_builder.build();

    // ── 3. Assemble unauthorized tx (clones for sighash) ────────
    let unauthed_tx: TransactionData<UnauthorizedTx> = TransactionData::from_parts_v6(
        branch_id,
        0,
        expiry,
        transparent_bundle.clone(),
        None,
        None,
        Some(ironwood_bundle.clone()),
    );

    // ── 4. Compute txid digest + sighashes ──────────────────────
    let txid_parts = unauthed_tx.digest(TxIdDigester);

    // ── 5. Authorize transparent inputs ─────────────────────────
    let treasury_tkey = keys.treasury_transparent();
    let mut signing_set = TransparentSigningSet::new();
    let scope = transparent::keys::TransparentKeyScope::EXTERNAL;
    for _ in inputs {
        let idx = transparent::keys::NonHardenedChildIndex::from_index(0).expect("FATAL: index");
        let sk = treasury_tkey
            .derive_secret_key(scope, idx)
            .expect("FATAL: transparent key");
        signing_set.add_key(sk);
    }

    let unauthed_ref = &unauthed_tx;
    let txid_ref = &txid_parts;
    let authorized_transparent = transparent_bundle
        .map(|b| {
            b.apply_signatures(
                |input| {
                    *signature_hash(unauthed_ref, &SignableInput::Transparent(input), txid_ref)
                        .as_ref()
                },
                &signing_set,
            )
        })
        .transpose()
        .expect("FATAL: transparent signing");

    // ── 6. Create Ironwood proof + sign ─────────────────────────
    // Output-only bundle: all spends are dummies, auto-signed by prepare.
    let shielded_sighash = signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);

    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);

    let authorized_ironwood = ironwood_bundle
        .create_proof(&pk, &mut rand::rngs::OsRng)
        .expect("FATAL: ironwood proof")
        .prepare(&mut rand::rngs::OsRng, *shielded_sighash.as_ref())
        .finalize()
        .expect("FATAL: ironwood finalize");

    // ── 7. Reassemble with Authorized bundles + freeze ──────────
    let authorized_tx: TransactionData<transaction::Authorized> = TransactionData::from_parts_v6(
        branch_id,
        0,
        expiry,
        authorized_transparent,
        None,
        None,
        Some(authorized_ironwood),
    );

    authorized_tx.freeze().expect("FATAL: freeze")
}
