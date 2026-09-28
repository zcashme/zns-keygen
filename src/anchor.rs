//! Anchor transaction builder.

use blake2b_simd::Hash as Blake2bHash;
use orchard::builder::{Builder as OrchardBuilder, BundleType};
use orchard::bundle::BundleVersion;
use orchard::circuit::{OrchardCircuitVersion, ProvingKey};
use transparent::builder::{TransparentBuilder, TransparentInputInfo};
use zcash_primitives::transaction::fees::FeeRule as _;
use zcash_primitives::transaction::fees::transparent::InputView as _;
use zcash_primitives::transaction::fees::zip317::FeeRule;
use zcash_primitives::transaction::{
    self, Authorization, TransactionData, TxDigests,
    sighash::{SignableInput, signature_hash},
    txid::TxIdDigester,
};
use zcash_protocol::consensus::{BlockHeight, BranchId, Parameters};
use zcash_protocol::value::{ZatBalance, Zatoshis};

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
    treasury_sk: &mut secp256k1::SecretKey,
    treasury_fvk: &orchard::keys::FullViewingKey,
    registry_fvk: &orchard::keys::FullViewingKey,
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
    // The signing key is erased once the signatures exist, before the
    // Ironwood proof.
    let authorized_transparent = transparent_bundle.map(|bundle| {
        authorize_transparent(bundle, inputs, &unauthed_tx, &txid_parts, treasury_sk)
    });

    // ── 6. Create Ironwood proof + sign ─────────────────────────
    // Output-only bundle: all spends are dummies, auto-signed by prepare.
    let shielded_sighash = signature_hash(&unauthed_tx, &SignableInput::Shielded, &txid_parts);

    let pk = ProvingKey::build(OrchardCircuitVersion::PostNu6_3);

    let authorized_ironwood = ironwood_bundle
        .create_proof(&pk, &mut rand::rngs::OsRng)
        .expect("FATAL: ironwood proof")
        .prepare(rand::rngs::OsRng, *shielded_sighash.as_ref())
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

/// Sign every transparent input with `treasury_sk`, erase that key, then apply
/// the signatures.
fn authorize_transparent(
    bundle: transparent::bundle::Bundle<transparent::builder::Unauthorized>,
    inputs: &[TransparentInputInfo],
    unauthed_tx: &TransactionData<UnauthorizedTx>,
    txid_parts: &TxDigests<Blake2bHash>,
    treasury_sk: &mut secp256k1::SecretKey,
) -> transparent::bundle::Bundle<transparent::bundle::Authorized> {
    let verify_ctx = secp256k1::Secp256k1::verification_only();
    let signatures = {
        let sign_ctx = secp256k1::Secp256k1::signing_only();
        let signed: Result<
            Vec<secp256k1::ecdsa::Signature>,
            transparent::sighash::InvalidInputIndex,
        > = inputs
            .iter()
            .enumerate()
            .map(|(index, info)| {
                let script = info.coin().script_pubkey();
                let signable = transparent::sighash::SignableInput::from_parts(
                    &bundle,
                    transparent::sighash::SighashType::ALL,
                    index,
                    script,
                    script,
                    info.coin().value(),
                )?;
                let sighash = signature_hash(
                    unauthed_tx,
                    &SignableInput::Transparent(signable),
                    txid_parts,
                );
                let msg = secp256k1::Message::from_digest(*sighash.as_ref());
                Ok(sign_ctx.sign_ecdsa(&msg, treasury_sk))
            })
            .collect();
        treasury_sk.non_secure_erase();
        signed.expect("FATAL: transparent sighash input")
    };

    bundle
        .prepare_transparent_signatures(
            |input| {
                *signature_hash(unauthed_tx, &SignableInput::Transparent(input), txid_parts)
                    .as_ref()
            },
            &verify_ctx,
        )
        .expect("FATAL: prepare transparent signatures")
        .append_external_signatures(&signatures)
        .expect("FATAL: transparent signature")
        .finalize_signatures()
        .expect("FATAL: transparent signing")
}

#[cfg(test)]
mod tests {
    use secp256k1::{Message, PublicKey, Secp256k1, SecretKey};
    use transparent::address::TransparentAddress;
    use transparent::builder::{SpendInfo, TransparentBuilder, TransparentInputInfo};
    use transparent::bundle::{OutPoint, TxOut};
    use zcash_protocol::consensus::{BlockHeight, BranchId, MAIN_NETWORK};
    use zcash_protocol::value::Zatoshis;
    use zcash_script::script::Evaluable;

    use super::*;

    fn p2pkh_input(pubkey: PublicKey, prevout_byte: u8, value: u64) -> TransparentInputInfo {
        let address = TransparentAddress::PublicKeyHash(transparent::util::hash160::hash(
            &pubkey.serialize(),
        ));
        let coin = TxOut::new(Zatoshis::from_u64(value).unwrap(), address.script().into());
        TransparentInputInfo::from_parts(
            OutPoint::new([prevout_byte; 32], 0),
            coin,
            SpendInfo::P2pkh { pubkey },
        )
        .expect("p2pkh input")
    }

    #[test]
    fn transparent_signatures_verify_and_signing_key_is_erased() {
        let mut sk = SecretKey::from_slice(&[2u8; 32]).expect("signing key");
        let pubkey = PublicKey::from_secret_key(&Secp256k1::signing_only(), &sk);
        let inputs = vec![
            p2pkh_input(pubkey, 1, 250_000),
            p2pkh_input(pubkey, 2, 250_000),
        ];

        let mut builder = TransparentBuilder::empty();
        for input in &inputs {
            builder.add_input(input.clone());
        }
        let bundle = builder.build().expect("transparent bundle");

        let height = BlockHeight::from_u32(3_000_000);
        let unauthed = TransactionData::from_parts_v6(
            BranchId::for_height(&MAIN_NETWORK, height),
            0,
            height + 40,
            Some(bundle.clone()),
            None,
            None,
            None,
        );
        let txid_parts = unauthed.digest(TxIdDigester);
        let authorized = authorize_transparent(bundle, &inputs, &unauthed, &txid_parts, &mut sk);

        assert_eq!(
            sk.as_ref(),
            &[1u8; 32],
            "signing key should be overwritten after signing"
        );

        let verify = Secp256k1::verification_only();
        let unauth_bundle = unauthed.transparent_bundle().expect("transparent bundle");
        assert_eq!(authorized.vin.len(), inputs.len());
        for (index, txin) in authorized.vin.iter().enumerate() {
            let script = inputs[index].coin().script_pubkey();
            let signable = transparent::sighash::SignableInput::from_parts(
                unauth_bundle,
                transparent::sighash::SighashType::ALL,
                index,
                script,
                script,
                inputs[index].coin().value(),
            )
            .expect("sighash input");
            let sighash = signature_hash(
                &unauthed,
                &SignableInput::Transparent(signable),
                &txid_parts,
            );
            let bytes = txin.script_sig().0.to_bytes();
            let sig_len = bytes[0] as usize;
            let pushed = &bytes[1..1 + sig_len];
            let signature = secp256k1::ecdsa::Signature::from_der(&pushed[..pushed.len() - 1])
                .expect("DER signature");
            verify
                .verify_ecdsa(
                    &Message::from_digest(*sighash.as_ref()),
                    &signature,
                    &pubkey,
                )
                .expect("signature verifies");
        }
    }
}
