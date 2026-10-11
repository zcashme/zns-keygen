//! Anchor broadcast classification.
//!
//! The ceremony runs straight through in one process. These pure helpers
//! decide what the anchor's chain presence means for the birthday.

/// Best-chain confirmations required before the inclusion height becomes the birthday.
///
/// One confirmation shows that the anchor entered a block. That block can still
/// be reorged, so it is not the birthday. Ten confirmations is the depth at
/// which this ceremony treats the inclusion height as fixed. The birthday is
/// that block's height, not the chain tip and not the height plus this depth.
pub const ANCHOR_CONFIRMATIONS: u32 = 10;

/// What a lookup of the anchor txid means for the birthday.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AnchorLookup {
    /// The node does not have this txid in the mempool or the best chain.
    Absent,
    /// In the mempool, or mined on the best chain with fewer than [`ANCHOR_CONFIRMATIONS`].
    ///
    /// `height` is missing for a mempool transaction. `confirmations` is missing
    /// or still below the required depth.
    Pending {
        height: Option<i64>,
        confirmations: Option<u64>,
    },
    /// Zebra still has the transaction, but only on a side chain.
    ///
    /// A negative height, including `-1`, is not a mining candidate. The
    /// transaction has to be submitted again so the node can accept it into the
    /// mempool or reject it as expired.
    SideChain,
    /// Best-chain block that contains the anchor, after [`ANCHOR_CONFIRMATIONS`].
    Confirmed { birthday: u32 },
}

/// The next step for the anchor. None of these builds a different transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BroadcastAction {
    /// The txid is unknown. Submit the anchor transaction and no other.
    SendStored,
    /// The txid is known, but its birthday is not confirmed. Do not finalize.
    AwaitConfirmation,
    /// The inclusion height is confirmed. Persist it and finalize.
    Confirmed { birthday: u32 },
}

/// Classify a verbose `getrawtransaction` result.
///
/// A missing height, a missing confirmation count, or fewer than
/// [`ANCHOR_CONFIRMATIONS`] stays pending. A negative height is a side chain.
/// The chain tip is not an input.
pub fn classify_anchor(height: Option<i64>, confirmations: Option<u64>) -> AnchorLookup {
    if matches!(height, Some(height) if height < 0) {
        return AnchorLookup::SideChain;
    }
    if let (Some(height), Some(confirmations)) = (height, confirmations)
        && height >= 0
        && confirmations >= u64::from(ANCHOR_CONFIRMATIONS)
        && let Ok(birthday) = u32::try_from(height)
    {
        return AnchorLookup::Confirmed { birthday };
    }
    AnchorLookup::Pending {
        height,
        confirmations,
    }
}

/// Decide the broadcast step from a lookup that has already been performed.
pub fn broadcast_action(lookup: AnchorLookup) -> BroadcastAction {
    match lookup {
        AnchorLookup::Absent | AnchorLookup::SideChain => BroadcastAction::SendStored,
        AnchorLookup::Pending { .. } => BroadcastAction::AwaitConfirmation,
        AnchorLookup::Confirmed { birthday } => BroadcastAction::Confirmed { birthday },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn absent_transaction_is_sent_once() {
        assert_eq!(
            broadcast_action(AnchorLookup::Absent),
            BroadcastAction::SendStored
        );
    }

    #[test]
    fn birthday_is_the_confirmed_inclusion_height() {
        let inclusion: i64 = 4408922;
        assert_eq!(
            classify_anchor(Some(inclusion), Some(u64::from(ANCHOR_CONFIRMATIONS))),
            AnchorLookup::Confirmed {
                birthday: inclusion as u32
            }
        );
        assert_eq!(
            broadcast_action(classify_anchor(
                Some(inclusion),
                Some(u64::from(ANCHOR_CONFIRMATIONS))
            )),
            BroadcastAction::Confirmed {
                birthday: inclusion as u32
            }
        );
    }

    #[test]
    fn unconfirmed_anchor_does_not_take_a_birthday() {
        let pending = [
            classify_anchor(None, None),
            classify_anchor(None, Some(0)),
            classify_anchor(Some(4408922), None),
            classify_anchor(Some(4408922), Some(u64::from(ANCHOR_CONFIRMATIONS - 1))),
            classify_anchor(None, Some(100)),
            classify_anchor(Some(i64::from(u32::MAX) + 1), Some(100)),
        ];
        for lookup in pending {
            assert!(matches!(lookup, AnchorLookup::Pending { .. }));
            assert_eq!(broadcast_action(lookup), BroadcastAction::AwaitConfirmation);
        }
    }

    #[test]
    fn side_chain_anchor_is_resubmitted() {
        assert_eq!(classify_anchor(Some(-1), Some(0)), AnchorLookup::SideChain);
        assert_eq!(
            classify_anchor(Some(-1), Some(100)),
            AnchorLookup::SideChain
        );
        assert_eq!(
            broadcast_action(AnchorLookup::SideChain),
            BroadcastAction::SendStored
        );
    }

    #[test]
    fn a_reorg_before_confirmation_keeps_the_later_inclusion_height() {
        assert_eq!(
            broadcast_action(classify_anchor(Some(100), Some(3))),
            BroadcastAction::AwaitConfirmation
        );
        assert_eq!(
            broadcast_action(classify_anchor(
                Some(108),
                Some(u64::from(ANCHOR_CONFIRMATIONS))
            )),
            BroadcastAction::Confirmed { birthday: 108 }
        );
    }
}
