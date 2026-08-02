//! BOLT 2 `accept_channel` oracle, for the v1 outbound channel funding flow.

use super::Oracle;
use crate::bolt::{AcceptChannel, OpenChannel};
use crate::channel_tx::CommitmentCost;
use crate::pending_channel::PendingChannel;
use crate::violation::Violation;

use bitcoin::Amount;

/// Context for `AcceptChannelOracle`
pub struct AcceptChannelContext<'a> {
    /// The `accept_channel` received from the peer.
    pub accept_channel: &'a AcceptChannel,
    /// The negotiation the `accept_channel` answers, identified by its
    /// `temporary_channel_id`, or `None` if no matching `open_channel` was sent.
    pub negotiation: Option<&'a PendingChannel>,
}

/// Checks whether the `open_channel` answered by an `accept_channel` satisfied
/// the BOLT 2 v1 channel establishment requirements for acceptance, and that
/// the negotiated `temporary_channel_id` was not reused.
pub struct AcceptChannelOracle;

impl Oracle<AcceptChannelContext<'_>> for AcceptChannelOracle {
    fn evaluate(&self, context: &AcceptChannelContext<'_>) -> Result<(), Violation> {
        // Check that the `accept_channel` answers a known `open_channel`.
        let Some(PendingChannel {
            open_channel,
            accept_channel: previous_accept_channel,
            funding_built,
        }) = context.negotiation
        else {
            return Err(Violation::InvalidAcceptChannel(
                context.accept_channel.temporary_channel_id,
                "unknown temporary_channel_id: no open_channel was sent for this negotiation"
                    .to_string(),
            ));
        };

        // Check that the `open_channel` was valid to accept.
        if let Err(reason) = verify_accepted_open_channel(open_channel) {
            return Err(Violation::InvalidAcceptChannel(
                context.accept_channel.temporary_channel_id,
                format!("accepted invalid open_channel: {reason}"),
            ));
        }

        // Check that the `temporary_channel_id` was not reused.
        if previous_accept_channel.is_some() && !funding_built {
            return Err(Violation::InvalidAcceptChannel(
                context.accept_channel.temporary_channel_id,
                "temporary_channel_id reuse: previous negotiation has not reached funding_created"
                    .to_string(),
            ));
        }

        Ok(())
    }
}

/// Returns an error if our `open_channel` breaches a BOLT 2 requirement, i.e.
/// the reason its receiver had to fail the channel instead of accepting it,
/// or `Ok(())` if it breaches none.
fn verify_accepted_open_channel(open_channel: &OpenChannel) -> Result<(), String> {
    // Check that the funding amounts are valid.
    // FIXME: Varies if `option_support_large_channel` is not negotiated.
    let total_supply_satoshis = Amount::MAX_MONEY.to_sat();
    if open_channel.funding_satoshis > total_supply_satoshis {
        return Err(format!(
            "funding_satoshis {} exceeds maximum funding of {total_supply_satoshis} sat",
            open_channel.funding_satoshis,
        ));
    }

    let funding_msat = open_channel.funding_satoshis * 1000;
    if open_channel.push_msat > funding_msat {
        return Err(format!(
            "push_msat {} exceeds funding amount {} msat",
            open_channel.push_msat, funding_msat,
        ));
    }

    // Check that the channel type was included.
    let Some(channel_type) = open_channel.tlvs.channel_type.as_deref() else {
        return Err("open_channel does not include a channel_type".to_string());
    };

    // Check that the opener can afford the proposed feerate.
    let opener_balance_sat = (funding_msat - open_channel.push_msat) / 1000;
    let commitment_cost = CommitmentCost::new(open_channel.feerate_per_kw, channel_type);
    if opener_balance_sat
        .checked_sub(commitment_cost.total_sat())
        .is_none()
    {
        return Err(format!(
            "opener balance {opener_balance_sat} sat cannot cover the commitment fee and anchor cost",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bolt::{AcceptChannel, AcceptChannelTlvs, ChannelId, OpenChannelTlvs};
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    fn pubkey(seed: u8) -> PublicKey {
        let sk = SecretKey::from_slice(&[seed; 32]).expect("valid secret key");
        PublicKey::from_secret_key(&Secp256k1::new(), &sk)
    }

    /// Valid `open_channel` message for testing.
    fn open_channel() -> OpenChannel {
        let key = pubkey(1);
        OpenChannel {
            chain_hash: [0u8; 32],
            temporary_channel_id: ChannelId::new([1u8; 32]),
            funding_satoshis: 10_000_000,
            push_msat: 3_000_000_000,
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            feerate_per_kw: 15_000,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: key,
            revocation_basepoint: key,
            payment_basepoint: key,
            delayed_payment_basepoint: key,
            htlc_basepoint: key,
            first_per_commitment_point: key,
            channel_flags: 1,
            tlvs: OpenChannelTlvs {
                upfront_shutdown_script: None,
                channel_type: Some(vec![0x10, 0x00]),
            },
        }
    }

    /// Valid `accept_channel` message for testing.
    fn accept_channel() -> AcceptChannel {
        let key = pubkey(2);
        AcceptChannel {
            temporary_channel_id: ChannelId::new([1u8; 32]),
            dust_limit_satoshis: 546,
            max_htlc_value_in_flight_msat: 100_000_000,
            channel_reserve_satoshis: 10_000,
            htlc_minimum_msat: 1_000,
            minimum_depth: 6,
            to_self_delay: 144,
            max_accepted_htlcs: 483,
            funding_pubkey: key,
            revocation_basepoint: key,
            payment_basepoint: key,
            delayed_payment_basepoint: key,
            htlc_basepoint: key,
            first_per_commitment_point: key,
            tlvs: AcceptChannelTlvs {
                upfront_shutdown_script: None,
                channel_type: Some(vec![0x10, 0x00]),
            },
        }
    }

    /// Pending channel negotiation for testing.
    fn pending_negotiation(oc: OpenChannel) -> PendingChannel {
        PendingChannel {
            open_channel: oc,
            accept_channel: None,
            funding_built: false,
        }
    }

    #[track_caller]
    fn assert_pass(accept_channel: &AcceptChannel, negotiation: Option<&PendingChannel>) {
        if let Err(err) = AcceptChannelOracle.evaluate(&AcceptChannelContext {
            accept_channel,
            negotiation,
        }) {
            panic!("expected pass, got: {err}");
        }
    }

    #[track_caller]
    fn assert_fail(
        accept_channel: &AcceptChannel,
        negotiation: Option<&PendingChannel>,
        expected: &str,
    ) {
        match AcceptChannelOracle.evaluate(&AcceptChannelContext {
            accept_channel,
            negotiation,
        }) {
            Err(Violation::InvalidAcceptChannel(chan_id, reason)) => {
                assert_eq!(accept_channel.temporary_channel_id, chan_id);
                assert!(
                    reason.contains(expected),
                    "unexpected failure reason: {reason}"
                );
            }
            _ => panic!("expected failure: {expected}"),
        }
    }

    #[test]
    fn conforming_negotiation_passes() {
        assert_pass(
            &accept_channel(),
            Some(&pending_negotiation(open_channel())),
        );
    }

    #[test]
    fn accept_channel_for_unknown_temporary_channel_id() {
        assert_fail(
            &accept_channel(),
            None,
            "unknown temporary_channel_id: no open_channel was sent for this negotiation",
        );
    }

    #[test]
    fn funding_satoshis_above_bitcoins_total_supply() {
        let mut oc = open_channel();
        oc.funding_satoshis = Amount::MAX_MONEY.to_sat() + 1;

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: funding_satoshis 2100000000000001 exceeds maximum funding",
        );
    }

    #[test]
    fn push_msat_above_the_funding_amount() {
        let mut oc = open_channel();
        oc.push_msat = oc.funding_satoshis * 1000 + 1;

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: push_msat 10000000001 exceeds funding amount",
        );
    }

    #[test]
    fn open_channel_without_a_channel_type() {
        let mut oc = open_channel();
        oc.tlvs.channel_type = None;

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: open_channel does not include a channel_type",
        );
    }

    #[test]
    fn opener_cannot_afford_commitment_fee() {
        let mut oc = open_channel();
        oc.push_msat = oc.funding_satoshis * 1000 - 10_000_000;

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: opener balance 10000 sat cannot cover the commitment fee",
        );
    }

    #[test]
    fn opener_cannot_cover_anchor_outputs() {
        let mut oc = open_channel();
        oc.push_msat = oc.funding_satoshis * 1000 - 17_000_000;
        oc.tlvs.channel_type = Some(vec![0x40, 0x10, 0x00]);

        assert_fail(
            &accept_channel(),
            Some(&pending_negotiation(oc)),
            "invalid open_channel: opener balance 17000 sat cannot cover the commitment fee and anchor cost",
        );
    }

    #[test]
    fn temporary_channel_id_reuse_before_funding_created() {
        let mut negotiation = pending_negotiation(open_channel());
        negotiation.accept_channel = Some(accept_channel());

        assert_fail(
            &accept_channel(),
            Some(&negotiation),
            "temporary_channel_id reuse: previous negotiation has not reached funding_created",
        );
    }

    #[test]
    fn temporary_channel_id_reuse_after_funding_created() {
        let mut negotiation = pending_negotiation(open_channel());
        negotiation.accept_channel = Some(accept_channel());
        negotiation.funding_built = true;

        assert_pass(&accept_channel(), Some(&negotiation));
    }
}
