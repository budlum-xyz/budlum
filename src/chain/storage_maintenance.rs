//! B.U.D. storage maintenance, as part of the block transition.
//!
//! Every block, the storage domain pays operators for the epochs their deals
//! were served, issues retrieval challenges, slashes the operators that
//! missed one, returns the bonds of deals that served their term, and opens
//! the repair tickets that keep every shard replicated. These are writes to
//! the storage registry and to balances, so they are consensus state.
//!
//! They used to run in the chain actor after a block was committed, reading
//! the wall clock, keeping the reward cursor on `Blockchain` outside the
//! state root, and persisting the registry to a side store that a restart
//! loaded over the block replay. A node that
//! restarted, or one that synced a different way, held a registry and
//! balances its peers did not. This module is the same work as a pure
//! function of `(state, block)`: `apply` runs inside the block transition
//! before the state root, on every path that applies a block, and reads the
//! block's own clock and entropy.
//!
//! The steps are pub(crate), exposed for the `Blockchain` test harness, which
//! drives one step at a time.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::block::Block;
use crate::domain::storage_deal::{StorageEconomicsEvent, StorageEconomicsEventKind};
use crate::domain::StorageDeal;

/// The challenge interval, in epochs, until domain parameters carry one.
/// Matches the test default in `StorageDomainParams::default`.
const DEFAULT_CHALLENGE_INTERVAL: u64 = 100;

/// The storage epoch a block height falls in.
#[must_use]
pub(crate) fn epoch_for(chain_id: u64, height: u64) -> u64 {
    height / crate::core::chain_config::epoch_len_for_chain_id(chain_id).max(1)
}

/// True on the chain the storage economics stay closed on: mainnet, until
/// its accounting parameters are decided.
#[must_use]
pub(crate) fn disabled_on(chain_id: u64) -> bool {
    chain_id
        == crate::core::chain_config::Network::Mainnet
            .chain_id()
            .value()
}

/// Run the block's storage maintenance on `state`.
///
/// # Errors
///
/// A bond return that would overflow a balance. The block is refused, as
/// any other failed state transition is.
pub(crate) fn apply(state: &mut AccountState, block: &Block) -> Result<(), String> {
    if disabled_on(block.chain_id) {
        return Ok(());
    }
    let epoch = epoch_for(block.chain_id, block.index);
    accrue_operator_rewards(state, epoch);
    issue_challenges(state, block.chain_id, epoch, &block.vrf_output);
    finalize_missed_challenges(state, epoch)?;
    finalize_expired_deals(state, epoch)?;
    open_repair_band_tickets(state, epoch);
    annotate_placements(state, block.chain_id, epoch, &block.previous_hash);
    registry_upkeep(state, epoch);
    Ok(())
}

/// Pay every active deal's operator for the epochs served since the last
/// payment, out of the fee the payer escrowed when the deal opened. Returns
/// the number of deals paid and the total.
pub(crate) fn accrue_operator_rewards(state: &mut AccountState, epoch: u64) -> (u32, u64) {
    // Cooldowns that ran out leave the map here, on the block's own clock:
    // the map is in the state root, and a wall clock would let two nodes
    // prune different rows.
    let now_unix = state.current_block_unix_secs;
    let pruned = state.storage_registry.prune_expired_cooldowns(now_unix);
    if pruned > 0 {
        tracing::debug!(pruned, "expired storage operator cooldowns dropped");
    }

    let deals: Vec<StorageDeal> = state
        .storage_registry
        .all_deals()
        .into_iter()
        .filter(|deal| deal.is_active())
        .cloned()
        .collect();

    let mut rewarded = 0u32;
    let mut total = 0u64;
    for deal in deals {
        let deal_id = deal.deal_id;
        let operator = deal.operator;
        let start_epoch = deal.deal_start_epoch;
        let ledger = &mut state.storage_registry.economics;
        let last_epoch = ledger
            .last_reward_epoch
            .get(&deal_id)
            .copied()
            .unwrap_or(start_epoch);
        let reward_until = epoch.min(deal.deal_end_epoch);
        if reward_until <= last_epoch || deal.economics.fee_per_byte_epoch == 0 {
            ledger
                .last_reward_epoch
                .entry(deal_id)
                .or_insert(last_epoch);
            continue;
        }
        // Delta of two cumulative totals: `total_fee` rounds up (div_ceil),
        // so a fresh interval total each tick would pay more than the
        // escrowed fee (HIGH, BUDLUM #162).
        let paid_through = last_epoch.saturating_sub(start_epoch);
        let owed_through = reward_until.saturating_sub(start_epoch);
        let amount = deal
            .total_fee(owed_through)
            .saturating_sub(deal.total_fee(paid_through));
        if amount == 0 {
            continue;
        }
        if let Err(e) = state.try_add_balance(&operator, amount) {
            tracing::error!("operator reward overflow for {operator}: {e}");
            continue;
        }
        let ledger = &mut state.storage_registry.economics;
        let reward_entry = ledger.operator_rewards.entry(operator).or_default();
        *reward_entry = reward_entry.saturating_add(amount);
        ledger.last_reward_epoch.insert(deal_id, reward_until);
        ledger.record(StorageEconomicsEvent {
            epoch,
            deal_id,
            operator,
            amount,
            balance_effect: amount,
            kind: StorageEconomicsEventKind::OperatorRewardAccrued,
        });
        rewarded += 1;
        total = total.saturating_add(amount);
    }
    (rewarded, total)
}

/// Open a retrieval challenge for every active deal whose interval elapsed
/// this epoch. The byte range comes from the block's VRF output, folded with
/// the deal and shard identity; a block without VRF entropy (a PoW or PoA
/// block) issues none rather than fall back to arithmetic a prover could
/// precompute. Returns the number of challenges opened.
pub(crate) fn issue_challenges(
    state: &mut AccountState,
    chain_id: u64,
    epoch: u64,
    vrf_output: &[u8],
) -> u32 {
    if vrf_output.is_empty() {
        return 0;
    }
    let active: Vec<(
        u64,
        u64,
        crate::storage::content_id::ContentId,
        crate::storage::content_id::ContentId,
    )> = state
        .storage_registry
        .all_deals()
        .iter()
        .filter(|d| d.is_active())
        .map(|d| (d.deal_id, d.deal_start_epoch, d.manifest_id, d.shard_id))
        .collect();

    // Sample the full small shard, then one sixty-fourth of a larger one,
    // between 4 KiB and 64 KiB.
    const MIN_CHALLENGE_RANGE_BYTES: u64 = 4 * 1024;
    const MAX_CHALLENGE_RANGE_BYTES: u64 = 64 * 1024;
    let mut issued = 0u32;
    for (deal_id, start_epoch, manifest_id, shard_id) in active {
        let elapsed = epoch.saturating_sub(start_epoch);
        if elapsed == 0 || elapsed % DEFAULT_CHALLENGE_INTERVAL != 0 {
            continue;
        }
        let Some(shard_size) = state
            .storage_registry
            .get_manifest(&manifest_id)
            .and_then(|manifest| manifest.shard(&shard_id))
            .map(|shard| u64::from(shard.size))
        else {
            tracing::warn!("active deal {deal_id} has no registered shard size");
            continue;
        };
        let range_len = if shard_size <= MIN_CHALLENGE_RANGE_BYTES {
            shard_size
        } else {
            (shard_size / 64)
                .clamp(MIN_CHALLENGE_RANGE_BYTES, MAX_CHALLENGE_RANGE_BYTES)
                .min(shard_size)
        };
        let Some(range_count) = shard_size
            .checked_sub(range_len)
            .and_then(|last_start| last_start.checked_add(1))
        else {
            tracing::warn!("active deal {deal_id} has an invalid shard size");
            continue;
        };
        let entropy = crate::core::hash::hash_fields_bytes(&[
            b"BDLM_RETRIEVAL_CHALLENGE_RANGE_V1",
            &chain_id.to_le_bytes(),
            &deal_id.to_le_bytes(),
            manifest_id.as_bytes(),
            shard_id.as_bytes(),
            &epoch.to_le_bytes(),
            vrf_output,
        ]);
        let [e0, e1, e2, e3, e4, e5, e6, e7, ..] = entropy;
        let byte_start = u64::from_le_bytes([e0, e1, e2, e3, e4, e5, e6, e7]) % range_count;
        let byte_end = byte_start + range_len;
        if state
            .storage_registry
            .open_challenge(
                deal_id,
                byte_start,
                byte_end,
                epoch,
                epoch + 10,
                Address::from([0u8; 32]),
                // The minimum opener bond for an automatic challenge.
                1,
            )
            .is_ok()
        {
            issued += 1;
        }
    }
    issued
}

/// Realize a recorded storage slash: start the operator's cooldown on the
/// block clock, count the confiscated bond as burned, and record the event.
/// Both slashing outcomes (a mismatched answer and a missed deadline) route
/// through here, so answering wrongly is no cheaper than not answering.
/// Returns the amount burned.
/// # Errors
///
/// A refund that would overflow the payer's balance. The block is refused,
/// as it is for any other failed state transition.
pub(crate) fn apply_bond_slash(
    state: &mut AccountState,
    epoch: u64,
    deal_id: u64,
    operator: Address,
    slashed_bond: u64,
    reason: &'static str,
) -> Result<u64, String> {
    let now_unix = state.current_block_unix_secs;
    let cooldown_until = state
        .storage_registry
        .begin_operator_cooldown(operator, now_unix);
    tracing::info!(
        %operator,
        cooldown_until,
        "storage operator missed a challenge and is in cooldown"
    );
    // The bond was debited when the deal opened and no slash path refunds
    // it, so the confiscation adds it to destroyed supply without taking a
    // second bond from the operator's live balance.
    let burned = slashed_bond;
    state.burned_total = state.burned_total.saturating_add(burned);
    if burned > 0 {
        tracing::warn!(
            "Confiscated the escrowed bond {burned} of operator {operator} for {reason}"
        );
    }
    let ledger = &mut state.storage_registry.economics;
    ledger.slashed_bond_total = ledger.slashed_bond_total.saturating_add(slashed_bond);
    ledger.burned_bond_total = ledger.burned_bond_total.saturating_add(burned);
    ledger.record(StorageEconomicsEvent {
        epoch,
        deal_id,
        operator,
        amount: slashed_bond,
        balance_effect: 0,
        kind: StorageEconomicsEventKind::OperatorBondSlashed,
    });

    // The deal just left `Active`, and `total_storage_escrowed_supply`
    // counts the unserved part of a *live* deal's prepaid fee. The epochs
    // this deal will never serve leave the denominator with the slash, and
    // nothing else puts them back: the fee would be neither refunded nor
    // burned, it would simply stop being counted, and the supply cap would
    // gain that much minting headroom. The service is not going to be
    // delivered, so the unserved fee returns to the account that escrowed
    // it, which turns the escrow back into a balance and keeps the
    // committed total level.
    let refund = match state.storage_registry.get_deal(deal_id) {
        Some(deal) => {
            let duration = deal.duration_epochs();
            let served = epoch.saturating_sub(deal.deal_start_epoch).min(duration);
            let unearned = deal
                .total_fee(duration)
                .saturating_sub(deal.total_fee(served));
            match deal.payer {
                Some(payer) if unearned > 0 => Some((payer, unearned)),
                _ => None,
            }
        }
        None => None,
    };
    if let Some((payer, unearned)) = refund {
        state
            .try_add_balance(&payer, unearned)
            .map_err(|error| format!("storage fee refund overflow for {payer}: {error}"))?;
        state
            .storage_registry
            .economics
            .record(StorageEconomicsEvent {
                epoch,
                deal_id,
                operator: payer,
                amount: unearned,
                balance_effect: 1,
                kind: StorageEconomicsEventKind::PayerRefund,
            });
        tracing::warn!(
            %payer,
            unearned,
            deal_id,
            "Returned the unserved prepaid fee of a slashed storage deal to its payer"
        );
    }
    Ok(burned)
}

/// Finalize every challenge whose deadline passed without an answer, and
/// slash the operator. Returns the number finalized and the total slashed.
/// # Errors
///
/// A bond refund that would overflow a balance.
pub(crate) fn finalize_missed_challenges(
    state: &mut AccountState,
    epoch: u64,
) -> Result<(u32, u64), String> {
    let pending: Vec<(u64, u64)> = state
        .storage_registry
        .all_challenges()
        .iter()
        .filter(|c| c.deadline_epoch <= epoch)
        .filter(|c| state.storage_registry.get_result(c.challenge_id).is_none())
        .map(|c| (c.challenge_id, c.deal_id))
        .collect();

    let mut finalized = 0u32;
    let mut total_slashed = 0u64;
    for (challenge_id, deal_id) in pending {
        let operator = state
            .storage_registry
            .get_deal(deal_id)
            .map_or_else(Address::zero, |deal| deal.operator);
        let Ok(result) = state
            .storage_registry
            .finalize_missed_challenge(challenge_id, epoch)
        else {
            continue;
        };
        if result.outcome == crate::domain::storage_deal::ChallengeOutcome::Missed {
            total_slashed = total_slashed.saturating_add(result.slashed_bond);
            apply_bond_slash(
                state,
                epoch,
                deal_id,
                operator,
                result.slashed_bond,
                "missed challenge",
            )?;
        }
        finalized += 1;
    }
    Ok((finalized, total_slashed))
}

/// Return the operator bond of every deal that reached its end epoch
/// without being slashed, and open the reallocation ticket for the shard it
/// held. A deal whose release would strand its object stays active and gets
/// the ticket first. Returns the number expired and the total returned.
///
/// # Errors
///
/// A bond return that would overflow the operator's balance.
pub(crate) fn finalize_expired_deals(
    state: &mut AccountState,
    epoch: u64,
) -> Result<(u32, u64), String> {
    let matured: Vec<(u64, Address)> = state
        .storage_registry
        .all_deals()
        .iter()
        .filter(|deal| deal.is_active() && deal.deal_end_epoch <= epoch)
        .map(|deal| (deal.deal_id, deal.operator))
        .collect();

    let mut expired = 0u32;
    let mut total_returned = 0u64;
    for (deal_id, operator) in matured {
        // `expire_deal` re-checks the epoch and the status and returns 0 for
        // a deal that is not active, so a double call cannot pay twice.
        let bond = match state.storage_registry.expire_deal(deal_id, epoch) {
            Ok(bond) => bond,
            Err(crate::domain::storage_deal::StorageError::ExpiryWouldStrandContent { .. }) => {
                if let Some(ticket_id) = state
                    .storage_registry
                    .open_expiry_reallocation(deal_id, epoch)
                {
                    tracing::warn!(
                        "B.U.D. deal {deal_id} is past its term but is one of the last carriers \
                         of its object; held Active, reallocation ticket {ticket_id} opened at \
                         epoch {epoch}"
                    );
                }
                continue;
            }
            Err(crate::domain::storage_deal::StorageError::OpenChallengeBlocksExpiry {
                open_challenges,
                ..
            }) => {
                // The term is over but a question about these bytes is still
                // open. The missed-answer slash settles only an `Active` deal,
                // so the row is held and the next sweep expires it. Expected,
                // not a fault: no warning, and no reallocation ticket until
                // the deal actually expires.
                tracing::debug!(
                    "B.U.D. deal {deal_id} reached its term with {open_challenges} challenge(s) \
                     still open; held Active at epoch {epoch}"
                );
                continue;
            }
            Err(error) => {
                tracing::warn!("Storage deal {deal_id} could not be expired: {error}");
                continue;
            }
        };
        expired += 1;
        // The ticket opens before the bond returns, so the sweep cannot
        // credit a bond and then fail to record the gap it leaves.
        if let Some(ticket_id) = state
            .storage_registry
            .open_expiry_reallocation(deal_id, epoch)
        {
            tracing::info!(
                "B.U.D. deal {deal_id} matured unrenewed; reallocation ticket {ticket_id} opened at epoch {epoch}"
            );
        }
        if bond == 0 {
            continue;
        }
        state
            .try_add_balance(&operator, bond)
            .map_err(|error| format!("storage bond return overflow for {operator}: {error}"))?;
        total_returned = total_returned.saturating_add(bond);
        state
            .storage_registry
            .economics
            .record(StorageEconomicsEvent {
                epoch,
                deal_id,
                operator,
                amount: bond,
                balance_effect: bond,
                kind: StorageEconomicsEventKind::OperatorBondReturned,
            });
    }
    Ok((expired, total_returned))
}

/// Open a repair ticket for every shard of an object in its repair band
/// that has no active replica: keyed off a historic deal when one
/// exists, otherwise as a never-placed ticket. A shard with a live deal gets
/// none, or accepting it would pay two operators for one slot.
fn open_repair_band_tickets(state: &mut AccountState, epoch: u64) {
    let repair_band = state.storage_registry.objects_below_own_repair_margin();
    for (manifest_id, live, k, margin) in &repair_band {
        tracing::warn!(
            "B.U.D. object {} is in the repair band at epoch {epoch}: {live} shards live, k={k}, margin={margin}",
            hex::encode(manifest_id.0)
        );
        let Some(manifest) = state.storage_registry.get_manifest(manifest_id).cloned() else {
            continue;
        };
        for shard in &manifest.shards {
            if state
                .storage_registry
                .active_replica_count(manifest_id, &shard.shard_id)
                > 0
            {
                continue;
            }
            let historic = state
                .storage_registry
                .deals_for_shard(manifest_id, &shard.shard_id)
                .into_iter()
                .filter(|deal| !deal.is_active())
                .map(|deal| deal.deal_id)
                .next_back();
            if let Some(deal_id) = historic {
                if let Some(ticket_id) = state
                    .storage_registry
                    .open_expiry_reallocation(deal_id, epoch)
                {
                    tracing::info!(
                        "B.U.D. opened repair ticket {ticket_id} for missing shard {} (historic deal {deal_id}) on {}",
                        hex::encode(shard.shard_id.0),
                        hex::encode(manifest_id.0)
                    );
                }
            } else {
                // The shard is on the manifest and never held a deal. The
                // domain comes from a sibling deal on the same object when
                // one exists.
                let domain_id = state
                    .storage_registry
                    .deals_for_manifest(manifest_id)
                    .first()
                    .map_or(0, |d| d.domain_id);
                if let Some(ticket_id) = state.storage_registry.open_never_placed_ticket(
                    domain_id,
                    *manifest_id,
                    shard.shard_id,
                    0,
                    epoch,
                ) {
                    tracing::info!(
                        "B.U.D. opened never-placed ticket {ticket_id} for shard {} on {}",
                        hex::encode(shard.shard_id.0),
                        hex::encode(manifest_id.0)
                    );
                }
            }
        }
    }
    for (manifest_id, live, k) in &state.storage_registry.unrecoverable_objects() {
        tracing::error!(
            "B.U.D. object {} is UNRECOVERABLE at epoch {epoch}: {live} shards live, k={k}; no repair can restore it",
            hex::encode(manifest_id.0)
        );
    }
}

/// Record, on every pending repair ticket, the holder the rendezvous
/// placement chose. The entropy is the previous block's hash: fixed before
/// this block was assembled, so its producer cannot steer the choice.
fn annotate_placements(state: &mut AccountState, chain_id: u64, epoch: u64, previous_hash: &str) {
    let candidates: Vec<crate::storage::assignment::ShardCandidate> = state
        .get_active_validators()
        .into_iter()
        .map(|validator| crate::storage::assignment::ShardCandidate {
            address: validator.address,
            stake: validator.stake,
        })
        .collect();
    if candidates.is_empty() {
        return;
    }
    let entropy = crate::core::hash::hash_fields_bytes(&[
        b"BDLM_MAINTENANCE_PLACEMENT_V1",
        &chain_id.to_le_bytes(),
        previous_hash.as_bytes(),
        &epoch.to_le_bytes(),
    ]);
    let annotated = state
        .storage_registry
        .annotate_expected_holders(&entropy, &candidates);
    if annotated > 0 {
        tracing::info!(
            "B.U.D. storage maintenance wrote {annotated} placement advisories at epoch {epoch}"
        );
    }
}

/// The demand band and the ticket lifecycle: a replacement ticket for every
/// free replica slot of a shard under its demand-adjusted target, overdue
/// tickets marked under-replicated, and settled tickets dropped.
fn registry_upkeep(state: &mut AccountState, epoch: u64) {
    let repair_tickets = state
        .storage_registry
        .open_repair_tickets_for_free_slots(epoch);
    if repair_tickets > 0 {
        tracing::warn!(
            "B.U.D. storage maintenance opened {repair_tickets} repair tickets for free replica slots at epoch {epoch}"
        );
    }
    let under_replicated = state
        .storage_registry
        .mark_overdue_reallocations_under_replicated(epoch);
    if under_replicated > 0 {
        tracing::warn!(
            "B.U.D. storage maintenance marked {under_replicated} reallocation tickets under-replicated at epoch {epoch}"
        );
    }
    let swept = state.storage_registry.sweep_settled_reallocations(epoch);
    if swept > 0 {
        tracing::info!(
            "B.U.D. storage maintenance dropped {swept} settled reallocation tickets at epoch {epoch}"
        );
    }
}
