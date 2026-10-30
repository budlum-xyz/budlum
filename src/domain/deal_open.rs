//! One deal-open implementation for every path that opens a paid storage deal.
//!
//! The RPC path and the in-block path both escrow a client fee and lock an
//! operator bond, and a repair (reallocation) acceptance does the same for the
//! replacement placement. Keeping that in functions on `AccountState` means
//! one copy of the rules and one answer to "what does a refused open leave
//! behind".

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::domain::storage_deal::{
    DealStatus, ReallocationStatus, StorageEconomicsParams, StorageError,
};
use crate::domain::storage_params::StorageDomainParams;
use crate::domain::Hash32;
use crate::storage::generated::held_bytes;

/// What a deal-open asks for, apart from who pays and who is checked.
pub struct DealOpenTerms<'a> {
    pub domain_id: u32,
    pub manifest: &'a crate::storage::ContentManifest,
    pub shard_id: crate::storage::ContentId,
    pub operator: Address,
    pub replica_index: u8,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub economics: StorageEconomicsParams,
    pub merkle_proof: Option<Vec<u8>>,
    pub storage_root: Option<Hash32>,
}

/// What a repair acceptance asks for. The placement itself (manifest, shard,
/// replica, domain) comes from the ticket, not from the caller.
pub struct ReallocationTerms {
    pub ticket_id: u64,
    pub replacement_operator: Address,
    pub start_epoch: u64,
    pub end_epoch: u64,
    pub economics: StorageEconomicsParams,
    pub merkle_proof: Option<Vec<u8>>,
    pub storage_root: Option<Hash32>,
}

/// The two amounts a deal moves out of balances once it is accepted.
struct Escrow {
    fee: u64,
    bond: u64,
}

/// Open a paid storage deal: every refusal is decided before any write.
///
/// The fee is priced on `held_bytes`, the same number `open_deal` records on
/// the deal, so the escrow and the recorded price cannot differ. Balance
/// checks only read. The registry open comes next and writes nothing when it
/// refuses. The debits come last and cannot fail after the checks above.
///
/// `payer_reserve` is a balance the payer must keep after paying. It is
/// required, not spent.
pub fn open_deal_escrowed(
    state: &mut AccountState,
    terms: &DealOpenTerms<'_>,
    payer: Address,
    now_unix_secs: u64,
    min_operator_bond: u64,
    payer_reserve: u64,
) -> Result<u64, String> {
    let operator = terms.operator;
    let manifest = terms.manifest;
    let shard_id = terms.shard_id;

    refuse_cooling_operator(state, &operator, now_unix_secs)?;
    let (epochs, listed_bytes) = epochs_and_listed_bytes(terms)?;
    // A deal must not start in an epoch that has already elapsed. The supply
    // denominator prices the unearned part of the fee from the epoch index
    // (`total_storage_escrowed_supply`), which agrees with what the operator is
    // owed only when every elapsed epoch of the window was served after the
    // open. A backdated start would make the whole fee read as earned before
    // `accrue_storage_operator_rewards` paid a single unit of it, so the
    // escrow would leave the denominator while the money is in nobody's
    // balance - and a bridge mint in the same block would clear the cap check
    // with it.
    refuse_elapsed_start(state, terms.start_epoch)?;

    // Replay guard: a signed deal-open must not debit escrow and lock bond
    // twice for the same placement. An ACTIVE deal of the same operator on
    // this shard whose epoch range overlaps refuses the open. The replica
    // index and the exact range are not part of the test: one operator holds
    // one copy of a shard, so a second deal with another index or a shifted
    // range adds a replica on paper and no durability.
    let duplicate = state
        .storage_registry
        .deals_for_shard(&manifest.manifest_id, &shard_id)
        .iter()
        .any(|d| {
            d.status == DealStatus::Active
                && d.operator == operator
                && d.deal_start_epoch < terms.end_epoch
                && terms.start_epoch < d.deal_end_epoch
        });
    if duplicate {
        return Err(format!(
            "an active deal already covers shard {shard_id:?} for operator {operator} at replica {} over epochs {}..{}; refusing a replayed open",
            terms.replica_index, terms.start_epoch, terms.end_epoch
        ));
    }

    let escrow = check_funds(state, terms, listed_bytes, epochs, &payer, payer_reserve)?;

    let deal_id = state
        .storage_registry
        .open_deal(
            terms.domain_id,
            manifest,
            shard_id,
            operator,
            terms.replica_index,
            terms.start_epoch,
            terms.end_epoch,
            terms.economics.clone(),
            &registry_params(min_operator_bond),
            terms.merkle_proof.clone(),
            terms.storage_root,
        )
        .map_err(|e| format!("open_deal failed: {e:?}"))?;

    state.storage_registry.set_deal_payer(deal_id, payer);
    debit_escrow(state, &payer, &operator, &escrow)?;
    Ok(deal_id)
}

/// Accept a repair ticket for a replacement operator, escrowing the fee and
/// locking the bond the same way a fresh open does.
///
/// Same order as [`open_deal_escrowed`]: every refusal is decided before any
/// write. The ticket checks and the cooldown read only, the balance checks
/// read only, the registry acceptance writes nothing when it refuses, and the
/// debits come last. The escrow is priced on `held_bytes` of the ticket's
/// shard, which is what the replacement deal records.
pub fn accept_reallocation_escrowed(
    state: &mut AccountState,
    terms: &ReallocationTerms,
    payer: Address,
    now_unix_secs: u64,
    min_operator_bond: u64,
    payer_reserve: u64,
) -> Result<u64, String> {
    let ticket_id = terms.ticket_id;
    let operator = terms.replacement_operator;

    let ticket = state
        .storage_registry
        .get_reallocation_ticket(ticket_id)
        .cloned()
        .ok_or_else(|| format!("unknown reallocation ticket {ticket_id}"))?;
    if !matches!(
        ticket.status,
        ReallocationStatus::Pending | ReallocationStatus::UnderReplicated
    ) {
        return Err(format!(
            "reallocation ticket {ticket_id} is not open for acceptance"
        ));
    }
    // The identity refusal precedes the cooldown refusal deliberately: the
    // slash that opened this very ticket also starts the operator's
    // cooldown, so the cooldown message would otherwise always shadow the
    // more specific answer: "you are the operator this ticket replaces".
    // A cooldown expires; being the slashed operator of the ticket does
    // not, and the caller deserves the refusal that never goes away.
    if operator == ticket.slashed_operator {
        return Err(format!(
            "operator {operator} is the slashed operator of ticket {ticket_id}"
        ));
    }
    refuse_cooling_operator(state, &operator, now_unix_secs)?;

    let manifest = state
        .storage_registry
        .get_manifest(&ticket.manifest_id)
        .cloned()
        .ok_or_else(|| {
            format!(
                "manifest {} of ticket {ticket_id} vanished",
                ticket.manifest_id
            )
        })?;
    let open_terms = DealOpenTerms {
        domain_id: ticket.domain_id,
        manifest: &manifest,
        shard_id: ticket.shard_id,
        operator,
        replica_index: ticket.replica_index,
        start_epoch: terms.start_epoch,
        end_epoch: terms.end_epoch,
        economics: terms.economics.clone(),
        merkle_proof: terms.merkle_proof.clone(),
        storage_root: terms.storage_root,
    };
    let (epochs, listed_bytes) = epochs_and_listed_bytes(&open_terms)?;
    refuse_elapsed_start(state, open_terms.start_epoch)?;
    let escrow = check_funds(
        state,
        &open_terms,
        listed_bytes,
        epochs,
        &payer,
        payer_reserve,
    )?;

    let replacement_deal_id = state
        .storage_registry
        .accept_reallocation_ticket(
            ticket_id,
            operator,
            terms.start_epoch,
            terms.end_epoch,
            terms.economics.clone(),
            &registry_params(min_operator_bond),
            terms.merkle_proof.clone(),
            terms.storage_root,
        )
        .map_err(|e| format!("accept_reallocation_ticket failed: {e:?}"))?;

    state
        .storage_registry
        .set_deal_payer(replacement_deal_id, payer);
    debit_escrow(state, &payer, &operator, &escrow)?;
    Ok(replacement_deal_id)
}

/// A deal may not start in an epoch that has already elapsed.
///
/// The supply denominator prices the unearned part of the fee from the epoch
/// index ([`crate::core::account::AccountState::total_storage_escrowed_supply`]),
/// which agrees with what the operator is owed only when every elapsed epoch
/// of the window was served after the open. A backdated start would make the
/// whole fee read as earned before `accrue_storage_operator_rewards` paid a
/// single unit of it, so the escrow would leave the denominator while the
/// money sits in nobody's balance - and a bridge mint in the same block would
/// clear the cap check with it.
fn refuse_elapsed_start(state: &AccountState, start_epoch: u64) -> Result<(), String> {
    if start_epoch < state.epoch_index {
        return Err(format!(
            "deal start epoch {start_epoch} has already elapsed (current epoch {})",
            state.epoch_index
        ));
    }
    Ok(())
}

/// An operator that missed a challenge sits out six hours. Checked here
/// because this layer knows wall time; the registry works in epochs. Both
/// entry points call this before anything else that can be refused for cause.
fn refuse_cooling_operator(
    state: &AccountState,
    operator: &Address,
    now_unix_secs: u64,
) -> Result<(), String> {
    if let Some(until) = state
        .storage_registry
        .operator_cooldown_until(operator, now_unix_secs)
    {
        return Err(format!(
            "operator {operator} missed a challenge and cannot take storage work until unix {until} ({} seconds left)",
            until.saturating_sub(now_unix_secs)
        ));
    }
    Ok(())
}

/// The deal length in epochs and the listed size of the shard.
///
/// The shard is looked up here rather than trusting a caller-supplied
/// size, so the escrow and the deal are computed from the same entry.
fn epochs_and_listed_bytes(terms: &DealOpenTerms<'_>) -> Result<(u64, u64), String> {
    let epochs = terms.end_epoch.saturating_sub(terms.start_epoch);
    if epochs == 0 {
        return Err("Deal duration must be > 0".into());
    }
    let listed_bytes = u64::from(
        terms
            .manifest
            .shard(&terms.shard_id)
            .ok_or_else(|| {
                format!(
                    "shard {:?} is not part of manifest {:?}",
                    terms.shard_id, terms.manifest.manifest_id
                )
            })?
            .size,
    );
    Ok((epochs, listed_bytes))
}

/// Price the deal on what the operator holds, which is what `open_deal`
/// records, and check both balances without writing.
///
/// When one account is both payer and operator it must cover the fee, the
/// reserve and the bond together.
fn check_funds(
    state: &AccountState,
    terms: &DealOpenTerms<'_>,
    listed_bytes: u64,
    epochs: u64,
    payer: &Address,
    payer_reserve: u64,
) -> Result<Escrow, String> {
    let held = held_bytes(&terms.manifest.source, listed_bytes).ok_or_else(|| {
        format!(
            "open_deal failed: {:?}",
            StorageError::InvalidManifest {
                reason: String::from(
                    "held_bytes refused the source (hybrid prefix longer than listed size)",
                ),
            }
        )
    })?;
    let fee = terms.economics.total_fee(held, epochs);
    let bond = terms.economics.operator_bond;

    // `spendable_balance`, not `get_balance`: the vesting lock is a spend gate
    // and an escrow is a spend. The debit below subtracts from
    // `account.balance`, so a raw-balance check here would let vesting-locked
    // allocation pay deal fees and operator bonds out of the account, which is
    // exactly the class `Transfer`, `AiOperatorBond`, hub registration and AI
    // inference escrow already close.
    let payer_needs = fee.checked_add(payer_reserve);
    if payer_needs.is_none_or(|need| state.spendable_balance(payer) < need) {
        return Err(format!("Insufficient payer balance for deal fee {fee}"));
    }
    if bond > 0 {
        let operator_needs = if *payer == terms.operator {
            payer_needs.and_then(|need| need.checked_add(bond))
        } else {
            Some(bond)
        };
        if operator_needs.is_none_or(|need| state.spendable_balance(&terms.operator) < need) {
            return Err(format!("Insufficient operator balance for bond {bond}"));
        }
    }
    Ok(Escrow { fee, bond })
}

/// The registry reads only `min_operator_bond` from the domain params when it
/// opens a deal, so the defaults for every other field are inert here.
fn registry_params(min_operator_bond: u64) -> StorageDomainParams {
    StorageDomainParams {
        min_operator_bond,
        ..StorageDomainParams::default()
    }
}

/// Move the fee and the bond out of the balances. The checks before the
/// registry write make a failure here unreachable.
fn debit_escrow(
    state: &mut AccountState,
    payer: &Address,
    operator: &Address,
    escrow: &Escrow,
) -> Result<(), String> {
    debit(state, payer, escrow.fee)?;
    debit(state, operator, escrow.bond)
}

/// Subtract `amount` from an account balance. The checks in the caller
/// make the failure unreachable, but it is reported rather than wrapped.
fn debit(state: &mut AccountState, who: &Address, amount: u64) -> Result<(), String> {
    if amount == 0 {
        return Ok(());
    }
    let account = state.get_or_create(who);
    account.balance = account
        .balance
        .checked_sub(amount)
        .ok_or_else(|| format!("balance underflow debiting {amount} from {who}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::storage_deal::FEE_RATE_SCALE;
    use crate::storage::ContentManifest;

    const BOND: u64 = 1_000_000;

    fn proof() -> Vec<u8> {
        let envelope = bud_proof::ProofEnvelope {
            proof_format_version: 1,
            backend: "test-backend".to_string(),
            p3_version: "0.6".to_string(),
            fri_params_id: "test-fri".to_string(),
            public_inputs_hash: [0x42u8; 32],
            proof_bytes: vec![0xABu8; 96],
            degree_bits: 8,
        };
        bincode::serialize(&envelope).unwrap()
    }

    fn manifest() -> ContentManifest {
        ContentManifest::from_bytes_sliced(b"deal open escrow payload", 8).unwrap()
    }

    /// The listed size of the first shard, which for a stored manifest is
    /// also what the deal holds.
    fn shard_bytes(manifest: &ContentManifest) -> u64 {
        u64::from(manifest.shards[0].size)
    }

    fn terms(manifest: &ContentManifest, operator: Address) -> DealOpenTerms<'_> {
        DealOpenTerms {
            domain_id: 42,
            manifest,
            shard_id: manifest.shards[0].shard_id,
            operator,
            replica_index: 0,
            start_epoch: 0,
            end_epoch: 10,
            economics: StorageEconomicsParams {
                operator_bond: BOND,
                // Priced so that one epoch costs 10 base units.
                fee_per_byte_epoch: 10 * (FEE_RATE_SCALE as u64) / shard_bytes(manifest),
            },
            merkle_proof: Some(proof()),
            storage_root: Some([0x42u8; 32]),
        }
    }

    fn fee_of(t: &DealOpenTerms<'_>) -> u64 {
        t.economics
            .total_fee(shard_bytes(t.manifest), t.end_epoch - t.start_epoch)
    }

    fn operator() -> Address {
        Address::from([11u8; 32])
    }

    fn payer() -> Address {
        Address::from([12u8; 32])
    }

    fn funded(payer_balance: u64, operator_balance: u64) -> AccountState {
        let mut state = AccountState::new();
        state.add_balance(&payer(), payer_balance);
        state.add_balance(&operator(), operator_balance);
        state
    }

    /// Everything a refused open must leave alone.
    fn snapshot(state: &AccountState) -> (u64, u64, [u8; 32]) {
        (
            state.get_balance(&payer()),
            state.get_balance(&operator()),
            state.storage_registry.root(),
        )
    }

    /// Run the open and, when it is refused, check that it wrote nothing.
    fn open_without_write(
        mut state: AccountState,
        t: &DealOpenTerms<'_>,
        payer_address: Address,
        now: u64,
        reserve: u64,
    ) -> Result<u64, String> {
        let before = snapshot(&state);
        let result = open_deal_escrowed(&mut state, t, payer_address, now, BOND, reserve);
        if result.is_err() {
            assert_eq!(snapshot(&state), before, "a refusal must not write");
        }
        result
    }

    #[test]
    fn a_cooled_down_operator_is_refused_without_a_write() {
        let manifest = manifest();
        let t = terms(&manifest, operator());
        let mut state = funded(5_000_000, 5_000_000);
        state
            .storage_registry
            .begin_operator_cooldown(operator(), 100);
        let err = open_without_write(state, &t, payer(), 200, 0).unwrap_err();
        assert!(err.contains("missed a challenge"), "got {err:?}");
    }

    #[test]
    fn a_zero_length_deal_is_refused_without_a_write() {
        let manifest = manifest();
        let mut t = terms(&manifest, operator());
        t.end_epoch = t.start_epoch;
        let err = open_without_write(funded(5_000_000, 5_000_000), &t, payer(), 0, 0).unwrap_err();
        assert!(err.contains("Deal duration must be > 0"), "got {err:?}");
    }

    #[test]
    fn an_unknown_shard_is_refused_without_a_write() {
        let manifest = manifest();
        let mut t = terms(&manifest, operator());
        t.shard_id = crate::storage::ContentId([0xEEu8; 32]);
        let err = open_without_write(funded(5_000_000, 5_000_000), &t, payer(), 0, 0).unwrap_err();
        assert!(err.contains("is not part of manifest"), "got {err:?}");
    }

    #[test]
    fn a_second_replica_of_the_same_operator_is_refused_without_a_write() {
        let manifest = manifest();
        let t = terms(&manifest, operator());
        let mut state = funded(5_000_000, 5_000_000);
        open_deal_escrowed(&mut state, &t, payer(), 0, BOND, 0).unwrap();
        let mut shifted = terms(&manifest, operator());
        shifted.replica_index = 1;
        shifted.start_epoch = t.start_epoch + 1;
        let err = open_without_write(state, &shifted, payer(), 0, 0).unwrap_err();
        assert!(err.contains("refusing a replayed open"), "got {err:?}");
    }

    #[test]
    fn a_replayed_open_is_refused_without_a_second_write() {
        let manifest = manifest();
        let t = terms(&manifest, operator());
        let mut state = funded(5_000_000, 5_000_000);
        open_deal_escrowed(&mut state, &t, payer(), 0, BOND, 0).unwrap();
        let err = open_without_write(state, &t, payer(), 0, 0).unwrap_err();
        assert!(err.contains("refusing a replayed open"), "got {err:?}");
    }

    #[test]
    fn a_short_payer_is_refused_without_a_write() {
        let manifest = manifest();
        let t = terms(&manifest, operator());
        let fee = fee_of(&t);
        let err = open_without_write(funded(fee - 1, 5_000_000), &t, payer(), 0, 0).unwrap_err();
        assert!(err.contains("Insufficient payer balance"), "got {err:?}");
    }

    #[test]
    fn a_short_operator_is_refused_without_a_write() {
        let manifest = manifest();
        let t = terms(&manifest, operator());
        let err = open_without_write(funded(5_000_000, BOND - 1), &t, payer(), 0, 0).unwrap_err();
        assert!(err.contains("Insufficient operator balance"), "got {err:?}");
    }

    #[test]
    fn a_registry_refusal_is_reported_and_writes_nothing() {
        let manifest = manifest();
        let mut t = terms(&manifest, operator());
        t.merkle_proof = None;
        let err = open_without_write(funded(5_000_000, 5_000_000), &t, payer(), 0, 0).unwrap_err();
        assert!(err.contains("open_deal failed"), "got {err:?}");
    }

    #[test]
    fn a_bond_below_the_minimum_is_refused_without_a_write() {
        let manifest = manifest();
        let mut t = terms(&manifest, operator());
        t.economics.operator_bond = BOND - 1;
        let err = open_without_write(funded(5_000_000, 5_000_000), &t, payer(), 0, 0).unwrap_err();
        assert!(err.contains("open_deal failed"), "got {err:?}");
    }

    #[test]
    fn payer_as_operator_must_cover_fee_and_bond_together() {
        let manifest = manifest();
        let t = terms(&manifest, operator());
        let fee = fee_of(&t);
        assert!(fee > 0);

        let mut short = AccountState::new();
        short.add_balance(&operator(), fee + BOND - 1);
        let before = (
            short.get_balance(&operator()),
            short.storage_registry.root(),
        );
        let err = open_deal_escrowed(&mut short, &t, operator(), 0, BOND, 0)
            .expect_err("one unit short must be refused");
        assert!(err.contains("Insufficient operator balance"), "got {err:?}");
        assert_eq!(
            (
                short.get_balance(&operator()),
                short.storage_registry.root()
            ),
            before
        );

        let mut exact = AccountState::new();
        exact.add_balance(&operator(), fee + BOND);
        open_deal_escrowed(&mut exact, &t, operator(), 0, BOND, 0).unwrap();
        assert_eq!(exact.get_balance(&operator()), 0);
    }

    #[test]
    fn the_payer_reserve_is_required_but_not_spent() {
        let manifest = manifest();
        let t = terms(&manifest, operator());
        let fee = fee_of(&t);
        let reserve = 7;

        let err = open_without_write(
            funded(fee + reserve - 1, 5_000_000),
            &t,
            payer(),
            0,
            reserve,
        )
        .unwrap_err();
        assert!(err.contains("Insufficient payer balance"), "got {err:?}");

        let mut state = funded(fee + reserve, 5_000_000);
        open_deal_escrowed(&mut state, &t, payer(), 0, BOND, reserve).unwrap();
        assert_eq!(state.get_balance(&payer()), reserve);
        assert_eq!(state.get_balance(&operator()), 5_000_000 - BOND);
    }

    /// The finding: the escrow left balances with no supply-denominator
    /// counterpart, so every open deal looked like supply destruction and
    /// opened that much minting headroom under the fixed cap.
    #[test]
    fn an_open_deal_moves_supply_into_escrow_without_changing_what_is_committed() {
        let manifest = manifest();
        let t = terms(&manifest, operator());
        let mut state = funded(5_000_000, 5_000_000);
        let committed = state.total_bud_committed();
        let capacity = state.supply_capacity_remaining();
        let deal_id = open_deal_escrowed(&mut state, &t, payer(), 0, BOND, 0).expect("opens");
        let deal = state.storage_registry.get_deal(deal_id).expect("deal");
        // The escrow holds the client fee and the operator bond, both of which
        // left balances; committed supply and the remaining capacity do not
        // move, which is the invariant the escrow term exists for.
        assert!(deal.total_fee(deal.duration_epochs()) > 0 && BOND > 0);
        assert_eq!(state.total_bud_committed(), committed);
        assert_eq!(state.supply_capacity_remaining(), capacity);
    }

    #[test]
    fn the_escrow_equals_the_fee_the_deal_records() {
        let manifest = manifest();
        let t = terms(&manifest, operator());
        let mut state = funded(5_000_000, 5_000_000);
        let deal_id = open_deal_escrowed(&mut state, &t, payer(), 0, BOND, 0).unwrap();
        let deal = state.storage_registry.get_deal(deal_id).unwrap();
        assert_eq!(deal.status, DealStatus::Active);
        let epochs = t.end_epoch - t.start_epoch;
        assert!(deal.total_fee(epochs) > 0);
        assert_eq!(
            state.get_balance(&payer()),
            5_000_000 - deal.total_fee(epochs)
        );
        assert_eq!(state.get_balance(&operator()), 5_000_000 - BOND);
    }
    #[test]
    fn payer_as_operator_must_also_keep_the_reserve() {
        let manifest = manifest();
        let t = terms(&manifest, operator());
        let fee = fee_of(&t);
        // Covers fee + bond and, separately, fee + reserve, but not all three.
        let reserve = BOND;
        let mut state = AccountState::new();
        state.add_balance(&operator(), fee + BOND);
        let before = (
            state.get_balance(&operator()),
            state.storage_registry.root(),
        );
        let err = open_deal_escrowed(&mut state, &t, operator(), 0, BOND, reserve)
            .expect_err("fee, reserve and bond together must be covered");
        assert!(err.contains("Insufficient operator balance"), "got {err:?}");
        assert_eq!(
            (
                state.get_balance(&operator()),
                state.storage_registry.root()
            ),
            before,
            "a refusal must not write"
        );

        let mut enough = AccountState::new();
        enough.add_balance(&operator(), fee + BOND + reserve);
        open_deal_escrowed(&mut enough, &t, operator(), 0, BOND, reserve).unwrap();
        assert_eq!(enough.get_balance(&operator()), reserve);
    }

    /// A hybrid manifest listing 13 bytes of which 4 are held, so the held
    /// price and the listed price differ.
    fn hybrid_manifest(prefix_bytes: u32) -> ContentManifest {
        use crate::storage::generated::{ContentSource, GeneratedSpec, GeneratorId};
        let spec = GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [7u8; 32],
            output_len: 32 * 32,
            step_budget: 8_000,
        };
        ContentManifest::from_bytes_sliced(b"prefixed cont", 13)
            .unwrap()
            .with_source(ContentSource::Hybrid { prefix_bytes, spec })
    }

    fn generated_manifest() -> ContentManifest {
        use crate::storage::generated::{
            generate_content, ContentSource, GeneratedSpec, GeneratorId,
        };
        let spec = GeneratedSpec {
            generator: GeneratorId::Avatar,
            seed: [7u8; 32],
            output_len: 32 * 32,
            step_budget: 8_000,
        };
        let bytes = generate_content(&spec).expect("the recipe must run");
        ContentManifest::from_bytes_sliced(&bytes, bytes.len() as u32)
            .unwrap()
            .with_source(ContentSource::Generated(spec))
    }

    /// One byte costs one base unit per epoch, so a fee reads as bytes times
    /// epochs.
    fn unit_rate_terms(manifest: &ContentManifest, operator: Address) -> DealOpenTerms<'_> {
        let mut t = terms(manifest, operator);
        t.economics.fee_per_byte_epoch = FEE_RATE_SCALE as u64;
        t
    }

    #[test]
    fn a_hybrid_deal_escrows_the_held_prefix_not_the_listed_size() {
        let manifest = hybrid_manifest(4);
        let t = unit_rate_terms(&manifest, operator());
        let epochs = t.end_epoch - t.start_epoch;
        let listed = shard_bytes(&manifest);
        assert_eq!(listed, 13);
        assert_ne!(
            t.economics.total_fee(4, epochs),
            t.economics.total_fee(listed, epochs)
        );

        let mut state = funded(5_000_000, 5_000_000);
        let deal_id = open_deal_escrowed(&mut state, &t, payer(), 0, BOND, 0).unwrap();
        let deal = state.storage_registry.get_deal(deal_id).unwrap();
        assert_eq!(deal.shard_bytes, 4);
        assert_eq!(deal.total_fee(epochs), 4 * epochs);
        assert_eq!(
            state.get_balance(&payer()),
            5_000_000 - deal.total_fee(epochs)
        );
        assert_eq!(state.get_balance(&operator()), 5_000_000 - BOND);
    }

    #[test]
    fn a_generated_deal_escrows_no_fee_but_locks_the_bond() {
        let manifest = generated_manifest();
        let t = unit_rate_terms(&manifest, operator());
        let epochs = t.end_epoch - t.start_epoch;
        assert!(
            t.economics.total_fee(shard_bytes(&manifest), epochs) > 0,
            "control: the listed size would not be free"
        );

        let mut state = funded(5_000_000, 5_000_000);
        let deal_id = open_deal_escrowed(&mut state, &t, payer(), 0, BOND, 0).unwrap();
        let deal = state.storage_registry.get_deal(deal_id).unwrap();
        assert_eq!(deal.shard_bytes, 0);
        assert_eq!(deal.total_fee(epochs), 0);
        assert_eq!(state.get_balance(&payer()), 5_000_000);
        assert_eq!(state.get_balance(&operator()), 5_000_000 - BOND);
    }

    #[test]
    fn a_hybrid_with_an_oversized_prefix_is_refused_without_a_write() {
        let manifest = hybrid_manifest(100);
        let t = unit_rate_terms(&manifest, operator());
        let err = open_without_write(funded(5_000_000, 5_000_000), &t, payer(), 0, 0).unwrap_err();
        assert!(err.contains("held_bytes refused the source"), "got {err:?}");
    }

    fn reallocation_terms(
        ticket_id: u64,
        replacement_operator: Address,
        manifest: &ContentManifest,
    ) -> ReallocationTerms {
        let t = unit_rate_terms(manifest, replacement_operator);
        ReallocationTerms {
            ticket_id,
            replacement_operator,
            start_epoch: t.start_epoch,
            end_epoch: t.end_epoch,
            economics: t.economics,
            merkle_proof: t.merkle_proof,
            storage_root: t.storage_root,
        }
    }

    /// A state holding the manifest and the sweep's ticket for its empty slot.
    fn state_with_ticket(
        manifest: &ContentManifest,
        payer_balance: u64,
        operator_balance: u64,
    ) -> (AccountState, u64) {
        let mut state = funded(payer_balance, operator_balance);
        state.storage_registry.register_manifest(manifest);
        let ticket_id = state
            .storage_registry
            .open_never_placed_ticket(42, manifest.manifest_id, manifest.shards[0].shard_id, 0, 1)
            .expect("the sweep's ticket opens for an empty slot");
        (state, ticket_id)
    }

    #[test]
    fn a_reallocation_whose_bond_check_fails_leaves_everything_unchanged() {
        let manifest = manifest();
        let (mut state, ticket_id) = state_with_ticket(&manifest, 5_000_000, BOND - 1);
        let terms = reallocation_terms(ticket_id, operator(), &manifest);
        let before = snapshot(&state);

        let err = accept_reallocation_escrowed(&mut state, &terms, payer(), 0, BOND, 0)
            .expect_err("a short operator cannot take the repair");
        assert!(err.contains("Insufficient operator balance"), "got {err:?}");
        assert_eq!(snapshot(&state), before, "the payer must not lose the fee");
        let ticket = state
            .storage_registry
            .get_reallocation_ticket(ticket_id)
            .unwrap();
        assert_eq!(ticket.status, ReallocationStatus::Pending);
    }

    #[test]
    fn a_reallocation_escrow_equals_the_recorded_fee_for_a_hybrid_manifest() {
        let manifest = hybrid_manifest(4);
        let (mut state, ticket_id) = state_with_ticket(&manifest, 5_000_000, 5_000_000);
        let terms = reallocation_terms(ticket_id, operator(), &manifest);
        let epochs = terms.end_epoch - terms.start_epoch;
        let listed = shard_bytes(&manifest);
        assert_ne!(
            terms.economics.total_fee(4, epochs),
            terms.economics.total_fee(listed, epochs)
        );

        let deal_id =
            accept_reallocation_escrowed(&mut state, &terms, payer(), 0, BOND, 0).unwrap();
        let deal = state.storage_registry.get_deal(deal_id).unwrap();
        assert_eq!(deal.shard_bytes, 4);
        assert_eq!(deal.total_fee(epochs), 4 * epochs);
        assert_eq!(
            state.get_balance(&payer()),
            5_000_000 - deal.total_fee(epochs)
        );
        assert_eq!(state.get_balance(&operator()), 5_000_000 - BOND);
    }

    #[test]
    fn a_reallocation_to_a_cooled_down_operator_is_refused_without_a_write() {
        let manifest = manifest();
        let (mut state, ticket_id) = state_with_ticket(&manifest, 5_000_000, 5_000_000);
        state
            .storage_registry
            .begin_operator_cooldown(operator(), 100);
        let terms = reallocation_terms(ticket_id, operator(), &manifest);
        let before = snapshot(&state);
        let err = accept_reallocation_escrowed(&mut state, &terms, payer(), 200, BOND, 0)
            .expect_err("the cooldown applies to repairs too");
        assert!(err.contains("missed a challenge"), "got {err:?}");
        assert_eq!(snapshot(&state), before);
    }
}
