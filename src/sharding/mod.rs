//! State-machine sharding with atomic cross-shard commits.
//!
//! Whitepaper v1.3: horizontal partitioning of the state machine with
//! cross-shard atomic commits backed by BLS finality.
//!
//! * The address space is partitioned deterministically into `num_shards`
//!   shards ([`shard_of`]), so the state machine is horizontally partitioned
//!   by construction.
//! * Every shard has its own Merkle root ([`shard_state_root`]), computed
//!   with the exact leaf format `AccountState::calculate_state_root` uses, so
//!   a shard root is comparable with the whole-state root.
//! * A single commitment over all shard roots ([`shards_commitment`]) is
//!   folded into the block header (`Block::shards_root`) and therefore into
//!   the block hash the BLS finality certificate seals: after activation, a
//!   validator rejects any block whose shards commitment does not match the
//!   replayed state.
//! * A transfer between two shards is a single state transition: the source
//!   shard is debited and the destination shard credited in one
//!   `apply_transaction` call, so the pair commits together or not at all
//!   ([`apply_cross_shard_transfer`]).
//!
//! Activation is a configuration decision (`ShardingConfig`), pinned before
//! a chain starts; the per-shard roots and the commitment are pure functions
//! of state, so every node computes identical values.

use sha2::{Digest, Sha256};

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType};

/// Maximum shard count, kept small so per-shard roots stay cheap to compute.
pub const MAX_SHARDS: u16 = 64;

/// A shard identifier: an index in `[0, num_shards)`.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct ShardId(pub u16);

/// State-machine sharding parameters, pinned before a chain starts.
///
/// Sharding is a consensus parameter: every node must agree on whether it is
/// enabled, how many shards partition the state, and from which height the
/// commitment becomes mandatory. The default is disabled, so existing chains
/// see no change; a chain that activates it commits `shards_root` in every
/// block from `activation_height` onward, and every validator enforces it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ShardingConfig {
    /// Whether state-machine sharding is enabled at all.
    pub enabled: bool,
    /// Number of shards partitioning the address space.
    pub num_shards: u16,
    /// First block height at which the shards commitment is mandatory.
    pub activation_height: u64,
}

impl Default for ShardingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            num_shards: 1,
            activation_height: 0,
        }
    }
}

impl ShardingConfig {
    /// Whether the shards commitment is mandatory at `height`.
    ///
    /// Requires the feature to be enabled, at least two shards (one shard is
    /// the unsharded state), and the height to have reached activation.
    #[must_use]
    pub const fn is_active_at(&self, height: u64) -> bool {
        self.enabled && self.num_shards >= 2 && height >= self.activation_height
    }
}

/// Deterministic partition of the address space into `num_shards` shards.
///
/// The first byte of the address modulo the shard count. This is stable
/// across nodes and blocks and does not depend on insertion order, so every
/// node partitions identically. `num_shards` is clamped to `[1, MAX_SHARDS]`
/// so a misconfigured value cannot produce an empty partition.
#[must_use]
pub fn shard_of(address: &Address, num_shards: u16) -> ShardId {
    let num_shards = num_shards.clamp(1, MAX_SHARDS);
    ShardId(u16::from(address.0[0]) % num_shards)
}

/// The shard a transaction is authored in: the shard of its `from` address.
#[must_use]
pub fn tx_source_shard(tx: &Transaction, num_shards: u16) -> ShardId {
    shard_of(&tx.from, num_shards)
}

/// The shard a transfer credits.
#[must_use]
pub fn tx_destination_shard(tx: &Transaction, num_shards: u16) -> Option<ShardId> {
    match tx.tx_type {
        TransactionType::Transfer => Some(shard_of(&tx.to, num_shards)),
        _ => None,
    }
}

/// Whether a transaction moves value between two different shards.
#[must_use]
pub fn is_cross_shard(tx: &Transaction, num_shards: u16) -> bool {
    tx_destination_shard(tx, num_shards)
        .is_some_and(|destination| destination != tx_source_shard(tx, num_shards))
}

/// The digest of one account in the same format `calculate_state_root` uses.
fn account_leaf(address: &Address, balance: u64, nonce: u64) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(address.0);
    hasher.update(balance.to_le_bytes());
    hasher.update(nonce.to_le_bytes());
    hasher.finalize().into()
}

/// Internal node digest in the same format `calculate_state_root` uses.
fn internal_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// The Merkle root over the accounts of one shard, in `calculate_state_root`
/// leaf format. Accounts are iterated in address order (the state map is a
/// `BTreeMap`), so the root is deterministic.
///
/// An empty shard roots to the SHA256 of the empty leaf layer, mirroring the
/// whole-state tree's handling of empty state.
#[must_use]
pub fn shard_state_root(state: &AccountState, shard: ShardId, num_shards: u16) -> [u8; 32] {
    let mut leaves: Vec<[u8; 32]> = state
        .accounts
        .iter()
        .filter(|(address, _)| shard_of(address, num_shards) == shard)
        .map(|(address, account)| account_leaf(address, account.balance, account.nonce))
        .collect();
    if leaves.is_empty() {
        return internal_node(&[0u8; 32], &[0u8; 32]);
    }
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        let mut i = 0;
        while i < leaves.len() {
            let left = leaves[i];
            let right = if i + 1 < leaves.len() {
                leaves[i + 1]
            } else {
                left
            };
            next.push(internal_node(&left, &right));
            i += 2;
        }
        leaves = next;
    }
    leaves[0]
}

/// The commitment over all per-shard roots, in shard order.
///
/// This is the value a block header carries in `Block::shards_root` when
/// sharding is active; because it is a deterministic function of state, the
/// validator re-computes it on replay and rejects a block that commits to
/// anything else.
#[must_use]
pub fn shards_commitment(state: &AccountState, num_shards: u16) -> [u8; 32] {
    let num_shards = num_shards.clamp(1, MAX_SHARDS);
    let mut leaves: Vec<[u8; 32]> = (0..num_shards)
        .map(|shard| shard_state_root(state, ShardId(shard), num_shards))
        .collect();
    while leaves.len() > 1 {
        let mut next = Vec::with_capacity(leaves.len().div_ceil(2));
        let mut i = 0;
        while i < leaves.len() {
            let left = leaves[i];
            let right = if i + 1 < leaves.len() {
                leaves[i + 1]
            } else {
                left
            };
            next.push(internal_node(&left, &right));
            i += 2;
        }
        leaves = next;
    }
    leaves[0]
}

/// Apply a cross-shard transfer atomically.
///
/// The transfer is validated before any mutation and both the source debit
/// and the destination credit happen in this one call against the same
/// state, so the pair either commits together or not at all. This is the
/// "atomic cross-shard commit" of the whitepaper: the shard roots are only
/// ever observed in the state after the whole transfer, never in a
/// half-applied intermediate.
///
/// This mirrors the executor's `Transfer` handling; the function exists so
/// the shard boundary is explicit and testable, and so callers that route by
/// shard have one place to go through.
///
/// # Errors
///
/// Returns an error when the transaction is not a cross-shard `Transfer`,
/// when the sender cannot cover the total cost, or when the receiver balance
/// would overflow.
///
/// # Panics
///
/// Panics only if a checked arithmetic step that was validated above fails
/// between the validation and the mutation, which the checks make
/// unreachable.
pub fn apply_cross_shard_transfer(
    state: &mut AccountState,
    tx: &Transaction,
    num_shards: u16,
) -> Result<(), String> {
    if !is_cross_shard(tx, num_shards) {
        return Err("apply_cross_shard_transfer requires a cross-shard transfer".into());
    }
    if tx.tx_type != TransactionType::Transfer {
        return Err("apply_cross_shard_transfer requires a Transfer".into());
    }

    let total_cost = tx.total_cost();
    let sender = state.get_or_create(&tx.from);
    if sender.balance < total_cost {
        return Err("insufficient balance for cross-shard transfer".into());
    }
    let receiver = state.get_or_create(&tx.to);
    receiver
        .balance
        .checked_add(tx.amount)
        .ok_or_else(|| "receiver balance overflow on cross-shard transfer".to_string())?;

    // Both mutations below are infallible after the checks above.
    // The checks above establish both, but this is a transaction-execution
    // path: a panic here is a halted chain, so an arithmetic surprise is
    // reported as a rejected transaction instead.
    let sender = state.get_or_create(&tx.from);
    sender.balance = sender
        .balance
        .checked_sub(total_cost)
        .ok_or("shard transfer: sender balance underflow")?;
    sender.nonce = sender.nonce.saturating_add(1);
    let receiver = state.get_or_create(&tx.to);
    receiver.balance = receiver
        .balance
        .checked_add(tx.amount)
        .ok_or("shard transfer: receiver balance overflow")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::transaction::{Transaction, DEFAULT_CHAIN_ID};

    fn addr(first: u8) -> Address {
        Address::from([first; 32])
    }

    fn transfer(from: Address, to: Address, amount: u64, fee: u64) -> Transaction {
        Transaction::new_with_chain_id(
            from,
            to,
            amount,
            fee,
            0,
            Vec::new(),
            DEFAULT_CHAIN_ID,
            TransactionType::Transfer,
        )
    }

    #[test]
    fn partition_is_deterministic_and_stable() {
        let num_shards = 8;
        for first in 0..=255u8 {
            let address = addr(first);
            assert_eq!(
                shard_of(&address, num_shards),
                shard_of(&address, num_shards),
                "same address, same shard"
            );
            assert!(shard_of(&address, num_shards).0 < num_shards);
        }
    }

    #[test]
    fn shard_count_is_clamped() {
        assert_eq!(shard_of(&addr(200), 0).0, 0);
        assert!(shard_of(&addr(250), u16::MAX).0 < MAX_SHARDS);
    }

    #[test]
    fn cross_shard_detection() {
        let num_shards = 4;
        let same = transfer(addr(0), addr(4), 10, 1); // both in shard 0
        assert!(!is_cross_shard(&same, num_shards));
        let cross = transfer(addr(0), addr(1), 10, 1); // shard 0 -> shard 1
        assert!(is_cross_shard(&cross, num_shards));
        assert_eq!(tx_source_shard(&cross, num_shards), ShardId(0));
        assert_eq!(tx_destination_shard(&cross, num_shards), Some(ShardId(1)));
    }

    #[test]
    fn per_shard_roots_are_disjoint_and_deterministic() {
        let mut state = AccountState::new();
        state.get_or_create(&addr(0)).balance = 100;
        state.get_or_create(&addr(1)).balance = 200;
        state.get_or_create(&addr(2)).balance = 300;

        let num_shards = 4;
        let root0 = shard_state_root(&state, ShardId(0), num_shards);
        let root0_again = shard_state_root(&state, ShardId(0), num_shards);
        assert_eq!(root0, root0_again, "per-shard root must be deterministic");

        // Shard 0 holds addresses 0, 4, ... ; shard 1 holds 1, 5, ...
        let root1 = shard_state_root(&state, ShardId(1), num_shards);
        assert_ne!(root0, root1, "different shards must root differently");

        // Moving an account changes its shard's root and the commitment.
        let before = shards_commitment(&state, num_shards);
        let account = state.get_or_create(&addr(1));
        account.balance = 250;
        let after = shards_commitment(&state, num_shards);
        assert_ne!(before, after);
    }

    #[test]
    fn cross_shard_transfer_is_atomic() {
        let mut state = AccountState::new();
        state.get_or_create(&addr(0)).balance = 100;
        state.get_or_create(&addr(1)).balance = 0;

        let num_shards = 2;
        let tx = transfer(addr(0), addr(1), 40, 5);
        let before = shards_commitment(&state, num_shards);

        // A transfer that would overflow the receiver must change nothing.
        let overflow = transfer(addr(0), addr(1), u64::MAX, 5);
        let result = apply_cross_shard_transfer(&mut state, &overflow, num_shards);
        assert!(result.is_err());
        assert_eq!(
            shards_commitment(&state, num_shards),
            before,
            "failed transfer left state untouched"
        );
        assert_eq!(state.get_or_create(&addr(0)).balance, 100);

        // A valid transfer debits the source shard and credits the
        // destination shard in one atomic step.
        apply_cross_shard_transfer(&mut state, &tx, num_shards).expect("valid transfer applies");
        assert_eq!(state.get_or_create(&addr(0)).balance, 100 - 45);
        assert_eq!(state.get_or_create(&addr(1)).balance, 40);
        assert_eq!(state.get_or_create(&addr(0)).nonce, 1);
    }

    #[test]
    fn shard_only_operations_are_rejected_by_the_cross_shard_gate() {
        let mut state = AccountState::new();
        state.get_or_create(&addr(0)).balance = 100;
        let same_shard = transfer(addr(0), addr(4), 10, 1);
        assert!(apply_cross_shard_transfer(&mut state, &same_shard, 4).is_err());
    }

    #[test]
    fn shards_commitment_changes_when_any_shard_changes() {
        let mut state = AccountState::new();
        for first in 0..8u8 {
            state.get_or_create(&addr(first)).balance = u64::from(first) * 10;
        }
        let num_shards = 4;
        let before = shards_commitment(&state, num_shards);
        state.get_or_create(&addr(3)).balance += 1;
        let after = shards_commitment(&state, num_shards);
        assert_ne!(before, after);
    }
}
