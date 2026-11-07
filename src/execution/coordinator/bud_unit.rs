//! Unified BUD unit accounting across execution environments.
//!
//! Every account holds whole atoms (`balance: u64`, `10^-6` BUD) plus a
//! fractional sub-atom field (`frac_attos: u64 < 10^12`, `10^-18` BUD). The
//! canonical value of an account is `balance * 10^12 + frac_attos` attoBUD.
//!
//! Each execution environment views and transfers BUD at its native decimal
//! precision:
//!
//! * `EVM` (`0x01`): `wei` (18 decimals, quantum `1` attoBUD)
//! * `SVM` (`0x03`): `lamport` (9 decimals, quantum `10^9` attoBUD)
//! * `Move` (`0x04`): `octa` (8 decimals, quantum `10^10` attoBUD)
//! * `WASM` (`0x02`): `ubud` (6 decimals, quantum `10^12` attoBUD)
//! * `BudZero` (`0x00`): `atom` (6 decimals, quantum `10^12` attoBUD)
//! Convenience: public attoBUD sub-unit quantum and conservation arithmetic surface (WP-26).

use std::fmt;

use budlum_uel_abi::{BudAmount, EeId};

use crate::core::account::{Account, AccountState, ATTO_PER_ATOM};
use crate::core::address::Address;

/// AttoBUD quantum for SVM (`lamport`, `10^-9` BUD = `10^9` attoBUD).
pub(crate) const ATTO_PER_LAMPORT: u128 = 1_000_000_000;
/// AttoBUD quantum for Move (`octa`, `10^-8` BUD = `10^10` attoBUD).
pub(crate) const ATTO_PER_OCTA: u128 = 10_000_000_000;

/// Refusal reasons for attoBUD conversion and transfer operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BudUnitError {
    /// Account carried `frac_attos >= 10^12`.
    InvalidFraction,
    /// Unknown execution environment id.
    UnknownEnvironment(EeId),
    /// Transfer amount is not an exact multiple of the environment's unit quantum.
    NonIntegralEnvironmentUnit { ee: EeId, quantum_attos: u128 },
    /// Sender lacks sufficient attoBUD balance.
    InsufficientBalance,
    /// Recipient balance or conversion overflowed `u64` atoms / `u128` attoBUD.
    BalanceOverflow,
}

impl fmt::Display for BudUnitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidFraction => write!(f, "account frac_attos must be below 10^12"),
            Self::UnknownEnvironment(ee) => {
                write!(f, "unknown execution environment 0x{:02x}", ee.0)
            }
            Self::NonIntegralEnvironmentUnit { ee, quantum_attos } => write!(
                f,
                "amount is not divisible by environment 0x{:02x} quantum ({quantum_attos} attoBUD)",
                ee.0
            ),
            Self::InsufficientBalance => write!(f, "insufficient attoBUD balance"),
            Self::BalanceOverflow => write!(f, "attoBUD balance overflow"),
        }
    }
}

impl std::error::Error for BudUnitError {}

/// Minimum transferable quantum in attoBUD for `ee`.
pub(crate) fn quantum_attos(ee: EeId) -> Result<u128, BudUnitError> {
    match ee {
        EeId::EVM => Ok(1),
        EeId::SVM => Ok(ATTO_PER_LAMPORT),
        EeId::MOVE => Ok(ATTO_PER_OCTA),
        EeId::WASM | EeId::BUDZERO => Ok(u128::from(ATTO_PER_ATOM)),
        other => Err(BudUnitError::UnknownEnvironment(other)),
    }
}

/// Exact attoBUD balance of `account`, verifying `frac_attos < 10^12`.
pub fn account_bud_amount(account: &Account) -> Result<BudAmount, BudUnitError> {
    if account.frac_attos >= ATTO_PER_ATOM {
        return Err(BudUnitError::InvalidFraction);
    }
    let whole = u128::from(account.balance)
        .checked_mul(u128::from(ATTO_PER_ATOM))
        .ok_or(BudUnitError::BalanceOverflow)?;
    let total = whole
        .checked_add(u128::from(account.frac_attos))
        .ok_or(BudUnitError::BalanceOverflow)?;
    Ok(BudAmount(total))
}

/// Balance visible inside `ee` in `ee`'s own smallest unit (`wei`, `lamport`,
/// `octa`, `ubud`, or `atom`).
pub(crate) fn visible_in_ee(account: &Account, ee: EeId) -> Result<u128, BudUnitError> {
    let total = account_bud_amount(account)?.0;
    let quantum = quantum_attos(ee)?;
    Ok(total / quantum)
}

/// Split an `attos` amount into `(whole_atoms, frac_attos)` with `frac_attos < 10^12`.
pub(crate) fn split_attos(attos: u128) -> Result<(u64, u64), BudUnitError> {
    let scale = u128::from(ATTO_PER_ATOM);
    let atoms_u128 = attos / scale;
    let frac_u128 = attos % scale;
    let atoms = u64::try_from(atoms_u128).map_err(|_| BudUnitError::BalanceOverflow)?;
    let frac = u64::try_from(frac_u128).map_err(|_| BudUnitError::BalanceOverflow)?;
    Ok((atoms, frac))
}

/// Checked subtraction `(balance, frac_attos) - (delta_atoms, delta_frac)`.
pub(crate) fn checked_sub_pair(
    balance: u64,
    frac_attos: u64,
    delta_atoms: u64,
    delta_frac: u64,
) -> Result<(u64, u64), BudUnitError> {
    if frac_attos >= ATTO_PER_ATOM || delta_frac >= ATTO_PER_ATOM {
        return Err(BudUnitError::InvalidFraction);
    }
    let (borrow, new_frac) = if frac_attos < delta_frac {
        (1u64, frac_attos + ATTO_PER_ATOM - delta_frac)
    } else {
        (0u64, frac_attos - delta_frac)
    };
    let new_balance = balance
        .checked_sub(delta_atoms)
        .and_then(|b| b.checked_sub(borrow))
        .ok_or(BudUnitError::InsufficientBalance)?;
    Ok((new_balance, new_frac))
}

/// Checked addition `(balance, frac_attos) + (delta_atoms, delta_frac)`.
pub(crate) fn checked_add_pair(
    balance: u64,
    frac_attos: u64,
    delta_atoms: u64,
    delta_frac: u64,
) -> Result<(u64, u64), BudUnitError> {
    if frac_attos >= ATTO_PER_ATOM || delta_frac >= ATTO_PER_ATOM {
        return Err(BudUnitError::InvalidFraction);
    }
    let sum_frac = frac_attos + delta_frac;
    let (carry, new_frac) = if sum_frac >= ATTO_PER_ATOM {
        (1u64, sum_frac - ATTO_PER_ATOM)
    } else {
        (0u64, sum_frac)
    };
    let new_balance = balance
        .checked_add(delta_atoms)
        .and_then(|b| b.checked_add(carry))
        .ok_or(BudUnitError::BalanceOverflow)?;
    Ok((new_balance, new_frac))
}

/// Conservation-preserving transfer of `attos` attoBUD in `state` under `ee`'s
/// unit divisibility rule, returning the recipient's updated visible balance in
/// `ee`'s native unit (truncated to `u64::MAX` when above `u64` for EVM wei).
///
/// Convenience: called by the execution coordinator when settling EE transfers.
pub fn transfer_atto_bud_in_state(
    state: &mut AccountState,
    from: &Address,
    to: &Address,
    ee: EeId,
    attos: u128,
) -> Result<u64, BudUnitError> {
    let quantum = quantum_attos(ee)?;
    if attos % quantum != 0 {
        return Err(BudUnitError::NonIntegralEnvironmentUnit {
            ee,
            quantum_attos: quantum,
        });
    }
    let (delta_atoms, delta_frac) = split_attos(attos)?;
    if from == to {
        let acct = state
            .accounts
            .get(from)
            .ok_or(BudUnitError::InsufficientBalance)?;
        let current = account_bud_amount(acct)?.0;
        if current < attos {
            return Err(BudUnitError::InsufficientBalance);
        }
        let vis = visible_in_ee(acct, ee)?;
        return Ok(u64::try_from(vis).unwrap_or(u64::MAX));
    }

    let sender_snapshot = state
        .accounts
        .get(from)
        .ok_or(BudUnitError::InsufficientBalance)?;
    let (next_from_bal, next_from_frac) = checked_sub_pair(
        sender_snapshot.balance,
        sender_snapshot.frac_attos,
        delta_atoms,
        delta_frac,
    )?;

    let (to_bal, to_frac) = state
        .accounts
        .get(to)
        .map_or((0u64, 0u64), |acct| (acct.balance, acct.frac_attos));
    let (next_to_bal, next_to_frac) = checked_add_pair(to_bal, to_frac, delta_atoms, delta_frac)?;

    if let Some(sender_mut) = state.accounts.get_mut(from) {
        sender_mut.balance = next_from_bal;
        sender_mut.frac_attos = next_from_frac;
    }
    state.mark_dirty(from);

    let recipient_mut = state.get_or_create(to);
    recipient_mut.balance = next_to_bal;
    recipient_mut.frac_attos = next_to_frac;
    let vis = visible_in_ee(recipient_mut, ee)?;
    state.mark_dirty(to);

    Ok(u64::try_from(vis).unwrap_or(u64::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(tag: u8) -> Address {
        Address([tag; 32])
    }

    #[test]
    fn frac_attos_stays_below_1e12() {
        let mut state = AccountState::new();
        let alice = addr(1);
        let bob = addr(2);
        state.accounts.insert(alice, Account::with_balance(alice, 5));
        state.accounts.insert(bob, Account::with_balance(bob, 0));

        // 750_000_000_000 + 750_000_000_000 = 1 atom + 500_000_000_000 frac_attos.
        let step = 750_000_000_000u128;
        state
            .transfer_atto_bud(&alice, &bob, EeId::EVM, step)
            .unwrap();
        assert_eq!(state.accounts[&alice].balance, 4);
        assert_eq!(state.accounts[&alice].frac_attos, 250_000_000_000);
        assert_eq!(state.accounts[&bob].balance, 0);
        assert_eq!(state.accounts[&bob].frac_attos, 750_000_000_000);

        state
            .transfer_atto_bud(&alice, &bob, EeId::EVM, step)
            .unwrap();
        assert_eq!(state.accounts[&alice].balance, 3);
        assert_eq!(state.accounts[&alice].frac_attos, 500_000_000_000);
        assert_eq!(state.accounts[&bob].balance, 1);
        assert_eq!(state.accounts[&bob].frac_attos, 500_000_000_000);

        for acct in state.accounts.values() {
            assert!(acct.frac_attos < ATTO_PER_ATOM);
        }

        // Corrupting frac_attos >= 10^12 is refused fail-closed.
        let bad = Account {
            public_key: addr(9),
            balance: 1,
            nonce: 0,
            frac_attos: ATTO_PER_ATOM,
        };
        assert_eq!(account_bud_amount(&bad), Err(BudUnitError::InvalidFraction));
    }

    #[test]
    fn uel_bud_conservation() {
        let mut state = AccountState::new();
        let a = addr(10);
        let b = addr(11);
        let c = addr(12);
        state.accounts.insert(a, Account::with_balance(a, 1_000));
        state.accounts.insert(b, Account::with_balance(b, 250));
        state.accounts.insert(c, Account::with_balance(c, 0));

        let initial_attos = state.total_atto_bud_committed();
        let initial_committed_ceiling = state.total_bud_committed();
        assert_eq!(initial_attos, 1_250u128 * u128::from(ATTO_PER_ATOM));

        // EVM wei-granularity transfer (1 wei = 1 attoBUD).
        state.transfer_atto_bud(&a, &b, EeId::EVM, 1).unwrap();
        assert_eq!(state.total_atto_bud_committed(), initial_attos);
        // Ceiling supply in atoms cannot drop below initial committed atoms!
        assert!(state.total_bud_committed() >= initial_committed_ceiling);

        // SVM lamport-granularity transfer (3 lamports = 3 * 10^9 attoBUD).
        state
            .transfer_atto_bud(&b, &c, EeId::SVM, 3 * ATTO_PER_LAMPORT)
            .unwrap();
        assert_eq!(state.total_atto_bud_committed(), initial_attos);

        // Move octa-granularity transfer (7 octas = 7 * 10^10 attoBUD).
        state
            .transfer_atto_bud(&a, &c, EeId::MOVE, 7 * ATTO_PER_OCTA)
            .unwrap();
        assert_eq!(state.total_atto_bud_committed(), initial_attos);

        // WASM ubud transfer (2 ubud = 2 * 10^12 attoBUD).
        state
            .transfer_atto_bud(&c, &a, EeId::WASM, 2 * u128::from(ATTO_PER_ATOM))
            .unwrap();
        assert_eq!(state.total_atto_bud_committed(), initial_attos);

        // Non-integral SVM transfer (1 wei) is refused without mutating balances.
        let snap_b = state.accounts[&b].clone();
        let err = state.transfer_atto_bud(&b, &c, EeId::SVM, 1);
        assert_eq!(
            err,
            Err(BudUnitError::NonIntegralEnvironmentUnit {
                ee: EeId::SVM,
                quantum_attos: ATTO_PER_LAMPORT,
            })
        );
        assert_eq!(state.accounts[&b].balance, snap_b.balance);
        assert_eq!(state.accounts[&b].frac_attos, snap_b.frac_attos);
        assert_eq!(state.total_atto_bud_committed(), initial_attos);
    }

    #[test]
    fn blg_256_environment_views_and_state_root_bind_frac_attos() {
        let acct = Account {
            public_key: addr(3),
            balance: 12,
            nonce: 1,
            frac_attos: 345_000_000_789,
        };
        assert_eq!(
            visible_in_ee(&acct, EeId::EVM).unwrap(),
            12_345_000_000_789u128
        );
        assert_eq!(visible_in_ee(&acct, EeId::SVM).unwrap(), 12_345u128);
        assert_eq!(visible_in_ee(&acct, EeId::MOVE).unwrap(), 1_234u128);
        assert_eq!(visible_in_ee(&acct, EeId::WASM).unwrap(), 12u128);
        assert_eq!(visible_in_ee(&acct, EeId::BUDZERO).unwrap(), 12u128);

        let mut s1 = AccountState::new();
        let k = addr(4);
        s1.accounts.insert(k, Account::with_balance(k, 10));
        let root_zero_frac = s1.calculate_state_root();

        s1.transfer_atto_bud(&k, &addr(5), EeId::EVM, 1).unwrap();
        let root_with_frac = s1.calculate_state_root();
        assert_ne!(root_zero_frac, root_with_frac);

        // Full rebuild and incremental dirty-leaf rebuild agree on frac_attos.
        let mut s2 = AccountState::new();
        for (addr_k, acc_v) in &s1.accounts {
            s2.accounts.insert(*addr_k, acc_v.clone());
        }
        assert_eq!(root_with_frac, s2.calculate_state_root());
    }
}
