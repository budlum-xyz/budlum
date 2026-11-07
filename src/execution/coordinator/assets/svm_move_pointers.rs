//! Stateless SVM (`SPL Token`) and Move (`fungible_asset` / `coin`) UAR pointers
//! across all four launch environments (`EVM`, `WASM`, `SVM`, `Move`).
//!
//! WIRING: unwired - staged for post-launch T-Expansion UAR pointer activation (WP-52).
//!
//! Design invariants:
//! - Every pointer contract/object holds zero local balance storage; balances live
//!   solely in the asset's home EE namespace (`Y-5`).
//! - Delegated spending allowances live solely in the asset's home EE ledger,
//!   never in the target pointer's local storage.
//! - Cross-EE reentrancy remains forbidden under the single-stack per-worker
//!   discipline (Section 8.7.3 rule 6 retained).

use crate::core::account::AccountState;
use crate::execution::coordinator::assets::{PointerDescriptor, POINTER_BYTECODE_PREFIX};
use budlum_uel_abi::EeId;
use sha3::{Digest, Sha3_256};

/// Public testnet chain id where post-launch UAR pointer expansion stays closed.
pub const PUBLIC_TESTNET_CHAIN_ID: u64 = 45_261;

/// Default activation height (`u64::MAX` = closed on public testnet until governance schedules).
pub const WP52_POINTER_ACTIVATION_HEIGHT: u64 = u64::MAX;

/// SVM pointer account namespace (`ee/svm/pointer_meta`, metadata-only, zero balance slots).
pub const NS_SVM_POINTER_META: &str = "ee/svm/pointer_meta";

/// Move pointer resource namespace (`ee/move/pointer_meta`, metadata-only, zero balance slots).
pub const NS_MOVE_POINTER_META: &str = "ee/move/pointer_meta";

/// Home-lived allowance namespace (`uel/home_allowance`).
pub const NS_HOME_ALLOWANCE: &str = "uel/home_allowance";

/// Derives the deterministic 32-byte SVM (`SPL`) or Move (`fungible_asset`) pointer address.
///
/// WIRING: exposed for post-launch T-Expansion activation.
pub fn derive_svm_or_move_pointer_id(
    asset_id: &[u8; 32],
    target_ee: EeId,
) -> Result<[u8; 32], &'static str> {
    if target_ee != EeId::SVM && target_ee != EeId::MOVE {
        return Err("target_ee_must_be_svm_or_move");
    }
    let mut h = Sha3_256::new();
    h.update(b"BDLM_UEL_POINTER_V1");
    h.update(asset_id);
    h.update([target_ee.0]);
    Ok(h.finalize().into())
}

/// Deploys a stateless SVM or Move UAR pointer descriptor (metadata-only; zero balance keys).
///
/// WIRING: exposed for post-launch T-Expansion activation.
pub fn deploy_svm_or_move_pointer(
    state: &mut AccountState,
    chain_id: u64,
    block_height: u64,
    activation_height: u64,
    target_ee: EeId,
    desc: &PointerDescriptor,
) -> Result<[u8; 32], &'static str> {
    if chain_id == PUBLIC_TESTNET_CHAIN_ID && block_height < activation_height {
        return Err("wp52_pointers_closed_on_testnet");
    }
    if desc.home_ee == target_ee.0 {
        return Err("cannot_create_pointer_in_home_ee");
    }
    let ptr_id = derive_svm_or_move_pointer_id(&desc.asset_id, target_ee)?;
    let ns = match target_ee {
        EeId::SVM => NS_SVM_POINTER_META,
        EeId::MOVE => NS_MOVE_POINTER_META,
        _ => return Err("target_ee_must_be_svm_or_move"),
    };
    let mut payload = Vec::from(POINTER_BYTECODE_PREFIX);
    payload.extend_from_slice(&desc.asset_id);
    payload.push(desc.home_ee);
    payload.push(desc.decimals);
    state.execution_state.kv_write(ns, &ptr_id, Some(payload));
    Ok(ptr_id)
}

/// Records an allowance strictly in the asset's home EE ledger (`uel/home_allowance`),
/// never inside any target pointer namespace.
///
/// WIRING: exposed for post-launch T-Expansion activation.
pub fn set_home_allowance(
    state: &mut AccountState,
    asset_id: &[u8; 32],
    home_ee: EeId,
    owner: &[u8; 32],
    spender: &[u8; 32],
    amount: u128,
) {
    let mut key = Vec::with_capacity(97);
    key.push(home_ee.0);
    key.extend_from_slice(asset_id);
    key.extend_from_slice(owner);
    key.extend_from_slice(spender);
    state
        .execution_state
        .kv_write(NS_HOME_ALLOWANCE, &key, Some(amount.to_le_bytes().to_vec()));
}

/// Reads the home-lived allowance for `(home_ee, asset_id, owner, spender)`.
///
/// WIRING: exposed for post-launch T-Expansion activation.
#[must_use]
pub fn read_home_allowance(
    state: &AccountState,
    asset_id: &[u8; 32],
    home_ee: EeId,
    owner: &[u8; 32],
    spender: &[u8; 32],
) -> u128 {
    let mut key = Vec::with_capacity(97);
    key.push(home_ee.0);
    key.extend_from_slice(asset_id);
    key.extend_from_slice(owner);
    key.extend_from_slice(spender);
    state
        .execution_state
        .kv_read(NS_HOME_ALLOWANCE, &key)
        .and_then(|raw| <[u8; 16]>::try_from(raw.as_slice()).ok())
        .map_or(0, u128::from_le_bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::execution::coordinator::assets::AssetStandard;
    use crate::execution::coordinator::state::{NS_MOVE_RESOURCE, NS_SVM_ACCOUNT};

    fn sample_descriptor(home_ee: EeId) -> PointerDescriptor {
        PointerDescriptor {
            asset_id: [0x52; 32],
            home_ee: home_ee.0,
            home_ref: vec![0xAA; 20],
            standard: AssetStandard::Fungible,
            decimals: 6,
            symbol: String::from("UBUD"),
            name: String::from("Universal Bud Asset"),
        }
    }

    #[test]
    fn svm_pointer_holds_no_balance() {
        let mut state = AccountState::new();
        let desc = sample_descriptor(EeId::EVM);

        // Closed by default on public testnet 45261.
        assert_eq!(
            deploy_svm_or_move_pointer(
                &mut state,
                PUBLIC_TESTNET_CHAIN_ID,
                100,
                WP52_POINTER_ACTIVATION_HEIGHT,
                EeId::SVM,
                &desc,
            ),
            Err("wp52_pointers_closed_on_testnet")
        );

        // Once activated, deploying an SVM SPL pointer writes zero balance entries in ee/svm/account.
        let ptr = deploy_svm_or_move_pointer(&mut state, 999, 10, 0, EeId::SVM, &desc)
            .expect("SVM pointer deploys once active");
        assert!(state.execution_state.kv_read(NS_SVM_POINTER_META, &ptr).is_some());
        assert!(
            state.execution_state.kv_read(NS_SVM_ACCOUNT, &ptr).is_none(),
            "SVM pointer must hold zero local balance state"
        );
    }

    #[test]
    fn move_pointer_holds_no_balance() {
        let mut state = AccountState::new();
        let desc = sample_descriptor(EeId::SVM);

        let ptr = deploy_svm_or_move_pointer(&mut state, 999, 10, 0, EeId::MOVE, &desc)
            .expect("Move pointer deploys once active");
        assert!(state.execution_state.kv_read(NS_MOVE_POINTER_META, &ptr).is_some());
        assert!(
            state.execution_state.kv_read(NS_MOVE_RESOURCE, &ptr).is_none(),
            "Move pointer must hold zero local coin/fungible_asset balance state"
        );
    }

    #[test]
    fn pointer_allowance_lives_at_home() {
        let mut state = AccountState::new();
        let owner = [0x11; 32];
        let spender = [0x22; 32];
        let svm_asset = [0xA1; 32];
        let move_asset = [0xB2; 32];

        set_home_allowance(&mut state, &svm_asset, EeId::SVM, &owner, &spender, 75_000);
        set_home_allowance(&mut state, &move_asset, EeId::MOVE, &owner, &spender, 120_000);

        assert_eq!(
            read_home_allowance(&state, &svm_asset, EeId::SVM, &owner, &spender),
            75_000
        );
        assert_eq!(
            read_home_allowance(&state, &move_asset, EeId::MOVE, &owner, &spender),
            120_000
        );
        // Querying under a non-home EE returns 0 because allowances never live at the pointer.
        assert_eq!(
            read_home_allowance(&state, &svm_asset, EeId::EVM, &owner, &spender),
            0
        );
        assert_eq!(
            read_home_allowance(&state, &move_asset, EeId::WASM, &owner, &spender),
            0
        );
    }
}
