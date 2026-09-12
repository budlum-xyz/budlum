//! The executor's vault arm and the folder locks on the two NFT doors.
//!
//! The membership semantics behind the arm live in `src/socialfi/vault.rs`
//! (registry refusals and the ownership reading, unit-tested there). What
//! this file pins is what only the block-application path can see: the
//! frame refusal for a value-carrying vault tx, the accounting epilogue,
//! and - the pair that makes the whole invariant hold - `NftTransfer` and
//! `NftBurn` refusing to strand a listing. The transfer door and the vault
//! door are one rule seen twice: nobody walks away from a folder leaving
//! somebody else's screen full of broken links.

use crate::core::account::AccountState;
use crate::core::address::Address;
use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
use crate::execution::executor::Executor;
use crate::socialfi::VaultTx;
use crate::storage::content_id::ContentId;

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

/// Alice with four minted tokens: ids 0..4 in registry order.
fn alice_state() -> (AccountState, Address, Vec<u64>) {
    let alice = addr(1);
    let mut state = AccountState::new();
    state.add_balance(&alice, 1_000);
    let mut ids = Vec::new();
    for (_i, tag) in ["folder-a", "token-1", "token-2", "folder-b"]
        .iter()
        .enumerate()
    {
        ids.push(
            state
                .nft_registry
                .mint(alice, ContentId::of(tag.as_bytes()), 0, None)
                .expect("mint on a fresh registry"),
        );
    }
    (state, alice, ids)
}

fn vault_tx(from: Address, body: VaultTx, nonce: u64) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        1,
        nonce,
        vec![],
        DEFAULT_CHAIN_ID,
        TransactionType::Vault(body),
    )
}

fn nft_data_tx(from: Address, data: Vec<u8>, tx_type: TransactionType, nonce: u64) -> Transaction {
    Transaction::new_with_chain_id(
        from,
        Address::zero(),
        0,
        1,
        nonce,
        data,
        DEFAULT_CHAIN_ID,
        tx_type,
    )
}

/// Both halves of the refusal: the code is what the assertions below read
/// (a refusal class), the message is what an operator reads. Dropping the
/// code here would make every `contains(...)` below vacuous.
fn apply(state: &mut AccountState, tx: Transaction) -> Result<(), String> {
    Executor::apply_transaction_checked(state, &tx)
        .map_err(|e| format!("{}: {}", e.code(), e.message()))
}

#[test]
fn the_vault_lifecycle_runs_end_to_end_through_the_executor() {
    let (mut state, alice, ids) = alice_state();
    let (folder_a, t1, t2, folder_b) = (ids[0], ids[1], ids[2], ids[3]);
    apply(
        &mut state,
        vault_tx(alice, VaultTx::RegisterFolder { folder: folder_a }, 0),
    )
    .unwrap();
    apply(
        &mut state,
        vault_tx(alice, VaultTx::RegisterFolder { folder: folder_b }, 1),
    )
    .unwrap();
    apply(
        &mut state,
        vault_tx(
            alice,
            VaultTx::AddMember {
                folder: folder_a,
                member: t1,
            },
            2,
        ),
    )
    .unwrap();
    apply(
        &mut state,
        vault_tx(
            alice,
            VaultTx::AddMember {
                folder: folder_a,
                member: t2,
            },
            3,
        ),
    )
    .unwrap();
    assert_eq!(state.vault.open(folder_a), Some(&[t1, t2][..]));
    apply(
        &mut state,
        vault_tx(
            alice,
            VaultTx::MoveMember {
                from: folder_a,
                to: folder_b,
                member: t2,
            },
            4,
        ),
    )
    .unwrap();
    assert_eq!(state.vault.open(folder_a), Some(&[t1][..]));
    assert_eq!(state.vault.open(folder_b), Some(&[t2][..]));
    apply(
        &mut state,
        vault_tx(
            alice,
            VaultTx::ExtractMember {
                folder: folder_b,
                member: t2,
            },
            5,
        ),
    )
    .unwrap();
    apply(
        &mut state,
        vault_tx(alice, VaultTx::CloseFolder { folder: folder_b }, 6),
    )
    .unwrap();
    assert!(!state.vault.is_folder(folder_b));
    // One fee and one nonce per accepted step; nothing else moved.
    assert_eq!(state.get_nonce(&alice), 7);
    assert_eq!(state.get_balance(&alice), 1_000 - 7);
}

#[test]
fn a_listed_token_cannot_be_transferred_or_burned_until_it_is_extracted() {
    let (mut state, alice, ids) = alice_state();
    let (folder, token) = (ids[0], ids[1]);
    apply(
        &mut state,
        vault_tx(alice, VaultTx::RegisterFolder { folder }, 0),
    )
    .unwrap();
    apply(
        &mut state,
        vault_tx(
            alice,
            VaultTx::AddMember {
                folder,
                member: token,
            },
            1,
        ),
    )
    .unwrap();

    let transfer = bincode::serialize(&(token, addr(7))).unwrap();
    let err = apply(
        &mut state,
        nft_data_tx(alice, transfer.clone(), TransactionType::NftTransfer, 2),
    )
    .expect_err("a listed token must not walk out of its folder");
    assert!(err.contains("vault_member_locked"), "{err}");
    let burn = bincode::serialize(&token).unwrap();
    let err = apply(
        &mut state,
        nft_data_tx(alice, burn.clone(), TransactionType::NftBurn, 3),
    )
    .expect_err("a listed token must not be burned under its folder");
    assert!(err.contains("vault_member_locked"), "{err}");

    // The refusals consumed nothing: nonce is where the two accepted steps
    // left it, and the listing is untouched.
    assert_eq!(state.get_nonce(&alice), 2);
    assert_eq!(state.vault.open(folder), Some(&[token][..]));

    // Extract, and the doors open.
    apply(
        &mut state,
        vault_tx(
            alice,
            VaultTx::ExtractMember {
                folder,
                member: token,
            },
            2,
        ),
    )
    .unwrap();
    apply(
        &mut state,
        nft_data_tx(alice, transfer, TransactionType::NftTransfer, 3),
    )
    .unwrap();
    assert_eq!(
        state.nft_registry.get_nft(token).map(|n| n.owner),
        Some(addr(7))
    );
}

#[test]
fn a_folder_with_contents_cannot_be_transferred_or_burned() {
    let (mut state, alice, ids) = alice_state();
    let (folder, token) = (ids[0], ids[1]);
    apply(
        &mut state,
        vault_tx(alice, VaultTx::RegisterFolder { folder }, 0),
    )
    .unwrap();
    apply(
        &mut state,
        vault_tx(
            alice,
            VaultTx::AddMember {
                folder,
                member: token,
            },
            1,
        ),
    )
    .unwrap();

    let transfer = bincode::serialize(&(folder, addr(7))).unwrap();
    let err = apply(
        &mut state,
        nft_data_tx(alice, transfer, TransactionType::NftTransfer, 2),
    )
    .expect_err("the container moves only empty: the list is not the container's to hand over");
    assert!(err.contains("vault_folder_not_empty"), "{err}");

    let burn = bincode::serialize(&folder).unwrap();
    let err = apply(
        &mut state,
        nft_data_tx(alice, burn, TransactionType::NftBurn, 3),
    )
    .expect_err("burning a full folder orphans the membership it names");
    assert!(err.contains("vault_folder_not_empty"), "{err}");
}

#[test]
fn the_frame_refuses_value_before_the_body_runs() {
    let (mut state, alice, ids) = alice_state();
    let mut tx = vault_tx(alice, VaultTx::RegisterFolder { folder: ids[0] }, 0);
    tx.amount = 5;
    let err = apply(&mut state, tx).expect_err("folders move ids, not value");
    assert!(err.contains("vault_amount_must_be_zero"), "{err}");
    assert!(state.vault.is_empty(), "and it registered nothing");
}

#[test]
fn somebody_elses_folder_reaches_the_frame_as_a_vault_refusal() {
    // The ownership reading is the body's; what the arm owes is that the
    // refusal SURFACES through block execution as a named failure, and the
    // would-be thief pays nothing.
    let (mut state, alice, ids) = alice_state();
    let bob = addr(2);
    state.add_balance(&bob, 100);
    apply(
        &mut state,
        vault_tx(alice, VaultTx::RegisterFolder { folder: ids[0] }, 0),
    )
    .unwrap();
    let err = apply(
        &mut state,
        vault_tx(
            bob,
            VaultTx::AddMember {
                folder: ids[0],
                member: ids[1],
            },
            0,
        ),
    )
    .expect_err("bob does not hold alice's folder");
    assert!(err.contains("vault_tx_failed"), "{err}");
    assert!(
        state.vault.open(ids[0]).is_some_and(|m| m.is_empty()),
        "the refusal wrote nothing"
    );
    assert_eq!(state.get_balance(&bob), 100, "and took nothing");
}
