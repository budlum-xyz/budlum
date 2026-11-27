//! Budlum settlement endpoint, SVM family.
//!
//! Custody and home calls are closed until departure and escape can return
//! assets. Only finalized checkpoint tracking remains available. The program
//! is deployed with the upgrade authority
//! set to none: no admin, no upgrade, no pause.
//!
//! Events follow the Anchor layout so standard indexers decode them:
//! `sol_log_data([discriminator ++ borsh(event)])`, with
//! `discriminator = sha256("event:<Name>")[..8]`. The layouts are pinned by
//! `src/object_layer/family/svm.rs`.

pub mod verifier;

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::{next_account_info, AccountInfo},
    clock::Clock,
    entrypoint,
    entrypoint::ProgramResult,
    hash::hash,
    log::sol_log_data,
    program_error::ProgramError,
    pubkey::Pubkey,
    sysvar::Sysvar,
};

pub const FUNGIBLE: u8 = 0;
pub const UNIQUE: u8 = 1;
/// Seconds without a newly accepted checkpoint before the exit opens.
pub const SILENCE_WINDOW_SECS: i64 = 1_209_600;
/// Custom error: release and escape open with the object-layer root opening.
pub const NOT_OPEN: u32 = 0x4255_0002;
pub const NOT_FINAL: u32 = 0x4255_0003;
pub const NOT_NEWER: u32 = 0x4255_0004;
pub const NOTHING_RECEIVED: u32 = 0x4255_0005;
pub const NOT_TOKEN_PROGRAM: u32 = 0x4255_0006;

/// SPL Token and Token-2022: the only programs whose balances are measured.
pub const TOKEN_PROGRAMS: [Pubkey; 2] = [
    solana_program::pubkey!("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"),
    solana_program::pubkey!("TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb"),
];

/// budlum/object-layer/arrive/v1
#[derive(BorshSerialize)]
pub struct ArriveEvent {
    pub kind: u8,
    pub mint: Pubkey,
    pub native_id: Option<Pubkey>,
    pub amount: u64,
    pub depositor: Pubkey,
    pub recipient: Option<[u8; 32]>,
}

/// budlum/object-layer/call/v1
#[derive(BorshSerialize)]
pub struct HomeCallEvent {
    pub sender: Pubkey,
    pub nonce: u64,
    pub calls: Vec<u8>,
}

/// budlum/object-layer/released/v1
#[derive(BorshSerialize)]
pub struct ReleasedEvent {
    pub departure_id: [u8; 32],
}

/// budlum/object-layer/escaped/v1
#[derive(BorshSerialize)]
pub struct EscapedEvent {
    pub kind: u8,
    pub mint: Pubkey,
    pub native_id: Option<Pubkey>,
    pub to: Pubkey,
}

/// The endpoint's state account (a PDA of this program, seed `b"endpoint"`).
#[derive(BorshSerialize, BorshDeserialize, Default)]
pub struct EndpointState {
    pub last_accepted_height: u64,
    pub last_accepted_at: i64,
}

/// One sender's nonce account (PDA, seeds `b"nonce"`, sender).
#[derive(BorshSerialize, BorshDeserialize, Default)]
pub struct NonceState {
    pub next: u64,
}

#[derive(BorshDeserialize)]
pub enum Instruction {
    /// Accounts: depositor (signer), depositor token account, vault token
    /// account, mint, token program. The amount logged is the vault's
    /// balance difference read after the transfer.
    Deposit {
        kind: u8,
        amount: u64,
        recipient: Option<[u8; 32]>,
        /// For a unique asset: the collection mint (the class).
        collection: Option<Pubkey>,
    },
    /// Accounts: sender (signer), sender's nonce PDA (writable).
    HomeCall {
        calls: Vec<u8>,
    },
    /// Accounts: verifier state PDA (writable, seed `b"verifier"`).
    InitVerifier {
        committee: verifier::CommitteeConfig,
    },
    /// Accounts: verifier state PDA (writable, seed `b"verifier"`), `sysvar::instructions`.
    RotateCommittee {
        handoff: verifier::CommitteeHandoffProof,
    },
    /// Accounts: verifier state PDA (writable, seed `b"verifier"`), `sysvar::instructions`.
    RecordCheckpoint {
        height: u64,
        state_root: [u8; 32],
        header_hash: [u8; 32],
        proof: verifier::SignedFinalityProof,
    },
    /// Accounts: endpoint state PDA (writable), verifier state PDA (seed `b"verifier"`).
    AcceptHeader {
        height: u64,
    },
    Release {
        proof: Vec<u8>,
    },
    Escape {
        proof: Vec<u8>,
    },
}

fn emit<E: BorshSerialize>(name: &str, event: &E) -> ProgramResult {
    let disc = hash(format!("event:{name}").as_bytes());
    let mut data = disc.to_bytes()[..8].to_vec();
    event
        .serialize(&mut data)
        .map_err(|_| ProgramError::InvalidAccountData)?;
    sol_log_data(&[&data]);
    Ok(())
}

fn token_amount(account: &AccountInfo) -> Result<u64, ProgramError> {
    // SPL token account layout: mint (32), owner (32), amount (u64 LE).
    let data = account.try_borrow_data()?;
    let bytes: [u8; 8] = data
        .get(64..72)
        .ok_or(ProgramError::InvalidAccountData)?
        .try_into()
        .map_err(|_| ProgramError::InvalidAccountData)?;
    Ok(u64::from_le_bytes(bytes))
}

fn load_account_state<T: BorshDeserialize + Default>(
    account: &AccountInfo,
) -> Result<T, ProgramError> {
    let data = account.try_borrow_data()?;
    if data.is_empty() {
        return Err(ProgramError::AccountDataTooSmall);
    }
    if data.iter().all(|&b| b == 0) {
        return Ok(T::default());
    }
    let mut rest: &[u8] = &data;
    let parsed = T::deserialize(&mut rest).map_err(|_| ProgramError::InvalidAccountData)?;
    if rest.iter().any(|&b| b != 0) {
        return Err(ProgramError::InvalidAccountData);
    }
    Ok(parsed)
}

fn save_account_state<T: BorshSerialize>(account: &AccountInfo, value: &T) -> ProgramResult {
    if !account.is_writable {
        return Err(ProgramError::InvalidArgument);
    }
    let mut data = account.try_borrow_mut_data()?;
    let mut cursor = std::io::Cursor::new(&mut data[..]);
    value
        .serialize(&mut cursor)
        .map_err(|_| ProgramError::AccountDataTooSmall)?;
    let written = cursor.position() as usize;
    data[written..].fill(0);
    Ok(())
}

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let instruction =
        Instruction::try_from_slice(input).map_err(|_| ProgramError::InvalidInstructionData)?;
    // Until the exit proofs exist, a vault transfer would be irreversible.
    // Refuse deposit and home-call events before touching any account.
    if matches!(
        &instruction,
        Instruction::Deposit { .. } | Instruction::HomeCall { .. }
    ) {
        return Err(ProgramError::Custom(NOT_OPEN));
    }
    let mut it = accounts.iter();
    match instruction {
        Instruction::Deposit {
            kind,
            amount,
            recipient,
            collection,
        } => {
            let depositor = next_account_info(&mut it)?;
            let from = next_account_info(&mut it)?;
            let vault = next_account_info(&mut it)?;
            let mint = next_account_info(&mut it)?;
            let token_program = next_account_info(&mut it)?;
            if !depositor.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            // The vault must be a token account of `mint`, owned by the
            // token program and held by this program's vault PDA; otherwise
            // a depositor could log an arrival into an account they control.
            let (vault_authority, _) = Pubkey::find_program_address(&[b"vault"], program_id);
            if !TOKEN_PROGRAMS.contains(token_program.key) {
                return Err(ProgramError::Custom(NOT_TOKEN_PROGRAM));
            }
            if vault.owner != token_program.key {
                return Err(ProgramError::IllegalOwner);
            }
            {
                let data = vault.try_borrow_data()?;
                let account_mint = data.get(0..32).ok_or(ProgramError::InvalidAccountData)?;
                let account_owner = data.get(32..64).ok_or(ProgramError::InvalidAccountData)?;
                if account_mint != mint.key.as_ref() || account_owner != vault_authority.as_ref() {
                    return Err(ProgramError::InvalidAccountData);
                }
            }
            let before = token_amount(vault)?;
            let ix = spl_transfer(
                token_program.key,
                from.key,
                vault.key,
                depositor.key,
                amount,
            );
            solana_program::program::invoke(
                &ix,
                &[
                    from.clone(),
                    vault.clone(),
                    depositor.clone(),
                    token_program.clone(),
                ],
            )?;
            let received = token_amount(vault)?.saturating_sub(before);
            if received == 0 {
                return Err(ProgramError::Custom(NOTHING_RECEIVED));
            }
            // The class of a unique asset is the collection its mint declares,
            // never a value the caller asserts. Refuse the unique path until
            // on-chain collection membership is read from the mint's metadata.
            let (class, native_id) = match (kind, collection) {
                (FUNGIBLE, None) => (*mint.key, None),
                (UNIQUE, Some(_)) if received == 1 => {
                    return Err(ProgramError::InvalidInstructionData);
                }
                _ => return Err(ProgramError::InvalidInstructionData),
            };
            emit(
                "ArriveEvent",
                &ArriveEvent {
                    kind,
                    mint: class,
                    native_id,
                    amount: received,
                    depositor: *depositor.key,
                    recipient,
                },
            )
        }
        Instruction::HomeCall { calls } => {
            let sender = next_account_info(&mut it)?;
            let nonce_account = next_account_info(&mut it)?;
            if !sender.is_signer {
                return Err(ProgramError::MissingRequiredSignature);
            }
            let (expected, _) =
                Pubkey::find_program_address(&[b"nonce", sender.key.as_ref()], program_id);
            if *nonce_account.key != expected || nonce_account.owner != program_id {
                return Err(ProgramError::InvalidSeeds);
            }
            if !nonce_account.is_writable {
                return Err(ProgramError::InvalidArgument);
            }
            let mut state: NonceState = load_account_state(nonce_account)?;
            let nonce = state.next;
            state.next = nonce
                .checked_add(1)
                .ok_or(ProgramError::ArithmeticOverflow)?;
            save_account_state(nonce_account, &state)?;
            emit(
                "HomeCallEvent",
                &HomeCallEvent {
                    sender: *sender.key,
                    nonce,
                    calls,
                },
            )
        }
        Instruction::InitVerifier { committee } => {
            let verifier_account = next_account_info(&mut it)?;
            let (expected, _) = Pubkey::find_program_address(&[b"verifier"], program_id);
            if *verifier_account.key != expected || verifier_account.owner != program_id {
                return Err(ProgramError::InvalidSeeds);
            }
            if !verifier_account.is_writable {
                return Err(ProgramError::InvalidArgument);
            }
            let mut vstate: verifier::VerifierState = load_account_state(verifier_account)?;
            verifier::initialize_committee(&mut vstate, committee)?;
            save_account_state(verifier_account, &vstate)
        }
        Instruction::RotateCommittee { handoff } => {
            let verifier_account = next_account_info(&mut it)?;
            let sysvar_ix_account = next_account_info(&mut it)?;
            let (expected, _) = Pubkey::find_program_address(&[b"verifier"], program_id);
            if *verifier_account.key != expected || verifier_account.owner != program_id {
                return Err(ProgramError::InvalidSeeds);
            }
            if !verifier_account.is_writable {
                return Err(ProgramError::InvalidArgument);
            }
            let mut vstate: verifier::VerifierState = load_account_state(verifier_account)?;
            verifier::rotate_committee(&mut vstate, sysvar_ix_account, &handoff)?;
            save_account_state(verifier_account, &vstate)
        }
        Instruction::RecordCheckpoint {
            height,
            state_root,
            header_hash,
            proof,
        } => {
            let verifier_account = next_account_info(&mut it)?;
            let sysvar_ix_account = next_account_info(&mut it)?;
            let (expected, _) = Pubkey::find_program_address(&[b"verifier"], program_id);
            if *verifier_account.key != expected || verifier_account.owner != program_id {
                return Err(ProgramError::InvalidSeeds);
            }
            if !verifier_account.is_writable {
                return Err(ProgramError::InvalidArgument);
            }
            let mut vstate: verifier::VerifierState = load_account_state(verifier_account)?;
            verifier::record(
                &mut vstate,
                sysvar_ix_account,
                height,
                state_root,
                header_hash,
                &proof,
            )?;
            save_account_state(verifier_account, &vstate)
        }
        Instruction::AcceptHeader { height } => {
            let state_account = next_account_info(&mut it)?;
            let verifier_account = next_account_info(&mut it)?;
            let (expected, _) = Pubkey::find_program_address(&[b"endpoint"], program_id);
            if *state_account.key != expected || state_account.owner != program_id {
                return Err(ProgramError::InvalidSeeds);
            }
            if !state_account.is_writable {
                return Err(ProgramError::InvalidArgument);
            }
            let (expected_verifier, _) = Pubkey::find_program_address(&[b"verifier"], program_id);
            if *verifier_account.key != expected_verifier || verifier_account.owner != program_id {
                return Err(ProgramError::InvalidSeeds);
            }
            let mut state: EndpointState = load_account_state(state_account)?;
            if height <= state.last_accepted_height {
                return Err(ProgramError::Custom(NOT_NEWER));
            }
            let vstate: verifier::VerifierState = load_account_state(verifier_account)?;
            if !verifier::height_final(&vstate, height)
                || verifier::header_at(&vstate, height) == [0u8; 32]
            {
                return Err(ProgramError::Custom(NOT_FINAL));
            }
            state.last_accepted_height = height;
            state.last_accepted_at = Clock::get()?.unix_timestamp;
            save_account_state(state_account, &state)
        }
        // Both need an opening of the object-layer root in an accepted
        // Budlum header.
        Instruction::Release { .. } | Instruction::Escape { .. } => {
            Err(ProgramError::Custom(NOT_OPEN))
        }
    }
}

/// SPL Token `Transfer` (instruction 3), built by hand so the program has no
/// dependency beyond `solana-program`.
fn spl_transfer(
    token_program: &Pubkey,
    from: &Pubkey,
    to: &Pubkey,
    authority: &Pubkey,
    amount: u64,
) -> solana_program::instruction::Instruction {
    use solana_program::instruction::{AccountMeta, Instruction as Ix};
    let mut data = vec![3u8];
    data.extend_from_slice(&amount.to_le_bytes());
    Ix {
        program_id: *token_program,
        accounts: vec![
            AccountMeta::new(*from, false),
            AccountMeta::new(*to, false),
            AccountMeta::new_readonly(*authority, true),
        ],
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custody_and_home_call_are_closed_before_accounts_are_touched() {
        // Borsh enum discriminant 0 = Deposit, then kind, amount and two
        // absent option fields. Empty accounts would otherwise fail later.
        let mut deposit = vec![0, FUNGIBLE];
        deposit.extend_from_slice(&1u64.to_le_bytes());
        deposit.extend_from_slice(&[0, 0]);
        let home_call = [1, 0, 0, 0, 0]; // variant 1, empty call vector
        for input in [&deposit[..], &home_call[..]] {
            assert_eq!(
                process_instruction(&Pubkey::new_unique(), &[], input),
                Err(ProgramError::Custom(NOT_OPEN))
            );
        }
    }

    #[test]
    fn preallocated_pda_blocks_committee_overwrite_and_preserves_checkpoints() {
        let program_id = Pubkey::new_unique();
        let (verifier_pda, _) = Pubkey::find_program_address(&[b"verifier"], &program_id);
        let mut lamports = 1_000_000u64;
        // Real Solana PDA pre-allocated with 2048 bytes of space.
        let mut raw_data = vec![0u8; 2048];

        let honest_committee = verifier::CommitteeConfig {
            budlum_chain_id: 45_261,
            epoch: 1,
            threshold: 1,
            members: vec![[0x11; 32]],
        };
        let mut init_honest = vec![2u8]; // Instruction::InitVerifier discriminant = 2
        honest_committee.serialize(&mut init_honest).unwrap();

        {
            let acc = AccountInfo::new(
                &verifier_pda,
                false,
                true,
                &mut lamports,
                &mut raw_data,
                &program_id,
                false,
                0,
            );
            process_instruction(&program_id, &[acc], &init_honest).unwrap();
        }

        // Attacker attempts second InitVerifier on the pre-allocated PDA with trailing zeros.
        let attacker_committee = verifier::CommitteeConfig {
            budlum_chain_id: 45_261,
            epoch: 1,
            threshold: 1,
            members: vec![[0x99; 32]],
        };
        let mut init_attacker = vec![2u8];
        attacker_committee.serialize(&mut init_attacker).unwrap();

        {
            let acc = AccountInfo::new(
                &verifier_pda,
                false,
                true,
                &mut lamports,
                &mut raw_data,
                &program_id,
                false,
                0,
            );
            assert_eq!(
                process_instruction(&program_id, &[acc], &init_attacker),
                Err(ProgramError::Custom(verifier::ERR_ALREADY_INITIALIZED)),
                "second InitVerifier on pre-allocated PDA must be refused"
            );
        }

        // Read-only verifier PDA must be refused before mutating.
        let mut fresh_lamports = 1_000_000u64;
        let mut fresh_data = vec![0u8; 2048];
        {
            let ro_acc = AccountInfo::new(
                &verifier_pda,
                false,
                false,
                &mut fresh_lamports,
                &mut fresh_data,
                &program_id,
                false,
                0,
            );
            assert!(
                process_instruction(&program_id, &[ro_acc], &init_honest).is_err(),
                "non-writable verifier PDA must be refused"
            );
        }
    }
}
