//! Budlum settlement endpoint, SVM family.
//!
//! Takes custody of SPL tokens and NFT mints that enter the Budlum Universal
//! Object Layer, carries home calls, and tracks the last accepted Budlum
//! checkpoint for the silence window. Deployed with the upgrade authority
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
    HomeCall { calls: Vec<u8> },
    /// Accounts: endpoint state PDA (writable).
    AcceptHeader { height: u64 },
    Release { proof: Vec<u8> },
    Escape { proof: Vec<u8> },
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

entrypoint!(process_instruction);

pub fn process_instruction(
    program_id: &Pubkey,
    accounts: &[AccountInfo],
    input: &[u8],
) -> ProgramResult {
    let instruction =
        Instruction::try_from_slice(input).map_err(|_| ProgramError::InvalidInstructionData)?;
    let mut it = accounts.iter();
    match instruction {
        Instruction::Deposit { kind, amount, recipient, collection } => {
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
            let ix = spl_transfer(token_program.key, from.key, vault.key, depositor.key, amount);
            solana_program::program::invoke(
                &ix,
                &[from.clone(), vault.clone(), depositor.clone(), token_program.clone()],
            )?;
            let received = token_amount(vault)?.saturating_sub(before);
            if received == 0 {
                return Err(ProgramError::Custom(NOTHING_RECEIVED));
            }
            let (class, native_id) = match (kind, collection) {
                (FUNGIBLE, None) => (*mint.key, None),
                (UNIQUE, Some(c)) if received == 1 => (c, Some(*mint.key)),
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
            let mut state = NonceState::try_from_slice(&nonce_account.try_borrow_data()?)
                .unwrap_or_default();
            let nonce = state.next;
            state.next = nonce.checked_add(1).ok_or(ProgramError::ArithmeticOverflow)?;
            state
                .serialize(&mut &mut nonce_account.try_borrow_mut_data()?[..])
                .map_err(|_| ProgramError::AccountDataTooSmall)?;
            emit("HomeCallEvent", &HomeCallEvent { sender: *sender.key, nonce, calls })
        }
        Instruction::AcceptHeader { height } => {
            let state_account = next_account_info(&mut it)?;
            let (expected, _) = Pubkey::find_program_address(&[b"endpoint"], program_id);
            if *state_account.key != expected || state_account.owner != program_id {
                return Err(ProgramError::InvalidSeeds);
            }
            let mut state = EndpointState::try_from_slice(&state_account.try_borrow_data()?)
                .unwrap_or_default();
            if height <= state.last_accepted_height {
                return Err(ProgramError::Custom(NOT_NEWER));
            }
            if !verifier::height_final(height) {
                return Err(ProgramError::Custom(NOT_FINAL));
            }
            state.last_accepted_height = height;
            state.last_accepted_at = Clock::get()?.unix_timestamp;
            state
                .serialize(&mut &mut state_account.try_borrow_mut_data()?[..])
                .map_err(|_| ProgramError::AccountDataTooSmall)
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
