//! Canonical SVM built-in program catalog (`Section 8.7.2` SVM row, `8.15`,).
//!
//! Supported built-ins:
//! - System Program (`11111111111111111111111111111111`)
//! - SPL Token (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`)
//! - SPL Token-2022 (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`)
//! - Associated Token Account (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`)
//! - Memo (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`)
//! - BPF Upgradeable Loader (`BPFLoaderUpgradeab1e11111111111111111111111`)
//! - Budlum Universal Call (`SHA256("BDLM_SVM_UNIVERSAL_PROGRAM_V1")`)
//!
//! Explicitly refused (`Section 8.15`):
//! - Solana Vote (`Vote111111111111111111111111111111111111111`)
//! - Solana Stake (`Stake11111111111111111111111111111111111111`)

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

/// Canonical `ee/svm/account` namespace (`Section 8.10` item 3).
pub const NS_SVM_ACCOUNT: &str = "ee/svm/account";

/// `1 lamport = 10^9 attoBUD` (`Section 8.5`).
pub const ATTOS_PER_LAMPORT: u128 = 1_000_000_000;

/// Solana System Program (`11111111111111111111111111111111`).
pub const SYSTEM_PROGRAM_ID: [u8; 32] = [0u8; 32];

/// SPL Token Program (`TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA`).
pub const SPL_TOKEN_PROGRAM_ID: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xd7, 0x65, 0xa1, 0x93, 0xd9, 0xcb, 0xe1, 0x46, 0xce, 0xeb, 0x79, 0xac,
    0x1c, 0xb4, 0x85, 0xed, 0x5f, 0x5b, 0x37, 0x91, 0x3a, 0x8c, 0xf5, 0x85, 0x7e, 0xff, 0x00, 0xa9,
];

/// SPL Token-2022 Program (`TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb`).
pub const SPL_TOKEN_2022_PROGRAM_ID: [u8; 32] = [
    0x06, 0xdd, 0xf6, 0xe1, 0xee, 0x75, 0x8f, 0xde, 0x18, 0x42, 0x5d, 0xbc, 0xe4, 0x6c, 0xcd, 0xda,
    0xb6, 0x1a, 0xfc, 0x4d, 0x83, 0xb9, 0x0d, 0x27, 0xfe, 0xbd, 0xf9, 0x28, 0xd8, 0xa1, 0x8b, 0xfc,
];

/// Associated Token Account Program (`ATokenGPvbdGVxr1b2hvZbsiqW5xWH25efTNsLJA8knL`).
pub const ASSOCIATED_TOKEN_PROGRAM_ID: [u8; 32] = [
    0x8c, 0x97, 0x25, 0x8f, 0x4e, 0x24, 0x89, 0xf1, 0xbb, 0x3d, 0x10, 0x29, 0x14, 0x8e, 0x0d, 0x83,
    0x0b, 0x5a, 0x13, 0x99, 0xda, 0xff, 0x10, 0x84, 0x04, 0x8e, 0x7b, 0xd8, 0xdb, 0xe9, 0xf8, 0x59,
];

/// SPL Memo Program (`MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr`).
pub const MEMO_PROGRAM_ID: [u8; 32] = [
    0x05, 0x4a, 0x53, 0x5a, 0x99, 0x29, 0x21, 0x06, 0x4d, 0x24, 0xe8, 0x71, 0x60, 0xda, 0x38, 0x7c,
    0x7c, 0x35, 0xb5, 0xdd, 0xbc, 0x92, 0xbb, 0x81, 0xe4, 0x1f, 0xa8, 0x40, 0x41, 0x05, 0x44, 0x8d,
];

/// BPF Upgradeable Loader (`BPFLoaderUpgradeab1e11111111111111111111111`).
pub const BPF_LOADER_UPGRADEABLE_ID: [u8; 32] = [
    0x02, 0xa8, 0xf6, 0x91, 0x4e, 0x88, 0xa1, 0xb0, 0xe2, 0x10, 0x15, 0x3e, 0xf7, 0x63, 0xae, 0x2b,
    0x00, 0xc2, 0xb9, 0x3d, 0x16, 0xc1, 0x24, 0xd2, 0xc0, 0x53, 0x7a, 0x10, 0x04, 0x80, 0x00, 0x00,
];

/// Budlum SVM Universal Call Built-in (`SHA256("BDLM_SVM_UNIVERSAL_PROGRAM_V1")`,
/// Base58 `Gkc2Nm7XBXmz5M3tfR8Unow9n1efTzAUNTeDSSFcUFsH`).
pub const UNIVERSAL_CALL_PROGRAM_ID: [u8; 32] = [
    0xea, 0x0a, 0xe1, 0x4f, 0x97, 0x1a, 0x98, 0x94, 0x8d, 0x77, 0x37, 0xd2, 0x60, 0x52, 0x20, 0x3b,
    0xde, 0xd9, 0x37, 0x93, 0x1c, 0x15, 0xfc, 0xa5, 0x53, 0x5c, 0xbd, 0xa6, 0x89, 0x78, 0xce, 0x44,
];

/// Refused Solana Vote Program (`Vote111111111111111111111111111111111111111`).
pub const VOTE_PROGRAM_ID: [u8; 32] = [
    0x07, 0x61, 0x48, 0x1d, 0x35, 0x74, 0x74, 0xbb, 0x7c, 0x4d, 0x76, 0x24, 0xeb, 0xd3, 0xbd, 0xb3,
    0xd8, 0x35, 0x5e, 0x73, 0xd1, 0x10, 0x43, 0xfc, 0x0d, 0xa3, 0x53, 0x80, 0x00, 0x00, 0x00, 0x00,
];

/// Refused Solana Stake Program (`Stake11111111111111111111111111111111111111`).
pub const STAKE_PROGRAM_ID: [u8; 32] = [
    0x06, 0xa1, 0xd8, 0x17, 0x91, 0x37, 0x54, 0x2a, 0x98, 0x34, 0x37, 0xbd, 0xfe, 0x2a, 0x7a, 0xb2,
    0x55, 0x7f, 0x53, 0x5c, 0x8a, 0x78, 0x72, 0x2b, 0x68, 0xa4, 0x9d, 0xc0, 0x00, 0x00, 0x00, 0x00,
];

/// Persisted SVM account record under `ee/svm/account`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvmAccountRecord {
    pub owner: [u8; 32],
    pub executable: bool,
    pub rent_epoch: u64,
    pub data: Vec<u8>,
}

impl Default for SvmAccountRecord {
    fn default() -> Self {
        Self {
            owner: SYSTEM_PROGRAM_ID,
            executable: false,
            rent_epoch: u64::MAX,
            data: Vec::new(),
        }
    }
}

/// Persisted SPL Token / Token-2022 Mint state (`data` inside `SvmAccountRecord`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplMintState {
    pub mint_authority: Option<[u8; 32]>,
    pub supply: u64,
    pub decimals: u8,
    pub is_initialized: bool,
}

/// Persisted SPL Token / Token-2022 Account state (`data` inside `SvmAccountRecord`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplTokenAccountState {
    pub mint: [u8; 32],
    pub owner: [u8; 32],
    pub amount: u64,
    pub delegate: Option<[u8; 32]>,
    pub delegated_amount: u64,
    pub is_initialized: bool,
}

/// Account meta passed inside an SVM instruction envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvmAccountMeta {
    pub pubkey: [u8; 32],
    pub is_signer: bool,
    pub is_writable: bool,
}

/// SVM instruction envelope executed by `budlum-ee-svm` (`Section 8.7.1`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SvmInstructionEnvelope {
    pub accounts: Vec<SvmAccountMeta>,
    pub data: Vec<u8>,
}

/// Borsh-decoded `UniversalCall` payload targeting `UNIVERSAL_CALL_PROGRAM_ID`
/// (`Section 8.7.2` SVM row).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BorshUniversalCall {
    pub target_ee: u8,
    pub target: Vec<u8>,
    pub input: Vec<u8>,
    pub value_attos: u128,
    pub gas_limit_bgu: u64,
    pub is_static: bool,
}

fn take_slice<'a>(cur: &mut &'a [u8], len: usize) -> Option<&'a [u8]> {
    let (h, t) = cur.split_at_checked(len)?;
    *cur = t;
    Some(h)
}

fn take_borsh_vec(cur: &mut &[u8], max_len: usize) -> Option<Vec<u8>> {
    let len_bytes: [u8; 4] = take_slice(cur, 4)?.try_into().ok()?;
    let len = u32::from_le_bytes(len_bytes) as usize;
    if len > max_len {
        return None;
    }
    Some(take_slice(cur, len)?.to_vec())
}

/// Decode a Borsh-serialized `UniversalCall` instruction data buffer.
#[must_use]
pub fn decode_borsh_universal_call(mut data: &[u8]) -> Option<BorshUniversalCall> {
    let target_ee = *take_slice(&mut data, 1)?.first()?;
    let target = take_borsh_vec(&mut data, 128)?;
    let input = take_borsh_vec(&mut data, 1024 * 1024)?;
    let val_bytes: [u8; 16] = take_slice(&mut data, 16)?.try_into().ok()?;
    let gas_bytes: [u8; 8] = take_slice(&mut data, 8)?.try_into().ok()?;
    let static_byte = *take_slice(&mut data, 1)?.first()?;
    if !data.is_empty() || static_byte > 1 {
        return None;
    }
    Some(BorshUniversalCall {
        target_ee,
        target,
        input,
        value_attos: u128::from_le_bytes(val_bytes),
        gas_limit_bgu: u64::from_le_bytes(gas_bytes),
        is_static: static_byte == 1,
    })
}

/// Borsh-encode a `BorshUniversalCall` payload (used by CPI callers and tests).
#[must_use]
pub fn encode_borsh_universal_call(call: &BorshUniversalCall) -> Vec<u8> {
    let mut out = Vec::with_capacity(30 + call.target.len() + call.input.len());
    out.push(call.target_ee);
    out.extend_from_slice(&(call.target.len() as u32).to_le_bytes());
    out.extend_from_slice(&call.target);
    out.extend_from_slice(&(call.input.len() as u32).to_le_bytes());
    out.extend_from_slice(&call.input);
    out.extend_from_slice(&call.value_attos.to_le_bytes());
    out.extend_from_slice(&call.gas_limit_bgu.to_le_bytes());
    out.push(u8::from(call.is_static));
    out
}

/// Derive a deterministic off-curve Associated Token Account address for
/// `(wallet, token_program, mint)`.
#[must_use]
pub fn derive_associated_token_address(
    wallet: &[u8; 32],
    token_program: &[u8; 32],
    mint: &[u8; 32],
) -> [u8; 32] {
    for bump in (0..=255u8).rev() {
        let mut h = Sha256::new();
        h.update(wallet);
        h.update(token_program);
        h.update(mint);
        h.update([bump]);
        h.update(ASSOCIATED_TOKEN_PROGRAM_ID);
        h.update(b"ProgramDerivedAddress");
        let candidate: [u8; 32] = h.finalize().into();
        if curve25519_dalek::edwards::CompressedEdwardsY(candidate)
            .decompress()
            .is_none()
        {
            return candidate;
        }
    }
    [0u8; 32]
}
