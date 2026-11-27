//! Budlum finality on an SVM home chain.
//!
//! Implements the unified four-query `IBudlumFinality` surface
//! (`height_final`, `root_at_height`, `latest_final_height`,
//! `finality_mode_at_height`) backed by committee Ed25519 quorum verification
//! (`ProofFormat::Signature`).
//!
//! On-chain, each committee signature is verified against a matching
//! `ed25519_program` precompile instruction in the same Solana transaction via
//! the `sysvar::instructions` account. No upgrade authority or admin key can
//! overwrite recorded checkpoints.

use borsh::{BorshDeserialize, BorshSerialize};
use solana_program::{
    account_info::AccountInfo, ed25519_program, program_error::ProgramError,
    sysvar::instructions as sysvar_instructions,
};

/// Canonical domain separator shared identically across EVM, CosmWasm, SVM, and Move.
pub const SIGNING_DOMAIN: &[u8; 25] = b"BDLM_OUTBOUND_FINALITY_V1";

/// Canonical domain separator for permissionless validator-set handoff certificates.
pub const HANDOFF_DOMAIN: &[u8; 24] = b"BDLM_OUTBOUND_HANDOFF_V1";

/// Fixed length of the canonical signing message (114 bytes).
pub const SIGNING_MESSAGE_LEN: usize = 114;

/// Custom error codes for the SVM finality verifier.
pub const ERR_INVALID_COMMITTEE: u32 = 0x4255_0101;
pub const ERR_ALREADY_INITIALIZED: u32 = 0x4255_0102;
pub const ERR_NOT_INITIALIZED: u32 = 0x4255_0103;
pub const ERR_ZERO_FIELD: u32 = 0x4255_0104;
pub const ERR_MODE_NONE: u32 = 0x4255_0105;
pub const ERR_DOMAIN_MISMATCH: u32 = 0x4255_0106;
pub const ERR_CONFLICT: u32 = 0x4255_0107;
pub const ERR_QUORUM_NOT_MET: u32 = 0x4255_0108;
pub const ERR_INVALID_SIGNER: u32 = 0x4255_0109;
pub const ERR_DUPLICATE_SIGNER: u32 = 0x4255_010A;
pub const ERR_INVALID_SIGNATURE: u32 = 0x4255_010B;

/// Verification mode recorded when a Budlum height becomes final.
/// Discriminants match Solidity `FinalityMode`.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum FinalityMode {
    None = 0,
    ClassicalOnly = 1,
    PostQuantumOnly = 2,
    Hybrid = 3,
}

impl FinalityMode {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// Proof format accepted by this verifier.
#[derive(BorshSerialize, BorshDeserialize, Clone, Copy, Debug, PartialEq, Eq)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum ProofFormat {
    None = 0,
    Signature = 1,
    Succinct = 2,
}

/// Pinned Budlum finality committee configuration (immutable after initialization).
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CommitteeConfig {
    pub budlum_chain_id: u64,
    pub epoch: u64,
    pub threshold: u32,
    pub members: Vec<[u8; 32]>,
}

/// One committee member's Ed25519 signature over a checkpoint.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignerSignature {
    pub signer_index: u32,
    pub signature: [u8; 64],
}

/// Signature-format finality proof verified by this SVM verifier.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct SignedFinalityProof {
    pub chain_id: u64,
    pub epoch: u64,
    pub mode: FinalityMode,
    pub signatures: Vec<SignerSignature>,
}

/// Permissionless validator-set handoff proof signed by `> 2/3` of the active committee.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CommitteeHandoffProof {
    pub next_committee: CommitteeConfig,
    pub signatures: Vec<SignerSignature>,
}

/// One verified finalized checkpoint stored inside `VerifierState`.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, PartialEq, Eq)]
pub struct CheckpointEntry {
    pub height: u64,
    pub state_root: [u8; 32],
    pub header_hash: [u8; 32],
    pub mode: FinalityMode,
}

/// PDA state account (seed `b"verifier"`) storing the pinned committee and verified checkpoints.
#[derive(BorshSerialize, BorshDeserialize, Clone, Debug, Default, PartialEq, Eq)]
pub struct VerifierState {
    pub committee: Option<CommitteeConfig>,
    pub latest_final_height: u64,
    pub checkpoints: Vec<CheckpointEntry>,
}

/// Proof format accepted by this verifier (`ProofFormat::Signature`).
#[must_use]
pub const fn accepted_proof_format() -> ProofFormat {
    ProofFormat::Signature
}

/// Build the canonical 114-byte signing message shared identically across all four families.
#[must_use]
pub fn signing_message(
    chain_id: u64,
    epoch: u64,
    height: u64,
    state_root: &[u8; 32],
    header_hash: &[u8; 32],
    mode: FinalityMode,
) -> [u8; SIGNING_MESSAGE_LEN] {
    let mut out = [0u8; SIGNING_MESSAGE_LEN];
    out[0..25].copy_from_slice(SIGNING_DOMAIN);
    out[25..33].copy_from_slice(&chain_id.to_le_bytes());
    out[33..41].copy_from_slice(&epoch.to_le_bytes());
    out[41..49].copy_from_slice(&height.to_le_bytes());
    out[49..81].copy_from_slice(state_root);
    out[81..113].copy_from_slice(header_hash);
    out[113] = mode.as_u8();
    out
}

/// Initialize the pinned committee once.
pub fn initialize_committee(
    state: &mut VerifierState,
    committee: CommitteeConfig,
) -> Result<(), ProgramError> {
    if state.committee.is_some() {
        return Err(ProgramError::Custom(ERR_ALREADY_INITIALIZED));
    }
    validate_committee(&committee)?;
    state.committee = Some(committee);
    state.latest_final_height = 0;
    state.checkpoints.clear();
    Ok(())
}

fn validate_committee(config: &CommitteeConfig) -> Result<(), ProgramError> {
    if config.budlum_chain_id == 0 || config.members.is_empty() {
        return Err(ProgramError::Custom(ERR_INVALID_COMMITTEE));
    }
    let n = config.members.len();
    let t = config.threshold as usize;
    if t == 0 || t > n || (t as u128).saturating_mul(3) <= (n as u128).saturating_mul(2) {
        return Err(ProgramError::Custom(ERR_INVALID_COMMITTEE));
    }
    for (i, pk) in config.members.iter().enumerate() {
        if *pk == [0u8; 32] {
            return Err(ProgramError::Custom(ERR_INVALID_COMMITTEE));
        }
        for other in &config.members[(i + 1)..] {
            if other == pk {
                return Err(ProgramError::Custom(ERR_INVALID_COMMITTEE));
            }
        }
    }
    Ok(())
}

/// Inspect the Solana `sysvar::instructions` account to confirm that the
/// native `ed25519_program` precompile verified `(pubkey, signature, message)`
/// in the current transaction.
pub fn verify_ed25519_from_sysvar(
    sysvar_ix_account: &AccountInfo<'_>,
    pubkey: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> bool {
    if *sysvar_ix_account.key != sysvar_instructions::ID {
        return false;
    }
    let Ok(current_idx) = sysvar_instructions::load_current_index_checked(sysvar_ix_account) else {
        return false;
    };
    for ix_idx in 0..usize::from(current_idx) {
        let Ok(ix) = sysvar_instructions::load_instruction_at_checked(ix_idx, sysvar_ix_account)
        else {
            continue;
        };
        if ix.program_id != ed25519_program::ID {
            continue;
        }
        if matches_ed25519_precompile_data(&ix.data, pubkey, signature, message) {
            return true;
        }
    }
    false
}

/// Parse Solana's standard Ed25519 precompile instruction layout (single-instruction self-contained offsets `0xFFFF`).
#[must_use]
pub fn matches_ed25519_precompile_data(
    data: &[u8],
    pubkey: &[u8; 32],
    signature: &[u8; 64],
    message: &[u8],
) -> bool {
    if data.len() < 16 || data[1] != 0 {
        return false;
    }
    let num_sigs = usize::from(data[0]);
    if num_sigs == 0 || 2 + num_sigs * 14 > data.len() {
        return false;
    }
    for i in 0..num_sigs {
        let off = 2 + i * 14;
        let sig_off = usize::from(u16::from_le_bytes([data[off], data[off + 1]]));
        let sig_ix = u16::from_le_bytes([data[off + 2], data[off + 3]]);
        let pk_off = usize::from(u16::from_le_bytes([data[off + 4], data[off + 5]]));
        let pk_ix = u16::from_le_bytes([data[off + 6], data[off + 7]]);
        let msg_off = usize::from(u16::from_le_bytes([data[off + 8], data[off + 9]]));
        let msg_len = usize::from(u16::from_le_bytes([data[off + 10], data[off + 11]]));
        let msg_ix = u16::from_le_bytes([data[off + 12], data[off + 13]]);

        if sig_ix != u16::MAX || pk_ix != u16::MAX || msg_ix != u16::MAX {
            continue;
        }
        if msg_len != message.len() {
            continue;
        }
        let Some(sig_slice) = data.get(sig_off..sig_off.saturating_add(64)) else {
            continue;
        };
        let Some(pk_slice) = data.get(pk_off..pk_off.saturating_add(32)) else {
            continue;
        };
        let Some(msg_slice) = data.get(msg_off..msg_off.saturating_add(msg_len)) else {
            continue;
        };
        if sig_slice == signature && pk_slice == pubkey && msg_slice == message {
            return true;
        }
    }
    false
}

/// Build the canonical handoff signing message shared across CosmWasm, SVM, and Move.
#[must_use]
pub fn handoff_message(chain_id: u64, from_epoch: u64, next: &CommitteeConfig) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + 8 + 8 + 8 + 4 + 4 + next.members.len() * 32);
    out.extend_from_slice(HANDOFF_DOMAIN);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&from_epoch.to_le_bytes());
    out.extend_from_slice(&next.epoch.to_le_bytes());
    out.extend_from_slice(&next.threshold.to_le_bytes());
    out.extend_from_slice(&(next.members.len() as u32).to_le_bytes());
    for pk in &next.members {
        out.extend_from_slice(pk);
    }
    out
}

/// Permissionlessly rotate the active committee on-chain using `ed25519_program` sysvar introspection.
pub fn rotate_committee(
    state: &mut VerifierState,
    sysvar_ix_account: &AccountInfo<'_>,
    handoff: &CommitteeHandoffProof,
) -> Result<u64, ProgramError> {
    rotate_committee_with_verifier(state, handoff, |pk, sig, msg| {
        verify_ed25519_from_sysvar(sysvar_ix_account, pk, sig, msg)
    })
}

/// Core permissionless committee handoff logic parameterized by the Ed25519 verifier callback.
pub fn rotate_committee_with_verifier<F>(
    state: &mut VerifierState,
    handoff: &CommitteeHandoffProof,
    mut verify_ed25519: F,
) -> Result<u64, ProgramError>
where
    F: FnMut(&[u8; 32], &[u8; 64], &[u8]) -> bool,
{
    let current = state
        .committee
        .as_ref()
        .ok_or(ProgramError::Custom(ERR_NOT_INITIALIZED))?;
    let expected_next_epoch = current
        .epoch
        .checked_add(1)
        .ok_or(ProgramError::ArithmeticOverflow)?;
    if handoff.next_committee.budlum_chain_id != current.budlum_chain_id
        || handoff.next_committee.epoch != expected_next_epoch
    {
        return Err(ProgramError::Custom(ERR_DOMAIN_MISMATCH));
    }
    validate_committee(&handoff.next_committee)?;
    if handoff.signatures.len() < current.threshold as usize {
        return Err(ProgramError::Custom(ERR_QUORUM_NOT_MET));
    }

    let msg = handoff_message(
        current.budlum_chain_id,
        current.epoch,
        &handoff.next_committee,
    );
    let mut seen = vec![false; current.members.len()];
    let mut valid_count: usize = 0;
    for entry in &handoff.signatures {
        let idx = entry.signer_index as usize;
        if idx >= current.members.len() {
            return Err(ProgramError::Custom(ERR_INVALID_SIGNER));
        }
        if seen[idx] {
            return Err(ProgramError::Custom(ERR_DUPLICATE_SIGNER));
        }
        if !verify_ed25519(&current.members[idx], &entry.signature, &msg) {
            return Err(ProgramError::Custom(ERR_INVALID_SIGNATURE));
        }
        seen[idx] = true;
        valid_count += 1;
    }
    if valid_count < current.threshold as usize {
        return Err(ProgramError::Custom(ERR_QUORUM_NOT_MET));
    }

    state.committee = Some(handoff.next_committee.clone());
    Ok(expected_next_epoch)
}

/// Record a checkpoint on-chain using Solana's `ed25519_program` precompile via `sysvar::instructions`.
pub fn record(
    state: &mut VerifierState,
    sysvar_ix_account: &AccountInfo<'_>,
    height: u64,
    state_root: [u8; 32],
    header_hash: [u8; 32],
    proof: &SignedFinalityProof,
) -> Result<(), ProgramError> {
    record_with_verifier(
        state,
        height,
        state_root,
        header_hash,
        proof,
        |pk, sig, msg| verify_ed25519_from_sysvar(sysvar_ix_account, pk, sig, msg),
    )
}

/// Core quorum + conflict verification logic parameterized by the Ed25519 verification callback.
pub fn record_with_verifier<F>(
    state: &mut VerifierState,
    height: u64,
    state_root: [u8; 32],
    header_hash: [u8; 32],
    proof: &SignedFinalityProof,
    mut verify_ed25519: F,
) -> Result<(), ProgramError>
where
    F: FnMut(&[u8; 32], &[u8; 64], &[u8]) -> bool,
{
    if height == 0 || state_root == [0u8; 32] || header_hash == [0u8; 32] {
        return Err(ProgramError::Custom(ERR_ZERO_FIELD));
    }
    if proof.mode == FinalityMode::None {
        return Err(ProgramError::Custom(ERR_MODE_NONE));
    }

    let committee = state
        .committee
        .as_ref()
        .ok_or(ProgramError::Custom(ERR_NOT_INITIALIZED))?;

    if proof.chain_id != committee.budlum_chain_id || proof.epoch != committee.epoch {
        return Err(ProgramError::Custom(ERR_DOMAIN_MISMATCH));
    }

    let already_recorded =
        if let Some(existing) = state.checkpoints.iter().find(|c| c.height == height) {
            if existing.state_root != state_root
                || existing.header_hash != header_hash
                || existing.mode != proof.mode
            {
                return Err(ProgramError::Custom(ERR_CONFLICT));
            }
            true
        } else {
            false
        };

    if proof.signatures.len() < committee.threshold as usize {
        return Err(ProgramError::Custom(ERR_QUORUM_NOT_MET));
    }

    let msg = signing_message(
        proof.chain_id,
        proof.epoch,
        height,
        &state_root,
        &header_hash,
        proof.mode,
    );

    let mut seen = vec![false; committee.members.len()];
    let mut valid_count: usize = 0;
    for entry in &proof.signatures {
        let idx = entry.signer_index as usize;
        if idx >= committee.members.len() {
            return Err(ProgramError::Custom(ERR_INVALID_SIGNER));
        }
        if seen[idx] {
            return Err(ProgramError::Custom(ERR_DUPLICATE_SIGNER));
        }
        if !verify_ed25519(&committee.members[idx], &entry.signature, &msg) {
            return Err(ProgramError::Custom(ERR_INVALID_SIGNATURE));
        }
        seen[idx] = true;
        valid_count += 1;
    }

    if valid_count < committee.threshold as usize {
        return Err(ProgramError::Custom(ERR_QUORUM_NOT_MET));
    }

    if !already_recorded {
        state.checkpoints.push(CheckpointEntry {
            height,
            state_root,
            header_hash,
            mode: proof.mode,
        });
        if height > state.latest_final_height {
            state.latest_final_height = height;
        }
    }
    Ok(())
}

/// `IBudlumFinality::heightFinal(height)`.
#[must_use]
pub fn height_final(state: &VerifierState, height: u64) -> bool {
    state.checkpoints.iter().any(|c| {
        c.height == height
            && c.state_root != [0u8; 32]
            && c.header_hash != [0u8; 32]
            && c.mode != FinalityMode::None
    })
}

/// `IBudlumFinality::rootAtHeight(height)`.
#[must_use]
pub fn root_at_height(state: &VerifierState, height: u64) -> [u8; 32] {
    state
        .checkpoints
        .iter()
        .find(|c| c.height == height)
        .map_or([0u8; 32], |c| c.state_root)
}

/// Authenticated Budlum header hash at `height`, or zero if not final.
#[must_use]
pub fn header_at(state: &VerifierState, height: u64) -> [u8; 32] {
    state
        .checkpoints
        .iter()
        .find(|c| c.height == height)
        .map_or([0u8; 32], |c| c.header_hash)
}

/// `IBudlumFinality::latestFinalHeight()`.
#[must_use]
pub fn latest_final_height(state: &VerifierState) -> u64 {
    state.latest_final_height
}

/// `IBudlumFinality::finalityModeAtHeight(height)`.
#[must_use]
pub fn finality_mode_at_height(state: &VerifierState, height: u64) -> FinalityMode {
    state
        .checkpoints
        .iter()
        .find(|c| c.height == height)
        .map_or(FinalityMode::None, |c| c.mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decode_hex<const N: usize>(s: &str) -> [u8; N] {
        assert_eq!(s.len(), N * 2);
        let mut out = [0u8; N];
        for (i, chunk) in s.as_bytes().chunks_exact(2).enumerate() {
            let hi = (chunk[0] as char).to_digit(16).unwrap() as u8;
            let lo = (chunk[1] as char).to_digit(16).unwrap() as u8;
            out[i] = (hi << 4) | lo;
        }
        out
    }

    const MEMBER_PKS: [&str; 4] = [
        "d04ab232742bb4ab3a1368bd4615e4e6d0224ab71a016baf8520a332c9778737",
        "204040e364c10f2bec9c1fe500a1cd4c247c89d650a01ed7e82caba867877c21",
        "66cd608b928b88e50e0efeaa33faf1c43cefe07294b0b87e9fe0aba6a3cf7633",
        "20828bf5c5bdcacb684863336c202fb5599da48be5596615742170705beca9f7",
    ];
    const MEMBER_SIGS: [&str; 4] = [
        "1376dada0ff884f37eba41a2f4be9d3a1df740abd4dc494422eb6202dec9a8b4da90327a59bfe0d366ffd3b33d26ef2cc03b7b08b5e3b7073b601e5146c47804",
        "a5a778aad6a12dd0016361aafe9050fb5b1aad1bac6a0a317ef5bdda2f89be426deb088c24a723152347670fcd0f7f89c261237bf6a6b81eb10f282526dd0e0a",
        "978eeb5b57ef4121f333ac4890607319d38551e1b493ff25beac307e73fc81683897a96beba2e615c08edfea3292eaeb195f05df5e57dc39148be3c75a5d900a",
        "104e160f8d0c83abba5d5c16e771d8aaa3225e6733562893f4720302f0c5c00f3db2e21eaedae7f1c92721491f473f387e9d0659ff082cf0cee75d44bc56e904",
    ];

    fn build_precompile_ix(pk: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> Vec<u8> {
        let mut data = Vec::with_capacity(16 + 32 + 64 + msg.len());
        data.push(1u8);
        data.push(0u8);
        let pk_off: u16 = 16;
        let sig_off: u16 = 16 + 32;
        let msg_off: u16 = 16 + 32 + 64;
        data.extend_from_slice(&sig_off.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes());
        data.extend_from_slice(&pk_off.to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes());
        data.extend_from_slice(&msg_off.to_le_bytes());
        data.extend_from_slice(&(msg.len() as u16).to_le_bytes());
        data.extend_from_slice(&u16::MAX.to_le_bytes());
        data.extend_from_slice(pk);
        data.extend_from_slice(sig);
        data.extend_from_slice(msg);
        data
    }

    fn sample_committee() -> CommitteeConfig {
        CommitteeConfig {
            budlum_chain_id: 1,
            epoch: 7,
            threshold: 3,
            members: MEMBER_PKS.iter().map(|h| decode_hex::<32>(h)).collect(),
        }
    }

    fn sample_proof(indices: &[u32]) -> SignedFinalityProof {
        SignedFinalityProof {
            chain_id: 1,
            epoch: 7,
            mode: FinalityMode::Hybrid,
            signatures: indices
                .iter()
                .map(|&idx| SignerSignature {
                    signer_index: idx,
                    signature: decode_hex::<64>(MEMBER_SIGS[idx as usize]),
                })
                .collect(),
        }
    }

    #[test]
    fn shared_vector_answers_four_finality_queries_and_matches_precompile_layout() {
        let mut state = VerifierState::default();
        initialize_committee(&mut state, sample_committee()).unwrap();
        assert_eq!(accepted_proof_format(), ProofFormat::Signature);

        let root = [0x42; 32];
        let header = [0x99; 32];
        let msg = signing_message(1, 7, 42, &root, &header, FinalityMode::Hybrid);
        let precompile_ixs: Vec<Vec<u8>> = (0..3)
            .map(|i| {
                build_precompile_ix(
                    &decode_hex::<32>(MEMBER_PKS[i]),
                    &decode_hex::<64>(MEMBER_SIGS[i]),
                    &msg,
                )
            })
            .collect();

        let proof = sample_proof(&[0, 1, 2]);
        record_with_verifier(&mut state, 42, root, header, &proof, |pk, sig, m| {
            precompile_ixs
                .iter()
                .any(|ix| matches_ed25519_precompile_data(ix, pk, sig, m))
        })
        .unwrap();

        assert!(height_final(&state, 42));
        assert_eq!(root_at_height(&state, 42), root);
        assert_eq!(header_at(&state, 42), header);
        assert_eq!(latest_final_height(&state), 42);
        assert_eq!(finality_mode_at_height(&state, 42), FinalityMode::Hybrid);

        let err = record_with_verifier(&mut state, 42, [0x43; 32], header, &proof, |_, _, _| true)
            .unwrap_err();
        assert_eq!(err, ProgramError::Custom(ERR_CONFLICT));

        assert_eq!(
            record_with_verifier(
                &mut state,
                43,
                root,
                header,
                &sample_proof(&[0, 1]),
                |_, _, _| true
            ),
            Err(ProgramError::Custom(ERR_QUORUM_NOT_MET))
        );
        assert_eq!(
            record_with_verifier(
                &mut state,
                43,
                root,
                header,
                &sample_proof(&[0, 0, 1]),
                |_, _, _| true
            ),
            Err(ProgramError::Custom(ERR_DUPLICATE_SIGNER))
        );
    }

    #[test]
    fn rotate_committee_10_consecutive_epochs_without_admin_key() {
        let mut state = VerifierState::default();
        initialize_committee(&mut state, sample_committee()).unwrap();

        let steps: [(u64, [&str; 4], [&str; 3]); 10] = [
            (7u64, ["ed4f33b075aa6e0f0064a0c4572fc3a2eb8137fe6824c789afa3d048821820cd", "d2e52fa01b98b4cc6488c730c3b838611442af63f707c3866474f7356715fb97", "f0a02b6e4e43991251a0566bc82081f7ac942d521e0b2d6eb26b88abe32e4ac7", "a86cf493557cc0efa1c325a912a04915c37f4065d726cd4439fa7b79d0ebb9af"], ["f27d62edd8a593e67023efc72316c9f99fae092ffb2e71b69657fa864d91d230f59a96ca93a53de9858c825d22664886b8dd008bf30a0b1b19af4500cba2980b", "a4a2684e41e99cf3d03b71ebdf9145b8de270f5bc1d026a3524ddc8bd9d7e29e42126faec629e025e6a4e066048d7d6e2f57963cac064ba411458ac2b840fb02", "08edcde608d4bec2b989727571ae466993f523ca508caac6f378d1d96e4cb63119e0ac84716f9d35ec6d033e79719d917c50e8c56087ed6441a66bbe71d1cc01"]),
            (8u64, ["c90c70e0721772c132203b89f9169e07d4531214bfb598af7051a1a5f5fb3b2f", "34a928aedc31eeb4ab69bfb986e8a686f61c86dc4ee45df670fd1334f94a8bf8", "3d2a31844dfac4bac05d919f6ca792f7acc808b13d9635b0f8f61f72d3a6d0b3", "d18f500e8e89e93cd1798d3035927b633a5d22693f125493102458ccefeb0137"], ["5b86a30f9a886e6c624fe57bd6e16a8c6ccbc4324f28c7478c0a76b3f66c7d5d8ec2d946168dc2334fc337fb06858eba1263983ff37a1c9e928d1fda6c5e2500", "cb70441bed7532ef07423c415b8355badfa979d488dc10e2478767baab198bb342016a46c068ab4ec620341669d8a0b8c9b93d0f154d10ae98b09879a2aa7e00", "efe45e8a89611c55868242fefec297b273035d2536f44edf7197f27b04e9fd77b0fb51bdef2ead514d9fa739c411f10333c790e5ce53b4ca76d22b5f2d4df80d"]),
            (9u64, ["0c1b6f89132c9e43ce312adc8bf051e67f965677d6df4d2bdbb01339f5978d88", "d9b065744a188838983ff2b9e1a6017d72ec3d3345d9b693e2ed157c2a601b34", "74b233d6bbcf482d2084c6aa3024a23220e1ec8f984e3bd56c114e4a6c10ff45", "f9a46f30b0005828c2b0fc11b0851f03354800f90ac22453f444c634acbbb494"], ["6ab16ac3f2f3b48e0e9d7d4e807fc091f1afb8edbd0a140f29b29d0849cf51f4f55dafb098b43ad342494f5d73e668046c7e92623f0ca9807d50a758814b7304", "b39a84264d849a0b961effe2fa0983744d181261506449131669c298385b0511fb00818640ba6bd1ec77fa3be0a970c71c163b0adf5b59926deb36e77fe04d01", "d6d628f9e5a9e26010cbbd4f1d109023f017fa9522f95bca662553101058e143d3e6735dd0af024ca59cae85612d8ec2196e02b629d6e2eb87b7f2efe8c7140e"]),
            (10u64, ["7f9b018d8df9dc600084a3ccd9d2eac9be09b4af3468b37aff4c9929cfa3ae03", "663728dd30154574aabe40bb0b58da62cb092064b8fcf3d7f15b6ae29dafcad3", "b9ffe0c0128dcf667ef233193b111b742e30301a6b5f253f093b07dea1a32e80", "0573509bbb04a3e43d10d25aa22a6ee31aa828d9555bda39acfb2b93821b078d"], ["1cbe71bd10f5c969b340921c2d51f7bcc77eadbc51112f5e388dd51a40f8fe92e5f7321ca3b8242558132ee618c781da008762aad463e3f81ca07956a478600e", "dbdd17589cefc8d3441b6d62ecd55ba324401efa785db7c6e787dea439e0aa5df6345623f061a9b9ff24048dfb1401305c224b5fa9d27e6f3122fdba94ab4e09", "7e8956851be8685aebb7bc8ae693ec28c45efb49b54bb0dc79fafd8ec920c2c41a6f1b31beb831732f32af28f2daa2bcf51077eb2bb20f3fd07b512dc46f0104"]),
            (11u64, ["8fd23fe6f05df44c27f79d36b28476cd5e18b3edddd4fc63eef477c40917f76c", "3c07b908f79bbe7cbf53afb2d98b2d1617ac5469d593aa6baa2f643bccec9926", "e3890ea8bbc7146b0cb361a1460b5cc426d8dcf8edf2cbb4f0965e0136dc3d71", "17652c697d3caeaa539a38c54d3cce811e824cff045b2c1f615c824b2a7af1b4"], ["116ebc41cbdb2a4392f7e7331e891cf5500da1d79b402dc224f56dbec03e0069af6e4050c4a9d963f36e65a31ff069fcb2bb35682488c4f51af6e4f01bddc008", "e7a178bd7c09aa2e4bc48cbcb0e2c60a47cdec3d38b988c732a66442db7f1b517e89744ab6e87b18639a281c3f8edb8ab5051177e2c54d79cbf7bcbee4e11a05", "add505f7868762ae4d346b61e9c5035d058d63a774b18dc496067ab28447ef3e8a288faf5955a234ecd7b440204afbfa4900bd48a1cd75eaa7f7f8d4bea9100f"]),
            (12u64, ["9cfcdcba986a5031d39e4fe3e4468fe316da14594de8b451d16bead54b1c1bdb", "a60f1b7e3af327dab74722b5241456599daad9c267ea913aa58e92626eb4895c", "ff43fd6c176003accf2e107b46dea1554cd01ef10ff0e2033d7aaa9cc0fa3f98", "f2be968771775a39c833a77f8ec6792fef80f4b8f7fa4718fee1000253d6c6e1"], ["f6e025ced0b977e5298870f9135c38451f55551e6bbc3f71c2f6fc2723ef7167f15deb57a5dc99bce0150507e8d904e49de8888bc4752b3364618522a2e29709", "360d34fd3b1619fc74a3ab81b6a6e063786fe240aec0a8287060e2d0ca2f7e9f31c4d315a748cb3e7bd39d9fa7b383efd6fecacc4f4a1f6db20264b865cb040e", "3adaf63c027929e5591dd070db249b979365295d723d236d56927d51148149231e0c5c6bc6508dacfb53aea8d64d67a3773fa2c9dbe53379a927fa7280018d00"]),
            (13u64, ["facb9663d3e7d40da79eac1d0f5419b42949f51448a6b272cdc1c4ab63ed336f", "f3d9129b169b8828abe53ab03abe04cad7d069c056fac6c0179c6a1fe8dda44d", "339861e360b9d165b0556dab3248d3acbdd5e06b27c326b679b97654e2ae32c8", "4b777284c588d688eb1938de04f4a1b1e4490509dfc75c4c34ed782a3d50db76"], ["d474f49541f9380eaa2597ba71f42f6e8310f25230c7084c51296314c8f9b83f1dddbd7dfa65eaae701fca43ae7ee417e8625023b0b4942b4b6f1cddbe29700d", "802552e2108dd3a030483c8ebd6389fac242a9ee53bc6f616aa35c1d956e8a54febf30cd7342ebddc7f00013a2169d2bcfbfc0f86a5010c9d94e7f542497fb04", "f7bc707c52e372a69398bfd6b9ab81045d0b6216dfcb1780fec46c3f8869af8485e0f6b4088ecffddf1e7d29fd003f43cb717c87c65625baa56f10cd061edc07"]),
            (14u64, ["cbc7cc49c24a656b9c65d4077dd33ab91bc8cf7d78184ccf90374f6559b59788", "2709be39f06c56baa9a94ed18497ac5744c83d8cf95c224a0ceb694658011f8d", "6c93845272a7a37399a59775c30d24dae337900e1f9b6a9f79cf55ca341d8224", "f3cff2efba9153ed9f3acda93421608ba923ceab26dc6b27be4144c572bca54e"], ["d8a698af362f99dbe655587f902ce4bed8baa5b59cb1701ace8ffb06adee00b2836aa9f3a6b12719781590bcbb6deae32128828b583cc442e1bab78d9967ab0f", "b347acb26e61f28ee337c758056992367e6ab2f6279e68a7a79cda59ce5d5ee62db946075a82a9bb8d1e7075e8c60210fa5f4d2bb8d9b5db1ea3eeca05c36704", "039549b8257474d25fde64a1853472d679fe6c3a5490b44ccdc92281d66bfe2465276f75ee7b03b00b9fa938126be54cf509c076af5f73bd52518717b0322f0e"]),
            (15u64, ["92bee53312c21326812b61b6273aa4b4ab5203ad3639582d8d3c5d34ce9c4c0d", "bc87e8705f988bde2b32dc26789cf028f4646b95c4aab7417156f8e9a2eb7cde", "ca4e83e9d8ecbab68bb7731c181b54953c3867badfa44c6cf868c83be1cd92ed", "7b49a4cbff1e74c8a1e0dbe6238f689068b74d2878612c444efc8c5588218569"], ["e7d2d94d60dcfc5f557ec9ba8c1ce69e70202a47950368d2ca4427833617aa346c834f27e31632687c57c477158f6ac00f1949b03aefb22b609c9ab566271409", "8aaff9809a51fa043a0dbe5bdcee48c0bda155d900aa00c24ead3dc3f5063f911fd7b19259d6af38a07cb5e8ebc88c8010bb18be9d1a1ee2aa2dd079fe7bef05", "977847abf5e19fe5a39d4c7e862700f494475a337c2a9769fbd5933b509aa612d1c505991f15a20888acc92fa7a4295c24246e1fe18ff5a78ad8d00ce948ec0d"]),
            (16u64, ["ebc8c78b4ef9dec27cc6ba09bb45a193903aa0fe32024b3e3e353066db9b70ef", "c4cc6f7d28a080dce8971523e57c623d9bf82a2e55379e1bb7e6b26cacc4580d", "908c63d51d4b7f00909b0dd38ed7277f117bb14fc7a247d1a8761b5b04603fdc", "fb851d81703e8a273d6291ef52d7b212a03aeec0ba1dcc34fcd219e95712a177"], ["d66b8c668d488164d92da6147528efd0b2e0fc8cc33682d06b870b21d488f0b4804ba38d9515bb885f04a8fd64ed9719b870db19460d39e9994d5a5f6f81c908", "75597761bb86a0d16f983ca477cda041da01d9ce92104dd33d1f32e49cb3909ab8c0d1801112a9bf870ac8aa1f8d7bc24960ea795d54a8e7d6dae819ab672302", "71c44ca706a4402feb0d9548c83fca0c1b519b988320e44b1b6e8bab169eba2d46b931d398460a54110bcf41d3f8b60507947654b026884460de21c4fc182407"]),
        ];

        for (from_ep, next_pks, sigs) in steps {
            let cur_pks = state.committee.as_ref().unwrap().members.clone();
            let next_committee = CommitteeConfig {
                budlum_chain_id: 1,
                epoch: from_ep + 1,
                threshold: 3,
                members: next_pks.iter().map(|h| decode_hex::<32>(h)).collect(),
            };
            let msg = handoff_message(1, from_ep, &next_committee);
            let precompile_ixs: Vec<Vec<u8>> = sigs
                .iter()
                .enumerate()
                .map(|(i, s)| build_precompile_ix(&cur_pks[i], &decode_hex::<64>(s), &msg))
                .collect();
            let handoff = CommitteeHandoffProof {
                next_committee,
                signatures: sigs
                    .iter()
                    .enumerate()
                    .map(|(i, s)| SignerSignature {
                        signer_index: i as u32,
                        signature: decode_hex::<64>(s),
                    })
                    .collect(),
            };
            let new_ep = rotate_committee_with_verifier(&mut state, &handoff, |pk, sig, m| {
                precompile_ixs
                    .iter()
                    .any(|ix| matches_ed25519_precompile_data(ix, pk, sig, m))
            })
            .unwrap();
            assert_eq!(new_ep, from_ep + 1);
        }

        assert_eq!(state.committee.as_ref().unwrap().epoch, 17);
        assert_eq!(
            record_with_verifier(
                &mut state,
                42,
                [0x42; 32],
                [0x99; 32],
                &sample_proof(&[0, 1, 2]),
                |_, _, _| true,
            ),
            Err(ProgramError::Custom(ERR_DOMAIN_MISMATCH))
        );

        let ep17_sigs = ["cf5d96458a77388856afc934a075b94aa61796eb41d42896c16a6cb0918defb63b6d714d7b78ca6efa9c49a17ad83a3ce7de21dbaa9deb880fa7875c9a035207", "4452bf285ace04ebf1e7546eab92b83cfaf65c2803e084d852e1a72a64c15a2f30abd76287f898af2f8cb303a38a1feff61057931228e2922402f8ae504b7807", "767e97c49e4944af8b33dcbe9ae1a2b4c242ac949afb8c5813c704f07dd508f7551c059f3a86ecb2d9c3106bc970e267ab1d98b1352d48a4e8b8a41028cd5904"];
        let ep17_pks = state.committee.as_ref().unwrap().members.clone();
        let ckpt_msg = signing_message(1, 17, 100, &[0xAA; 32], &[0xBB; 32], FinalityMode::Hybrid);
        let ckpt_ixs: Vec<Vec<u8>> = ep17_sigs
            .iter()
            .enumerate()
            .map(|(i, s)| build_precompile_ix(&ep17_pks[i], &decode_hex::<64>(s), &ckpt_msg))
            .collect();
        let ep17_proof = SignedFinalityProof {
            chain_id: 1,
            epoch: 17,
            mode: FinalityMode::Hybrid,
            signatures: ep17_sigs
                .iter()
                .enumerate()
                .map(|(i, s)| SignerSignature {
                    signer_index: i as u32,
                    signature: decode_hex::<64>(s),
                })
                .collect(),
        };
        record_with_verifier(
            &mut state,
            100,
            [0xAA; 32],
            [0xBB; 32],
            &ep17_proof,
            |pk, sig, m| {
                ckpt_ixs
                    .iter()
                    .any(|ix| matches_ed25519_precompile_data(ix, pk, sig, m))
            },
        )
        .unwrap();
        assert!(height_final(&state, 100));
        assert_eq!(root_at_height(&state, 100), [0xAA; 32]);
        assert_eq!(latest_final_height(&state), 100);
        assert_eq!(finality_mode_at_height(&state, 100), FinalityMode::Hybrid);
    }

    #[test]
    fn record_rejects_conflicting_mode_unauthenticated_replay_and_bad_precompile_padding() {
        let mut state = VerifierState::default();
        initialize_committee(&mut state, sample_committee()).unwrap();

        let root = [0x42; 32];
        let header = [0x99; 32];
        let msg = signing_message(1, 7, 42, &root, &header, FinalityMode::Hybrid);
        let precompile_ixs: Vec<Vec<u8>> = (0..3)
            .map(|i| {
                build_precompile_ix(
                    &decode_hex::<32>(MEMBER_PKS[i]),
                    &decode_hex::<64>(MEMBER_SIGS[i]),
                    &msg,
                )
            })
            .collect();

        // Non-canonical header padding byte (data[1] != 0) must be rejected.
        let mut bad_padding_ix = precompile_ixs[0].clone();
        bad_padding_ix[1] = 0xFF;
        assert!(!matches_ed25519_precompile_data(
            &bad_padding_ix,
            &decode_hex::<32>(MEMBER_PKS[0]),
            &decode_hex::<64>(MEMBER_SIGS[0]),
            &msg,
        ));

        let valid_proof = sample_proof(&[0, 1, 2]);
        record_with_verifier(&mut state, 42, root, header, &valid_proof, |pk, sig, m| {
            precompile_ixs
                .iter()
                .any(|ix| matches_ed25519_precompile_data(ix, pk, sig, m))
        })
        .unwrap();
        assert_eq!(state.checkpoints.len(), 1);

        // Conflicting FinalityMode at the same height must fail closed with ERR_CONFLICT.
        let mut conflicting_mode_proof = sample_proof(&[0, 1, 2]);
        conflicting_mode_proof.mode = FinalityMode::ClassicalOnly;
        let err = record_with_verifier(
            &mut state,
            42,
            root,
            header,
            &conflicting_mode_proof,
            |_, _, _| true,
        )
        .unwrap_err();
        assert_eq!(err, ProgramError::Custom(ERR_CONFLICT));

        // Unauthenticated empty-signature replay on an existing height must be rejected.
        let unauthenticated_replay = SignedFinalityProof {
            chain_id: 1,
            epoch: 7,
            mode: FinalityMode::Hybrid,
            signatures: Vec::new(),
        };
        let err = record_with_verifier(
            &mut state,
            42,
            root,
            header,
            &unauthenticated_replay,
            |_, _, _| false,
        )
        .unwrap_err();
        assert_eq!(err, ProgramError::Custom(ERR_QUORUM_NOT_MET));

        // Authenticated replay with a valid quorum remains idempotent without duplicating entries.
        record_with_verifier(&mut state, 42, root, header, &valid_proof, |pk, sig, m| {
            precompile_ixs
                .iter()
                .any(|ix| matches_ed25519_precompile_data(ix, pk, sig, m))
        })
        .unwrap();
        assert_eq!(state.checkpoints.len(), 1);
    }
}
