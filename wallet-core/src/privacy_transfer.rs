//! Private transfer intent builder (D2 note/UTXO path).
//!
//! Produces the witness + public commitments a relayer/prover needs to
//! assemble PrivacyCommit / NullifierCheck / SumConservation VM programs.
//! Does **not** submit on-chain (wallet is not a relayer — CLAUDE.md §2).

use crate::privacy_crypto::{address_to_recipient_tag, privacy_commit, privacy_nullifier};
use crate::{BudlumAddress, WalletError};

/// One spent input note (wallet-side witness).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateNoteInput {
    pub amount: u64,
    /// Recipient tag used when the note was created (field limb).
    pub recipient_tag: u64,
    pub blinding: u64,
    /// Spending key / nullifier secret (field limb).
    pub spend_secret: u64,
}

impl PrivateNoteInput {
    #[must_use]
    pub fn commitment(&self) -> u64 {
        privacy_commit(self.amount, self.recipient_tag, self.blinding)
    }

    #[must_use]
    pub fn nullifier(&self) -> u64 {
        privacy_nullifier(self.spend_secret)
    }
}

/// One created output note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateNoteOutput {
    pub amount: u64,
    pub recipient: BudlumAddress,
    pub recipient_tag: u64,
    pub blinding: u64,
}

impl PrivateNoteOutput {
    #[must_use]
    pub fn commitment(&self) -> u64 {
        privacy_commit(self.amount, self.recipient_tag, self.blinding)
    }
}

/// Fully built private transfer intent (public + private halves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateTransferIntent {
    /// Public commitments for new notes (NoteRegistry insert candidates).
    pub output_commitments: Vec<[u8; 32]>,
    /// Public nullifiers for spent notes (double-spend markers).
    pub nullifiers: Vec<[u8; 32]>,
    /// Σ input amounts (SumConservation rs1 witness — private).
    pub sum_in: u64,
    /// Σ output amounts (SumConservation rs2 witness — private).
    pub sum_out: u64,
    /// Per-input witnesses (never broadcast in clear if TEE active).
    pub inputs: Vec<PrivateNoteInput>,
    /// Per-output witnesses.
    pub outputs: Vec<PrivateNoteOutput>,
    /// Domain-separated digest over public halves for wallet signature.
    pub public_digest: [u8; 32],
    /// Ed25519 signature over `public_digest` (authorization).
    pub authorization_sig: [u8; 64],
}

/// Build parameters for a simple 1-in → 1-out (+ optional change) transfer.
#[derive(Debug, Clone)]
pub struct PrivateTransferRequest {
    pub input: PrivateNoteInput,
    pub to: BudlumAddress,
    pub send_amount: u64,
    /// Blinding for the payment output.
    pub output_blinding: u64,
    /// If input.amount > send_amount, change returns to this tag with this blinding.
    pub change_recipient_tag: Option<u64>,
    pub change_blinding: Option<u64>,
}

impl PrivateTransferRequest {
    pub fn validate_conservation(&self) -> Result<(), WalletError> {
        if self.send_amount == 0 {
            return Err(WalletError::InvalidPrivateTransfer(
                "send_amount must be > 0".into(),
            ));
        }
        if self.send_amount > self.input.amount {
            return Err(WalletError::InvalidPrivateTransfer(format!(
                "send_amount {} exceeds input {}",
                self.send_amount, self.input.amount
            )));
        }
        let change = self.input.amount - self.send_amount;
        if change > 0 && (self.change_recipient_tag.is_none() || self.change_blinding.is_none()) {
            return Err(WalletError::InvalidPrivateTransfer(
                "change output requires change_recipient_tag and change_blinding".into(),
            ));
        }
        Ok(())
    }
}

/// Derive a field-element spend secret from wallet seed + note commitment.
#[must_use]
pub fn derive_spend_secret(wallet_seed: &[u8; 32], note_commitment: u64) -> u64 {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"BUDLUM_NOTE_SPEND_SECRET_V1");
    h.update(wallet_seed);
    h.update(note_commitment.to_le_bytes());
    let out = h.finalize();
    u64::from_le_bytes(out[..8].try_into().unwrap())
}

/// Derive blinding from wallet seed + counter (deterministic UX helper).
#[must_use]
pub fn derive_blinding(wallet_seed: &[u8; 32], counter: u64) -> u64 {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"BUDLUM_NOTE_BLINDING_V1");
    h.update(wallet_seed);
    h.update(counter.to_le_bytes());
    let out = h.finalize();
    u64::from_le_bytes(out[..8].try_into().unwrap())
}

pub(crate) fn build_outputs(
    req: &PrivateTransferRequest,
) -> Result<Vec<PrivateNoteOutput>, WalletError> {
    req.validate_conservation()?;
    let payment_tag = address_to_recipient_tag(&req.to);
    let mut outs = vec![PrivateNoteOutput {
        amount: req.send_amount,
        recipient: req.to,
        recipient_tag: payment_tag,
        blinding: req.output_blinding,
    }];
    let change = req.input.amount - req.send_amount;
    if change > 0 {
        outs.push(PrivateNoteOutput {
            amount: change,
            recipient: [0u8; 32], // change to self — caller fills address if needed
            recipient_tag: req.change_recipient_tag.expect("validated"),
            blinding: req.change_blinding.expect("validated"),
        });
    }
    Ok(outs)
}

pub(crate) fn public_digest(nullifiers: &[[u8; 32]], output_commitments: &[[u8; 32]]) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"BUDLUM_PRIVATE_TRANSFER_V1");
    h.update((nullifiers.len() as u64).to_le_bytes());
    for n in nullifiers {
        h.update(n);
    }
    h.update((output_commitments.len() as u64).to_le_bytes());
    for c in output_commitments {
        h.update(c);
    }
    h.finalize().into()
}
