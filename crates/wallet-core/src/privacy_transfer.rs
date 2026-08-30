//! Private transfer intent builder (note/UTXO path).
//!
//! Produces the witness + public commitments a relayer/prover needs to
//! Assemble PrivacyCommit / NullifierCheck / SumConservation VM programs.
//! Does **not** submit on-chain (wallet is not a relayer - see README).

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
        // privacy_commit(amount, blinding, recipient_tag)
        privacy_commit(self.amount, self.blinding, self.recipient_tag)
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
        // privacy_commit(amount, blinding, recipient_tag)
        privacy_commit(self.amount, self.blinding, self.recipient_tag)
    }
}

/// Fully built private transfer intent (public + private halves).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateTransferIntent {
    /// Public commitments for new notes (NoteRegistry insert candidates).
    pub output_commitments: Vec<[u8; 32]>,
    /// Public nullifiers for spent notes (double-spend markers).
    pub nullifiers: Vec<[u8; 32]>,
    /// Σ input amounts (SumConservation rs1 witness - private).
    pub sum_in: u64,
    /// Σ output amounts (SumConservation rs2 witness - private).
    pub sum_out: u64,
    /// Per-input witnesses (never broadcast in clear if TEE active).
    pub inputs: Vec<PrivateNoteInput>,
    /// Per-output witnesses.
    pub outputs: Vec<PrivateNoteOutput>,
    /// Domain-separated digest over public halves for wallet signature.
    pub public_digest: [u8; 32],
    /// ML-DSA-87 signature over `public_digest` (authorization).
    pub authorization_sig: [u8; crate::ML_DSA_87_SIGNATURE_LEN],
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
    let out: [u8; 32] = h.finalize().into();
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = out;
    u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
}

/// Derive blinding from wallet seed + counter (deterministic UX helper).
#[must_use]
pub fn derive_blinding(wallet_seed: &[u8; 32], counter: u64) -> u64 {
    use sha3::{Digest, Sha3_256};
    let mut h = Sha3_256::new();
    h.update(b"BUDLUM_NOTE_BLINDING_V1");
    h.update(wallet_seed);
    h.update(counter.to_le_bytes());
    let out: [u8; 32] = h.finalize().into();
    let [b0, b1, b2, b3, b4, b5, b6, b7, ..] = out;
    u64::from_le_bytes([b0, b1, b2, b3, b4, b5, b6, b7])
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
        // Read as a refusal, not as `expect("validated")`. The two fields are
        // checked in `validate_conservation` a few lines up, so the panic was
        // unreachable on today's code - but it was unreachable only because of
        // a check somewhere else in the file. Reordering that check, or adding
        // a second caller that skips it, turns a wallet building a change
        // output into a process that aborts while holding the user's note
        // witnesses. The refusal costs one match and cannot become a panic.
        let (Some(recipient_tag), Some(blinding)) = (req.change_recipient_tag, req.change_blinding)
        else {
            return Err(WalletError::InvalidPrivateTransfer(
                "change output requires change_recipient_tag and change_blinding".into(),
            ));
        };
        outs.push(PrivateNoteOutput {
            amount: change,
            recipient: [0u8; 32], // change to self - caller fills address if needed
            recipient_tag,
            blinding,
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

#[cfg(test)]
mod change_output_tests {
    use super::*;

    fn request_with_change(tag: Option<u64>, blinding: Option<u64>) -> PrivateTransferRequest {
        PrivateTransferRequest {
            input: PrivateNoteInput {
                amount: 100,
                recipient_tag: 7,
                blinding: 11,
                spend_secret: 13,
            },
            to: [1u8; 32],
            send_amount: 40,
            output_blinding: 17,
            change_recipient_tag: tag,
            change_blinding: blinding,
        }
    }

    /// A change output needs both of its secrets, and the answer is a refusal.
    ///
    /// `build_outputs` used to read these two fields with `expect("validated")`.
    /// It was correct only because `validate_conservation` runs first - so the
    /// guarantee lived in the call order, not in the code depending on it.
    ///
    /// On today's tree this test passes against both versions, because the
    /// early `validate_conservation()?` refuses first and the `expect` is
    /// never reached. That is exactly the point, and it is why the difference
    /// was measured by mutation rather than assumed: deleting the
    /// `validate_conservation()?` line from `build_outputs` leaves this test
    /// green on the `let ... else` version and makes it fail with
    /// `panicked at privacy_transfer.rs` on the `expect` version. The refusal
    /// is what survives losing a guard somewhere else.
    #[test]
    fn a_change_output_missing_one_secret_is_refused_not_a_panic() {
        for (tag, blinding, missing) in [
            (None, Some(23u64), "recipient tag"),
            (Some(19u64), None, "blinding"),
            (None, None, "both"),
        ] {
            let req = request_with_change(tag, blinding);
            let err = build_outputs(&req)
                .expect_err("a change output without its {missing} must be refused, never built");
            assert!(
                matches!(err, WalletError::InvalidPrivateTransfer(_)),
                "missing {missing}: expected a private-transfer refusal, got {err:?}"
            );
        }
    }

    /// The refusal must not swallow the transfers that are actually complete.
    #[test]
    fn a_change_output_carrying_both_secrets_is_built() {
        let req = request_with_change(Some(19), Some(23));
        let outs = build_outputs(&req).expect("a complete request must build");
        assert_eq!(outs.len(), 2, "payment and change");
        assert_eq!(outs[1].amount, 60, "change is input minus send");
        assert_eq!(outs[1].recipient_tag, 19);
        assert_eq!(outs[1].blinding, 23);
    }

    /// No change means no second output, and no secrets are required for it.
    #[test]
    fn an_exact_spend_needs_no_change_secrets() {
        let mut req = request_with_change(None, None);
        req.send_amount = req.input.amount;
        let outs = build_outputs(&req).expect("an exact spend has no change output");
        assert_eq!(outs.len(), 1, "payment only");
    }
}
