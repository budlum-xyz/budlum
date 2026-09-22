//! Error taxonomy. Every failure is irrefutable by construction: the
//! verifier returns an error, never a panic; the production deny-lints
//! (`unwrap_used`, `expect_used`) are honoured inside this crate too.

use core::fmt;

/// Every way a BPQS operation can refuse.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BpqsError {
    /// The caller asked for more than `q_max` signatures inside one epoch.
    /// Few-time relaxation has a hard ceiling; breaching it is a protocol
    /// fault, not a key compromise - the error is surfaced, never silently
    /// absorbed.
    QuotaExceeded {
        /// Epoch index in which the over-quota request was made.
        epoch: u32,
        /// The per-epoch call count the caller reported.
        attempted: u32,
    },
    /// The signature was minted for a different epoch than the verifier
    /// derived from the chain height. This is the self-timestamping refusal:
    /// shifting an old signature forward (or a future one back) is rejected.
    EpochMismatch {
        /// Epoch the verifier computed from the chain height context.
        expected: u32,
        /// Epoch carried inside the signature.
        in_signature: u32,
    },
    /// The epoch window is zero: dividing a height by zero is meaningless,
    /// and an operator that config-gated this must be told loudly.
    BadEpochWindow,
    /// The Merkle authentication path does not rebuild the committed root.
    BadAuthPath,
    /// The Winternitz chain heads do not rebuild the verification digest.
    BadChain,
    /// Input shape violation (wrong buffer length, truncated signature).
    Malformed(&'static str),
}

impl fmt::Display for BpqsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BpqsError::QuotaExceeded { epoch, attempted } => write!(
                f,
                "epoch {epoch}: signature call #{attempted} exceeds the few-time ceiling"
            ),
            BpqsError::EpochMismatch {
                expected,
                in_signature,
            } => write!(
                f,
                "self-timestamp refusal: verifier epoch {expected}, signature epoch {in_signature}"
            ),
            BpqsError::BadEpochWindow => {
                write!(f, "epoch window is zero; height derivation is undefined")
            }
            BpqsError::BadAuthPath => write!(f, "merkle authentication path refused"),
            BpqsError::BadChain => write!(f, "winternitz chain verification refused"),
            BpqsError::Malformed(what) => write!(f, "malformed input: {what}"),
        }
    }
}

impl core::error::Error for BpqsError {}
