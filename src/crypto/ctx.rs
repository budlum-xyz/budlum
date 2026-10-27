//! FIPS 204 and FIPS 205 context strings.
//!
//! Every ML-DSA and SLH-DSA signature and verification in this tree passes a
//! non-empty context string. FIPS 204 section 5.2 and FIPS 205 section 10.2
//! make the context part of the signed message, so a signature made for one
//! surface does not verify on another even when the payload bytes are equal.
//! The context is a second separation layer under the `BDLM_*` hash tags; it
//! does not replace them.
//!
//! The table below is section 6.5 of plus a small set of
//! registered extras for signing surfaces that exist today and are not in the
//! table (`EXTRAS`). A context is at most 255 bytes (FIPS 204
//! section 5.2); every string here is far shorter.
//!
//! An empty context is refused by the verification facade
//! ([`super::pq::verify`]) on every chain. The `pq-ctx-is-bound` gate reads
//! this file: a call site must name one of these constants, never a literal.
//!
//! This file has no dependency on the rest of the node. `crates/wallet-core`
//! mounts the same source (see `docs/pq/README.md`).

/// The longest context FIPS 204 and FIPS 205 accept, in bytes.
pub const MAX_CONTEXT_LEN: usize = 255;

/// User transaction and bundle (TxV7).
pub const TX_V7: &[u8] = b"BDLM/TX/V7";
/// Multisig transaction (TxV8).
pub const TX_V8: &[u8] = b"BDLM/TX/V8";
/// Block.
pub const BLOCK_V6: &[u8] = b"BDLM/BLOCK/V6";
/// Quorum certificate blob.
pub const QC_V2: &[u8] = b"BDLM/QC/V2";
/// Handoff Certificate.
pub const HANDOFF_V1: &[u8] = b"BDLM/HANDOFF/V1";
/// Anchor.
pub const ANCHOR_V2: &[u8] = b"BDLM/ANCHOR/V2";
/// Root Seal.
pub const SEAL_V1: &[u8] = b"BDLM/SEAL/V1";
/// Cold committee.
pub const COLD_V1: &[u8] = b"BDLM/COLD/V1";
/// Evidence.
pub const EVIDENCE_V2: &[u8] = b"BDLM/EVIDENCE/V2";
/// Snapshot manifest.
pub const SNAPSHOT_V2: &[u8] = b"BDLM/SNAPSHOT/V2";
/// PoA authority signature.
pub const POA_V2: &[u8] = b"BDLM/POA/V2";
/// Storage deal and channel.
pub const STORAGE_V2: &[u8] = b"BDLM/STORAGE/V2";
/// Pollen.
pub const POLLEN_V2: &[u8] = b"BDLM/POLLEN/V2";
/// Identity registry.
pub const IDENTITY_V2: &[u8] = b"BDLM/IDENTITY/V2";
/// Peer identity.
pub const PEER_V1: &[u8] = b"BDLM/PEER/V1";
/// Recovery key (SLH-DSA).
pub const RECOVERY_V1: &[u8] = b"BDLM/RECOVERY/V1";
/// Filiz commitment record.
pub const FILIZ_V1: &[u8] = b"BDLM/FILIZ/V1";
/// Canary proof.
pub const CANARY_V1: &[u8] = b"BDLM/CANARY/V1";
/// Reseal certificate.
pub const RESEAL_V1: &[u8] = b"BDLM/RESEAL/V1";
/// Release signature.
pub const RELEASE_V1: &[u8] = b"BDLM/RELEASE/V1";

/// V5 user transaction (ML-DSA-87 alone). Devnet only: TxV7 replaces it.
pub const TX_V5: &[u8] = b"BDLM/TX/V5";
/// V6 threshold multisig transaction. Devnet only: TxV8 replaces it.
pub const TX_V6: &[u8] = b"BDLM/TX/V6";
/// Guardian vote on a wallet recovery proposal.
pub const GUARDIAN_V1: &[u8] = b"BDLM/GUARDIAN/V1";
/// TEE attestation binding.
pub const TEE_V1: &[u8] = b"BDLM/TEE/V1";
/// Private transfer authorization.
pub const PRIVATE_TRANSFER_V1: &[u8] = b"BDLM/PRIVATE_TRANSFER/V1";
/// Key file pairing probe and HSM key binding message.
pub const KEY_BINDING_V1: &[u8] = b"BDLM/KEY_BINDING/V1";

/// A bridge-transfer holder's authorization of a burn (the debit half of a
/// mint). Separate from the transaction context because the holder authorizes
/// the burn and the fee payer authorizes the transaction; one may be the other
/// and neither is implied by the other.
pub const BRIDGE_V1: &[u8] = b"BDLM/BRIDGE/V1";

/// A cross-domain message sender's authentication of the message id (the
/// envelope that binds the relayed message, `BDLM/...`). Distinct from the
/// relay transaction's own context: the sender authenticates the message and
/// the submitting relayer authenticates the transaction.
pub const CROSS_DOMAIN_V1: &[u8] = b"BDLM/CROSS_DOMAIN/V1";

/// table, in the order of section 6.5.
pub const TABLE: &[&[u8]] = &[
    TX_V7,
    TX_V8,
    BLOCK_V6,
    QC_V2,
    HANDOFF_V1,
    ANCHOR_V2,
    SEAL_V1,
    COLD_V1,
    EVIDENCE_V2,
    SNAPSHOT_V2,
    POA_V2,
    STORAGE_V2,
    POLLEN_V2,
    IDENTITY_V2,
    PEER_V1,
    RECOVERY_V1,
    FILIZ_V1,
    CANARY_V1,
    RESEAL_V1,
    RELEASE_V1,
];

/// Registered extras for signing surfaces that exist today and have no row in
/// table.
pub const EXTRAS: &[&[u8]] = &[
    TX_V5,
    TX_V6,
    GUARDIAN_V1,
    TEE_V1,
    PRIVATE_TRANSFER_V1,
    KEY_BINDING_V1,
    BRIDGE_V1,
    CROSS_DOMAIN_V1,
];

/// Whether `ctx` is a registered context string.
#[must_use]
pub fn is_registered(ctx: &[u8]) -> bool {
    TABLE.contains(&ctx) || EXTRAS.contains(&ctx)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ctx_strings_are_unique_ascii_and_short() {
        let mut seen: Vec<&[u8]> = Vec::new();
        for ctx in TABLE.iter().chain(EXTRAS.iter()) {
            assert!(!ctx.is_empty(), "an empty context is never registered");
            assert!(ctx.len() <= MAX_CONTEXT_LEN);
            assert!(ctx.starts_with(b"BDLM/"));
            assert!(ctx
                .iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || matches!(b, b'/' | b'_')));
            assert!(!seen.contains(ctx), "duplicate context string");
            seen.push(ctx);
        }
        assert_eq!(TABLE.len(), 20, "section 6.5 lists twenty contexts");
    }

    #[test]
    fn ctx_is_registered_accepts_only_the_registry() {
        assert!(is_registered(TX_V7));
        assert!(is_registered(TX_V5));
        assert!(!is_registered(b""));
        assert!(!is_registered(b"BDLM/TX/V9"));
    }
}
