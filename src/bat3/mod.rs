//! `Bat3` canonical text journal, zero-residual reconstruction engine,
//! consensus-agnostic fact anchor, and `K1`/`K2`/`K3` privacy layers.
//!
//! WIRING: mounted at `crate::bat3` and called by `crate::explorer_evidence`
//! for verified cross-domain journal and selective-disclosure digests.

pub mod consensus_interface;
pub mod journal;
pub mod privacy_layers;
pub mod reconstruct;

pub use consensus_interface::{Bat3ConsensusError, ConsensusFact, FactBackingClass};
pub use journal::{
    validate_canonical_bat3_text, Bat3Journal, Bat3JournalEntry, Bat3JournalError,
    MAX_BAT3_ENTRY_BYTES, MAX_BAT3_TOPIC_BYTES,
};
pub use privacy_layers::{
    Bat3LayeredRecord, Bat3NullifierSet, Bat3PrivacyError, K2FieldOpening, K2SelectiveEnvelope,
    K3ShieldedRecord, PrivacyTier, MAX_K2_FIELDS,
};
pub use reconstruct::{
    compute_reconstruct_commitment, reconstruct_and_verify, Bat3Blueprint, Bat3ReconstructError,
    ReconstructStep, MAX_BAT3_BLUEPRINT_STEPS, MAX_BAT3_RECONSTRUCT_BYTES,
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cross_domain::external::spec::{
        AdapterId, DomainKey, FinalityAttestation, SecurityBacking, TimeUnit,
    };
    use crate::crypto::facts::ObservedScheme;
    use crate::crypto::scheme::SchemeId;
    use std::collections::BTreeMap;

    #[test]
    fn journal_enforces_nfc_refuses_bidi_and_preserves_odd_leaf_merkle_separation() {
        let mut journal = Bat3Journal::new();
        let e0 = journal
            .append(10, [0x11; 32], "bat3/spec:v1", "deterministic ledger fact")
            .unwrap();
        let e1 = journal
            .append(11, [0x22; 32], "bat3/spec:v1", "second canonical entry")
            .unwrap();
        let e2 = journal
            .append(12, [0x33; 32], "bat3/spec:v1", "third canonical entry")
            .unwrap();
        assert_eq!(e0.sequence(), 0);
        assert_eq!(e1.sequence(), 1);
        assert_eq!(e2.sequence(), 2);
        journal.verify_integrity().unwrap();

        // NFD decomposed "é" must be refused in favor of NFC "é".
        let nfd_err = journal.append(13, [0x44; 32], "bat3/spec:v1", "café");
        assert_eq!(nfd_err, Err(Bat3JournalError::NonNfcText));

        // Bidirectional override U+202E must fail closed.
        let bidi_err = journal.append(13, [0x44; 32], "bat3/spec:v1", "safe\u{202e}evil");
        assert_eq!(
            bidi_err,
            Err(Bat3JournalError::ForbiddenControlChar(0x202E))
        );

        // Odd-leaf Merkle promotion must distinguish [e0, e1, e2] from [e0, e1, e2, e2_dup].
        let root_three = journal.root();
        let mut four = Bat3Journal::new();
        four.append(10, [0x11; 32], "bat3/spec:v1", "deterministic ledger fact")
            .unwrap();
        four.append(11, [0x22; 32], "bat3/spec:v1", "second canonical entry")
            .unwrap();
        four.append(12, [0x33; 32], "bat3/spec:v1", "third canonical entry")
            .unwrap();
        four.append(12, [0x33; 32], "bat3/spec:v1", "third canonical entry")
            .unwrap();
        assert_ne!(root_three, four.root());
    }

    #[test]
    fn zero_residual_reconstruction_roundtrips_and_refuses_tampering_or_bombs() {
        let steps = vec![
            ReconstructStep::LiteralSegment(b"BDLM-BAT3:".to_vec()),
            ReconstructStep::RepeatPattern {
                pattern: vec![0xA5, 0x5A],
                repeat_count: 8,
            },
            ReconstructStep::BackReference {
                back_offset: 4,
                length: 6,
            },
            ReconstructStep::AffineByteRun {
                seed: 7,
                stride: 13,
                mask_byte: 0x3C,
                length: 16,
            },
        ];
        let blueprint = Bat3Blueprint::from_steps(steps).unwrap();
        let out = reconstruct_and_verify(&blueprint).unwrap();
        assert_eq!(out.len(), usize::try_from(blueprint.output_len()).unwrap());

        let mut tampered_json = serde_json::to_value(&blueprint).unwrap();
        let first_byte = tampered_json
            .get_mut("expected_commitment")
            .and_then(|v| v.as_array_mut())
            .and_then(|a| a.first_mut())
            .unwrap();
        *first_byte = serde_json::Value::from((first_byte.as_u64().unwrap() ^ 0x01) & 0xFF);
        let tampered: Bat3Blueprint = serde_json::from_value(tampered_json).unwrap();
        assert_eq!(
            reconstruct_and_verify(&tampered),
            Err(Bat3ReconstructError::CommitmentMismatch)
        );

        // Decompression bomb > 1 MiB must fail closed.
        let bomb = vec![ReconstructStep::RepeatPattern {
            pattern: vec![0xFF; 1024],
            repeat_count: 1025,
        }];
        assert!(matches!(
            Bat3Blueprint::from_steps(bomb),
            Err(Bat3ReconstructError::OutputExceedsCeiling { .. })
        ));
    }

    #[test]
    fn consensus_fact_binds_attestation_and_rejects_unbacked_or_mutated_roots() {
        let entry = Bat3JournalEntry::new(0, 77, [0x99; 32], "bat3/anchor", "state-fact").unwrap();
        let adapter = AdapterId::from_name("aptos-jolteon-2chain-v1");
        let att = FinalityAttestation {
            adapter,
            domain: DomainKey::from_parts(&adapter, "aptos-mainnet"),
            height: 500,
            state_root: [0xAB; 32],
            finalized_at: 500,
            time_unit: TimeUnit::Height,
            security: SecurityBacking::SignatureSet {
                scheme: ObservedScheme::Scheme(SchemeId::ML_DSA_65),
                signers: 3,
                required: 3,
                total_weight: 400,
                slashable: true,
            },
            evidence_digest: [0xCD; 32],
            adapter_version: 1,
            evidence_version: 1,
            attested_block_hash: Some([0xEF; 32]),
            attested_event_root: None,
            attested_tx_root: None,
        };
        let fact = ConsensusFact::bind_from_attestation(&entry, &att).unwrap();
        fact.verify_against_attestation(&entry, &att).unwrap();

        let mut unbacked = att.clone();
        unbacked.security = SecurityBacking::None;
        assert!(matches!(
            ConsensusFact::bind_from_attestation(&entry, &unbacked),
            Err(Bat3ConsensusError::UnbackedAttestation(_))
        ));

        let mut wrong_root = att;
        wrong_root.state_root = [0xAC; 32];
        assert!(matches!(
            fact.verify_against_attestation(&entry, &wrong_root),
            Err(Bat3ConsensusError::AttestationMismatch("state_root"))
        ));
    }

    #[test]
    fn k1_k2_k3_selective_disclosure_and_nullifier_replay_protection() {
        let mut fields = BTreeMap::new();
        fields.insert(
            String::from("credential_holder"),
            (String::from("alice.bud"), [0x11; 32]),
        );
        fields.insert(
            String::from("graduation_year"),
            (String::from("2026"), [0x22; 32]),
        );
        let (env, openings) = K2SelectiveEnvelope::seal(&fields).unwrap();
        openings[0].verify(&env).unwrap();
        openings[1].verify(&env).unwrap();

        let mut forged_json = serde_json::to_value(openings.first().unwrap()).unwrap();
        forged_json.as_object_mut().unwrap().insert(
            String::from("field_value"),
            serde_json::Value::from("mallory.bud"),
        );
        let forged_opening: K2FieldOpening = serde_json::from_value(forged_json).unwrap();
        assert!(matches!(
            forged_opening.verify(&env),
            Err(Bat3PrivacyError::InvalidOpening(_))
        ));

        let k3 =
            K3ShieldedRecord::derive(&[0xAA; 32], &[0xBB; 32], &[0xCC; 32], [0xDD; 32]).unwrap();
        let mut nullifiers = Bat3NullifierSet::new();
        nullifiers.admit_k3(&k3).unwrap();
        assert!(matches!(
            nullifiers.admit_k3(&k3),
            Err(Bat3PrivacyError::DuplicateNullifier(_))
        ));

        let layered = Bat3LayeredRecord::K2(env.clone());
        assert_eq!(layered.tier(), PrivacyTier::K2SelectiveDisclosure);
        let expected_root: [u8; 32] = serde_json::from_value(
            serde_json::to_value(&env)
                .unwrap()
                .get("envelope_root")
                .cloned()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(layered.public_commitment(), expected_root);
    }
}
