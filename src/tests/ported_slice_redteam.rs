//! Adversarial probes over the identity slice this branch carries.
//!
//! The slice arrived as a port, so it gets what any carried code gets: an
//! adversary, not a reader. Every probe below is a refusal the slice *claims*
//! to make - written from the claim, then run against the code. A probe that
//! fails is a bug in the slice, not a badly written test; a probe that passes
//! is the claim turned into something that cannot silently stop being true.
//!
//! What is probed, and why each one is worth a test of its own:
//!
//! - **DID parsing.** The parse is the wire boundary: a spelling it accepts
//!   but the registry stores differently is a duplicated identity.
//! - **The PoA write gate.** The master registry has exactly one writable
//!   domain. Every other domain must be refused *before* anything is read.
//! - **Sender binding.** `from` must BE the subject, the issuer, or the
//!   rotating DID. Naming somebody else in the payload is the shape every
//!   authority bug in this tree has had.
//! - **Content-derived ids.** A credential id computed from the payload would
//!   let a stranger reach a victim's credential by re-issuing its bytes.
//! - **Quorum arithmetic.** Approvals are counted as *distinct guardians*,
//!   never as signatures: one guardian signing three times is one vote.

#![cfg(test)]

use crate::core::address::Address;
use crate::core::hash::hash_fields_bytes;
use crate::domain::ConsensusKind;
use crate::registry::{
    address_of_did, credential_id, did_of, execute_identity_tx, field_commitment, fill_template,
    template_slots, CredentialCommitment, FieldCommitment, FillError, IdentityError, IdentityOp,
    IdentityRecord, IdentityRegistry, IdentityTx, MethodKind, SlotDisclosure, VerificationMethod,
};

fn addr(byte: u8) -> Address {
    Address([byte; 32])
}

fn method(key: u8) -> VerificationMethod {
    VerificationMethod::new([key; 32], MethodKind::MlDsa87)
}

/// Subject `0x01..`, one live key, two guardians, quorum two.
fn subject_record() -> IdentityRecord {
    IdentityRecord::new(addr(1), vec![method(1)], vec![addr(2), addr(3)], 2).unwrap()
}

/// Issuer `0x09..`, registered on its own, no guardians.
fn issuer_record() -> IdentityRecord {
    IdentityRecord::new(addr(9), vec![method(9)], vec![], 0).unwrap()
}

/// A well-formed credential from `issuer` to the subject `0x01..`.
fn credential(issuer: u8, issued_at: u64, expires_at: Option<u64>) -> CredentialCommitment {
    let salt = [7u8; 32];
    let value = hash_fields_bytes(&[b"v", &[10]]);
    CredentialCommitment {
        issuer: addr(issuer),
        subject: addr(1),
        schema: "kycc-lite-v1".to_string(),
        fields: vec![FieldCommitment {
            name: "legal_name".to_string(),
            commitment: field_commitment("kycc-lite-v1", "legal_name", &salt, &value),
        }],
        issued_at,
        expires_at,
    }
}

/// A registry holding both DIDs, on the domain that may write it.
fn two_dids() -> IdentityRegistry {
    let mut registry = IdentityRegistry::new();
    registry
        .apply(
            &ConsensusKind::PoA,
            IdentityOp::Register {
                record: issuer_record(),
            },
            0,
        )
        .unwrap();
    registry
        .apply(
            &ConsensusKind::PoA,
            IdentityOp::Register {
                record: subject_record(),
            },
            0,
        )
        .unwrap();
    registry
}

const POA: ConsensusKind = ConsensusKind::PoA;

#[test]
fn a_did_parses_in_one_spelling_only() {
    let a = addr(0xab);
    let did = did_of(&a);
    assert_eq!(did, format!("did:bud:{}", "ab".repeat(32)));
    assert_eq!(address_of_did(&did), Some(a), "the canonical spelling must round-trip");

    // Every near miss is a refusal, not a normalization: an accepted
    // alternate spelling is the same key stored under two identities.
    assert_eq!(address_of_did(&did.to_uppercase()), None);
    assert_eq!(address_of_did(&format!("did:bud:{}", "aB".repeat(32))), None);
    assert_eq!(address_of_did(&format!("{did} ")), None, "a trailing space is not a DID");
    assert_eq!(address_of_did(&format!("{did}00")), None, "too long");
    assert_eq!(address_of_did(&format!("did:bud:{}", "0".repeat(63))), None, "too short");
    assert_eq!(address_of_did(&format!("did:bud:{}", "z".repeat(64))), None, "non-hex");
    assert_eq!(address_of_did("did:bud:"), None, "no hex at all");
    assert_eq!(address_of_did(""), None);
    assert_eq!(address_of_did(&format!("did:example:{}", "0".repeat(64))), None, "wrong method");

    // The all-zero address is a real address, not a sentinel: it must parse.
    assert_eq!(
        address_of_did(&format!("did:bud:{}", "0".repeat(64))),
        Some(addr(0)),
        "the zero address is parseable; whether it may act is another door's question"
    );
}

#[test]
fn only_the_poa_domain_writes_the_master_registry() {
    // `Custom("PoA")` is in the list on purpose: the gate matches the variant,
    // not a label an operator can type into an open door.
    let domains = [
        ConsensusKind::PoW,
        ConsensusKind::PoS,
        ConsensusKind::Bft,
        ConsensusKind::Zk,
        ConsensusKind::Custom("PoA".to_string()),
    ];
    for domain in domains {
        let mut registry = IdentityRegistry::new();
        let err = registry
            .apply(
                &domain,
                IdentityOp::Register {
                    record: subject_record(),
                },
                0,
            )
            .unwrap_err();
        assert!(
            matches!(err, IdentityError::NotPoaDomain { .. }),
            "{domain:?} wrote the master identity registry"
        );
        assert!(
            registry.is_empty(),
            "{domain:?} was refused but left state behind"
        );
    }
}

#[test]
fn the_write_gate_answers_before_the_payload_is_read() {
    // A record that would fail validation anyway must still be refused for
    // the domain, not for the record: otherwise the refusal leaks which
    // payloads the registry would have looked at.
    let mut registry = IdentityRegistry::new();
    let broken = IdentityRecord {
        subject: addr(1),
        methods: vec![],
        credential_root: None,
        guardians: vec![],
        recovery_threshold: 0,
    };
    let err = registry
        .apply(&ConsensusKind::PoW, IdentityOp::Register { record: broken }, 0)
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::NotPoaDomain { .. }),
        "the domain gate must answer before validation, got {err:?}"
    );
}

#[test]
fn a_credential_id_is_content_derived_so_a_forged_issuer_reaches_nothing() {
    let mut registry = two_dids();
    let real = credential(9, 100, Some(1_000));
    execute_identity_tx(
        &mut registry,
        &addr(9),
        IdentityTx::Issue {
            credential: real.clone(),
        },
        &POA,
        200,
        1,
    )
    .unwrap();

    // The stranger copies the victim's bytes and names itself issuer. If the
    // id were anything but content-derived, this would resolve to the
    // victim's credential and revoke it.
    let forged = credential(77, 100, Some(1_000));
    assert_ne!(
        credential_id(&forged),
        credential_id(&real),
        "two credentials differing only in issuer share an id"
    );
    let err = execute_identity_tx(
        &mut registry,
        &addr(77),
        IdentityTx::Revoke {
            credential: forged,
        },
        &POA,
        200,
        1,
    )
    .unwrap_err();
    assert!(
        matches!(err, IdentityError::UnknownCredential),
        "a forged issuer reached a credential it does not own: {err:?}"
    );
    assert!(!registry.is_revoked(&credential_id(&real)));

    // And handing over the victim's real credential is refused at the sender
    // rule, before the registry is touched at all.
    let err = execute_identity_tx(
        &mut registry,
        &addr(77),
        IdentityTx::Revoke {
            credential: real.clone(),
        },
        &POA,
        200,
        1,
    )
    .unwrap_err();
    assert!(
        matches!(err, IdentityError::BadApproval(_)),
        "a stranger revoked with the victim's own payload: {err:?}"
    );
    assert!(
        !registry.is_revoked(&credential_id(&real)),
        "the refused revocation still landed"
    );
}

#[test]
fn a_revocation_is_not_a_toggle() {
    let mut registry = two_dids();
    let c = credential(9, 100, Some(1_000));
    let id = credential_id(&c);
    execute_identity_tx(
        &mut registry,
        &addr(9),
        IdentityTx::Issue {
            credential: c.clone(),
        },
        &POA,
        200,
        1,
    )
    .unwrap();
    execute_identity_tx(
        &mut registry,
        &addr(9),
        IdentityTx::Revoke {
            credential: c.clone(),
        },
        &POA,
        300,
        1,
    )
    .unwrap();
    assert!(registry.is_revoked(&id));

    let err = execute_identity_tx(
        &mut registry,
        &addr(9),
        IdentityTx::Revoke { credential: c },
        &POA,
        400,
        1,
    )
    .unwrap_err();
    assert!(
        matches!(err, IdentityError::AlreadyRevoked),
        "revoking twice must be a refusal, not a silent no-op: {err:?}"
    );
}

#[test]
fn issuance_refuses_a_credential_from_the_future_or_born_dead() {
    let mut registry = two_dids();

    let future = credential(9, 500, Some(1_000));
    let err = execute_identity_tx(
        &mut registry,
        &addr(9),
        IdentityTx::Issue {
            credential: future,
        },
        &POA,
        200,
        1,
    )
    .unwrap_err();
    assert!(
        matches!(err, IdentityError::FromTheFuture { issued_at: 500, now: 200 }),
        "a credential dated ahead of the chain was accepted: {err:?}"
    );

    // `expires_at == issued_at` is the boundary: dead on arrival.
    let dead = credential(9, 100, Some(100));
    let err = execute_identity_tx(
        &mut registry,
        &addr(9),
        IdentityTx::Issue { credential: dead },
        &POA,
        200,
        1,
    )
    .unwrap_err();
    assert!(
        matches!(err, IdentityError::ExpiredAtIssuance { issued_at: 100, expiry: 100 }),
        "a credential expiring at its own issuance was accepted: {err:?}"
    );
}

#[test]
fn an_unregistered_subject_cannot_be_handed_a_credential() {
    let mut registry = IdentityRegistry::new();
    registry
        .apply(
            &POA,
            IdentityOp::Register {
                record: issuer_record(),
            },
            0,
        )
        .unwrap();
    // The subject `0x01..` was never registered.
    let err = execute_identity_tx(
        &mut registry,
        &addr(9),
        IdentityTx::Issue {
            credential: credential(9, 100, Some(1_000)),
        },
        &POA,
        200,
        1,
    )
    .unwrap_err();
    assert!(
        matches!(err, IdentityError::UnknownSubject { .. }),
        "a credential was issued to a DID the registry does not know: {err:?}"
    );
}

#[test]
fn the_same_credential_cannot_be_issued_twice() {
    let mut registry = two_dids();
    let c = credential(9, 100, Some(1_000));
    execute_identity_tx(
        &mut registry,
        &addr(9),
        IdentityTx::Issue {
            credential: c.clone(),
        },
        &POA,
        200,
        1,
    )
    .unwrap();
    let err = execute_identity_tx(
        &mut registry,
        &addr(9),
        IdentityTx::Issue { credential: c },
        &POA,
        200,
        1,
    )
    .unwrap_err();
    assert!(
        matches!(err, IdentityError::AlreadyIssued { .. }),
        "one credential became two: {err:?}"
    );
}

#[test]
fn quorum_counts_guardians_not_signatures() {
    // One short of the threshold.
    let mut registry = two_dids();
    let err = registry
        .guardian_recovery(addr(1), [9; 32], &[addr(2)], 500)
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::QuorumShort { need: 2, got: 1, .. }),
        "the quorum check moved: {err:?}"
    );
    let untouched = registry.record(&addr(1)).unwrap();
    assert!(
        untouched.methods.iter().all(|m| m.revoked_at.is_none()),
        "a refused recovery revoked keys anyway"
    );

    // One guardian signing three times is one vote. This is the whole point
    // of counting set membership rather than approvals.
    let mut registry = two_dids();
    let err = registry
        .guardian_recovery(addr(1), [9; 32], &[addr(2), addr(2), addr(2)], 500)
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::QuorumShort { need: 2, got: 1, .. }),
        "three signatures from one guardian reached a quorum of two: {err:?}"
    );

    // Strangers are not counted, and they do not make up the difference.
    let mut registry = two_dids();
    let err = registry
        .guardian_recovery(addr(1), [9; 32], &[addr(2), addr(77), addr(88)], 500)
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::QuorumShort { need: 2, got: 1, .. }),
        "non-guardians were counted toward the quorum: {err:?}"
    );

    // A DID with no guardians has no quorum to reach.
    let mut registry = IdentityRegistry::new();
    registry
        .apply(
            &POA,
            IdentityOp::Register {
                record: issuer_record(),
            },
            0,
        )
        .unwrap();
    let err = registry
        .guardian_recovery(addr(9), [5; 32], &[addr(2)], 500)
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::NoGuardians { .. }),
        "a guardianless DID rotated its key: {err:?}"
    );
}

#[test]
fn recovery_rotates_once_and_a_replay_meets_the_live_key() {
    let mut registry = two_dids();
    registry
        .guardian_recovery(addr(1), [9; 32], &[addr(2), addr(3)], 500)
        .unwrap();

    {
        let record = registry.record(&addr(1)).unwrap();
        let old = record
            .methods
            .iter()
            .find(|m| m.key_id == [1; 32])
            .expect("the original method survives the rotation as a revocation");
        let new = record
            .methods
            .iter()
            .find(|m| m.key_id == [9; 32])
            .expect("the rotated-in method is present");
        assert_eq!(old.revoked_at, Some(500), "the old key must die at the rotation epoch");
        assert!(
            !old.is_live_at(500),
            "a key revoked at epoch N is still live at N"
        );
        assert!(new.is_live_at(500), "the new key is not live at its own epoch");
    }

    // Replaying the same approvals must not rotate a second time: the key is
    // already live, and a second rotation would revoke the one just installed.
    let err = registry
        .guardian_recovery(addr(1), [9; 32], &[addr(2), addr(3)], 600)
        .unwrap_err();
    assert!(
        matches!(err, IdentityError::DuplicateKeyId { .. }),
        "a replayed recovery rotated the DID again: {err:?}"
    );
}

#[test]
fn a_record_cannot_be_built_past_its_own_guard_rules() {
    // The order below is the order `validate` checks in; each probe names the
    // rule it expects, so a reordered check shows up as a wrong variant
    // rather than as a passing test.
    let err = IdentityRecord::new(addr(1), vec![], vec![], 0).unwrap_err();
    assert!(matches!(err, IdentityError::NoMethods { .. }), "{err:?}");

    let err = IdentityRecord::new(addr(1), vec![method(1), method(1)], vec![], 0).unwrap_err();
    assert!(matches!(err, IdentityError::DuplicateKeyId { .. }), "{err:?}");

    let err = IdentityRecord::new(addr(1), vec![method(1)], vec![addr(1)], 1).unwrap_err();
    assert!(
        matches!(err, IdentityError::SubjectIsOwnGuardian { .. }),
        "a DID was its own guardian: {err:?}"
    );

    let err = IdentityRecord::new(addr(1), vec![method(1)], vec![addr(2), addr(2)], 1).unwrap_err();
    assert!(
        matches!(err, IdentityError::DuplicateGuardian { .. }),
        "a guardian listed twice was accepted: {err:?}"
    );

    let err = IdentityRecord::new(addr(1), vec![method(1)], vec![addr(2)], 2).unwrap_err();
    assert!(
        matches!(err, IdentityError::UnreachableQuorum { threshold: 2, guardians: 1, .. }),
        "a quorum no guardian set could meet was accepted: {err:?}"
    );

    // Threshold zero *with* guardians is refused too: a recovery that needs
    // nobody is a key rotation anybody can perform.
    let err = IdentityRecord::new(addr(1), vec![method(1)], vec![addr(2)], 0).unwrap_err();
    assert!(
        matches!(err, IdentityError::UnreachableQuorum { threshold: 0, .. }),
        "a zero threshold with guardians present was accepted: {err:?}"
    );

    let err = IdentityRecord::new(addr(1), vec![method(1)], vec![], 1).unwrap_err();
    assert!(
        matches!(err, IdentityError::ThresholdWithoutGuardians { .. }),
        "{err:?}"
    );
}

fn disclosure(slot: &str, value: &str) -> SlotDisclosure {
    SlotDisclosure {
        slot: slot.to_string(),
        credential_id: [1; 32],
        field: "legal_name".to_string(),
        value: value.to_string(),
        salt: [2; 32],
    }
}

#[test]
fn a_template_may_be_written_in_turkish() {
    // The ported parser walked the template one BYTE at a time and then asked
    // `str::get(cursor..)`, which answers `None` from inside a multi-byte
    // character. Every template containing a non-ASCII character was
    // therefore refused as malformed. In a product whose users write Turkish
    // that is not an edge case, it is the ordinary case - and the refusal
    // named the wrong cause, so nothing pointed at the real one.
    let template = "İsim: {{ad}}\nDoğum: {{dogum_tarihi}}";
    let slots = template_slots(template).expect("a Turkish template is not malformed");
    assert_eq!(
        slots,
        vec!["ad".to_string(), "dogum_tarihi".to_string()],
        "the slot list must not depend on the template's alphabet"
    );

    let filled = fill_template(
        template,
        &[
            disclosure("ad", "Ayşe Yılmaz"),
            disclosure("dogum_tarihi", "1990-01-01"),
        ],
    )
    .expect("the fill must not depend on the template's alphabet either");
    assert_eq!(filled, "İsim: Ayşe Yılmaz\nDoğum: 1990-01-01");
}

#[test]
fn multibyte_values_survive_and_the_grammar_refusals_still_bite() {
    // Values as well as templates: a multi-byte value must land intact.
    let filled = fill_template("ad: {{ad}}", &[disclosure("ad", "ğüşöçİ🎉")]).unwrap();
    assert_eq!(filled, "ad: ğüşöçİ🎉");

    // The rewrite tightened the walk; it must not have loosened the grammar.
    assert!(matches!(
        template_slots("ad: {{ad"),
        Err(FillError::MalformedTemplate(_))
    ), "an unclosed slot was accepted");
    assert!(matches!(
        template_slots("ad: }}"),
        Err(FillError::MalformedTemplate(_))
    ), "a stray closer was accepted");
    assert!(
        matches!(template_slots("ad: {{}}"), Err(FillError::EmptySlot)),
        "a nameless slot was accepted"
    );
    assert!(
        matches!(
            template_slots("{{a}} {{a}}"),
            Err(FillError::DuplicateSlot { .. })
        ),
        "a repeated slot was accepted"
    );

    // And the single-pass guarantee: a value carrying grammar is refused
    // rather than re-scanned, which is how "ad: {{tc_kimlik}}" would become a
    // disclosure no consent screen ever showed.
    let err = fill_template("ad: {{ad}}", &[disclosure("ad", "{{tc_kimlik}}")]).unwrap_err();
    assert!(
        matches!(err, FillError::ValueCarriesBraces { .. }),
        "a value carrying template grammar was substituted: {err}"
    );
}
