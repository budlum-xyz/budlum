use budlum_core::consensus::merkle_tree::odd_promotion_sentinel;
use budlum_core::crypto::facts::QuantumClass;
use budlum_core::settlement::notary::{
    anchor_notary_entries, verify_notary_proof_offline, NotaryAnchorRequest, NotaryEntry,
    NotaryError, NotaryTimestampProof, StaticSealKeySet,
};
use budlum_core::settlement::pq_anchor::{AnchorLeaf, AnchorMode, PqAnchor};
use budlum_core::settlement::root_seal::{
    build_root_seal, SealError, SealKeys, SealSigner, SoftwareSealSigner, ROOT_SEAL_INTERVAL,
};

fn must<T, E: std::fmt::Debug>(res: Result<T, E>, msg: &str) -> T {
    match res {
        Ok(v) => v,
        Err(e) => panic!("{msg}: {e:?}"),
    }
}

struct SuspendedSealKeySet {
    key_index: u8,
    public_key: Vec<u8>,
}

impl SealKeys for SuspendedSealKeySet {
    fn seal_key(&self, index: u8) -> Option<&[u8]> {
        (index == self.key_index).then_some(self.public_key.as_slice())
    }

    fn seal_key_suspended(&self, index: u8, _key_epoch: u32) -> bool {
        index == self.key_index
    }
}

fn deterministic_signer(seed_byte: u8) -> SoftwareSealSigner {
    let seed = vec![seed_byte; 96];
    must(
        SoftwareSealSigner::from_seed(&seed),
        "valid 96-byte SLH-DSA-SHAKE-256s seed",
    )
}

fn sample_entries(count: usize, height: u64) -> Vec<NotaryEntry> {
    (0..count)
        .map(|i| {
            let mut digest = [0u8; 32];
            digest[0] = must(u8::try_from(i + 1), "small index");
            digest[31] = 0xA5;
            NotaryEntry {
                document_digest: digest,
                height,
                label: format!("release-v1.{i}"),
            }
        })
        .collect()
}

fn sample_extra_anchor(chain_id: u64, height: u64, tag: u8, key_epoch: u32) -> PqAnchor {
    PqAnchor {
        chain_id,
        height,
        aggregate_root: [tag; 32],
        stark_root: None,
        crossdomain_root: None,
        key_epoch,
        signatures: Vec::new(),
    }
}

#[test]
fn quantum_safe_notary_roundtrip_offline_across_odd_and_even_batches_and_chained_seals() {
    let signer = deterministic_signer(0x42);
    let keys = must(
        StaticSealKeySet::new(0, signer.public_key()),
        "64-byte SLH-DSA pubkey",
    );
    let chain_id = 45_261;
    let key_epoch = 1;

    for &(entry_count, entry_idx, extra_anchor_heights) in &[
        (5usize, 4usize, &[360u64, 1080u64][..]),
        (4usize, 2usize, &[720u64][..]),
        (1usize, 0usize, &[][..]),
    ] {
        let entries = sample_entries(entry_count, 1440);
        let extra_leaves = [
            AnchorLeaf {
                finality_digest: [0x33; 32],
                quantum_class: QuantumClass::Lattice,
            },
            AnchorLeaf {
                finality_digest: [0x44; 32],
                quantum_class: QuantumClass::Hash,
            },
        ];
        let extra_anchors: Vec<PqAnchor> = extra_anchor_heights
            .iter()
            .enumerate()
            .map(|(i, &h)| {
                sample_extra_anchor(
                    chain_id,
                    h,
                    must(u8::try_from(0x50 + i), "small tag"),
                    key_epoch,
                )
            })
            .collect();

        let req = NotaryAnchorRequest {
            mode: AnchorMode::Devnet,
            chain_id,
            anchor_height: 1800,
            seal_height: ROOT_SEAL_INTERVAL,
            key_epoch,
            key_index: 0,
            previous_seal: None,
            extra_anchor_leaves: &extra_leaves,
            extra_period_anchors: &extra_anchors,
        };
        let mut proof = must(
            anchor_notary_entries(&req, &entries, entry_idx, &signer),
            "notary anchoring succeeds",
        );

        let period2_anchor =
            sample_extra_anchor(chain_id, ROOT_SEAL_INTERVAL + 360, 0x77, key_epoch);
        let seal2 = must(
            build_root_seal(
                chain_id,
                ROOT_SEAL_INTERVAL * 2,
                &[period2_anchor],
                Some(&proof.seal),
                key_epoch,
                0,
                &signer,
            ),
            "second seal builds",
        );
        proof.seal_chain.push(seal2.clone());

        let json = must(serde_json::to_string(&proof), "serialize");
        let decoded: NotaryTimestampProof = must(serde_json::from_str(&json), "deserialize");

        let verified = must(
            verify_notary_proof_offline(
                &decoded,
                Some(entries[entry_idx].document_digest),
                chain_id,
                &keys,
                key_epoch,
            ),
            "offline hash-only verification must pass",
        );

        assert_eq!(verified.document_digest, entries[entry_idx].document_digest);
        assert_eq!(verified.entry_height, 1440);
        assert_eq!(verified.anchor_height, 1800);
        assert_eq!(verified.seal_height, ROOT_SEAL_INTERVAL);
        assert_eq!(verified.latest_seal_height, ROOT_SEAL_INTERVAL * 2);
        assert_eq!(verified.latest_seal_digest, seal2.digest());
        assert_eq!(verified.quantum_class, QuantumClass::Hash);
        assert_eq!(verified.anchor_mode, AnchorMode::Devnet);
    }
}

#[test]
fn quantum_safe_notary_refuses_all_tamper_and_boundary_vectors_fail_closed() {
    let signer = deterministic_signer(0x19);
    let other_signer = deterministic_signer(0x2A);
    let keys = must(StaticSealKeySet::new(0, signer.public_key()), "64-byte pk");
    let other_keys = must(
        StaticSealKeySet::new(0, other_signer.public_key()),
        "64-byte pk",
    );
    let chain_id = 45_261;
    let key_epoch = 3;

    let entries = sample_entries(3, 700);
    let prod_req = NotaryAnchorRequest {
        mode: AnchorMode::ProductionApproved,
        chain_id,
        anchor_height: 720,
        seal_height: ROOT_SEAL_INTERVAL,
        key_epoch,
        key_index: 0,
        previous_seal: None,
        extra_anchor_leaves: &[],
        extra_period_anchors: &[],
    };
    assert_eq!(
        anchor_notary_entries(&prod_req, &entries, 0, &signer),
        Err(NotaryError::ProductionModeBlocked)
    );

    let dev_req = NotaryAnchorRequest {
        mode: AnchorMode::Devnet,
        ..prod_req
    };
    let bad_zero = [NotaryEntry {
        document_digest: [0u8; 32],
        height: 700,
        label: "ok".into(),
    }];
    assert!(matches!(
        anchor_notary_entries(&dev_req, &bad_zero, 0, &signer),
        Err(NotaryError::ZeroDigest { .. })
    ));
    let bad_label = [NotaryEntry {
        document_digest: [1u8; 32],
        height: 700,
        label: "bad\nlabel".into(),
    }];
    assert_eq!(
        anchor_notary_entries(&dev_req, &bad_label, 0, &signer),
        Err(NotaryError::InvalidLabel)
    );

    let base = must(
        anchor_notary_entries(&dev_req, &entries, 2, &signer),
        "valid baseline",
    );
    assert!(verify_notary_proof_offline(
        &base,
        Some(entries[2].document_digest),
        chain_id,
        &keys,
        key_epoch
    )
    .is_ok());

    assert_eq!(
        verify_notary_proof_offline(&base, Some([0xFF; 32]), chain_id, &keys, key_epoch),
        Err(NotaryError::DigestMismatch)
    );

    let mut bad_doc = base.clone();
    bad_doc.notary_proof.entry.document_digest[0] ^= 1;
    assert!(matches!(
        verify_notary_proof_offline(&bad_doc, None, chain_id, &keys, key_epoch),
        Err(NotaryError::InvalidMerkleProof(_))
    ));

    let mut bad_count = base.clone();
    bad_count.notary_proof.leaf_count = 4;
    assert!(matches!(
        verify_notary_proof_offline(&bad_count, None, chain_id, &keys, key_epoch),
        Err(NotaryError::InvalidMerkleProof(_))
    ));
    let mut extra_sib = base.clone();
    extra_sib
        .notary_proof
        .siblings
        .push(odd_promotion_sentinel());
    assert!(matches!(
        verify_notary_proof_offline(&extra_sib, None, chain_id, &keys, key_epoch),
        Err(NotaryError::InvalidMerkleProof(_))
    ));

    let mut bad_class = base.clone();
    bad_class.anchor_proof.leaf.quantum_class = QuantumClass::Lattice;
    assert_eq!(
        verify_notary_proof_offline(&bad_class, None, chain_id, &keys, key_epoch),
        Err(NotaryError::NonHashAnchorClass)
    );

    let mut bad_anchor = base.clone();
    bad_anchor.anchor.aggregate_root[0] ^= 0x80;
    assert!(matches!(
        verify_notary_proof_offline(&bad_anchor, None, chain_id, &keys, key_epoch),
        Err(NotaryError::InvalidMerkleProof(_))
    ));

    let mut bad_sig = base.clone();
    bad_sig.seal.signature[0] ^= 0x01;
    assert_eq!(
        verify_notary_proof_offline(&bad_sig, None, chain_id, &keys, key_epoch),
        Err(NotaryError::Seal(SealError::InvalidSignature))
    );

    assert_eq!(
        verify_notary_proof_offline(&base, None, chain_id, &other_keys, key_epoch),
        Err(NotaryError::Seal(SealError::InvalidSignature))
    );
    let suspended = SuspendedSealKeySet {
        key_index: 0,
        public_key: signer.public_key(),
    };
    assert_eq!(
        verify_notary_proof_offline(&base, None, chain_id, &suspended, key_epoch),
        Err(NotaryError::Seal(SealError::KeySuspended {
            index: 0,
            key_epoch
        }))
    );
    assert_eq!(
        verify_notary_proof_offline(&base, None, chain_id + 1, &keys, key_epoch),
        Err(NotaryError::AnchorWrongChain {
            expected: chain_id + 1,
            got: chain_id
        })
    );
    assert_eq!(
        verify_notary_proof_offline(&base, None, chain_id, &keys, key_epoch + 1),
        Err(NotaryError::Seal(SealError::StaleKeyEpoch {
            seal_epoch: key_epoch,
            current_epoch: key_epoch + 1
        }))
    );

    let period2_anchor = sample_extra_anchor(chain_id, ROOT_SEAL_INTERVAL + 360, 0x66, key_epoch);
    let broken_seal2 = must(
        build_root_seal(
            chain_id,
            ROOT_SEAL_INTERVAL * 2,
            &[period2_anchor],
            None,
            key_epoch,
            0,
            &signer,
        ),
        "builds unlinked seal",
    );
    let mut bad_chain = base;
    bad_chain.seal_chain.push(broken_seal2);
    assert_eq!(
        verify_notary_proof_offline(&bad_chain, None, chain_id, &keys, key_epoch),
        Err(NotaryError::BrokenSealChain {
            seal_height: ROOT_SEAL_INTERVAL * 2
        })
    );
}
