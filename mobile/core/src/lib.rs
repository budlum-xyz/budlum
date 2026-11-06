//! Budlum mobile validator core (`budlum-mobile-core`).
//!
//! WP-11, 2/N. The production path is [`duty::MobileCore`]. A phone runs
//! custody duties without linking `budlum-core`. Later slices add UniFFI,
//! libp2p, the light client and `crates/budlum-types`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::expect_used, clippy::unwrap_used))]

pub mod custody;
pub mod duty;
pub mod error;
pub mod handover;
pub mod hash;
pub mod policy;
pub mod presence;
pub mod quota;
pub mod relay;
pub mod store;

pub use custody::{Audit, CustodyProof, CustodyProofBatch, ProofContext};
pub use duty::{Connection, CoreStatus, DutyTx, LastAudit, MobileCore, TESTNET_CHAIN_ID};
pub use error::CoreError;
pub use handover::{fetch_from_holders, Holder, ShareSource, SHARE_OWNER_TIMEOUT};
pub use policy::{NetworkPolicy, Policy, PowerPolicy};
pub use presence::{
    is_presence_double_sign, presence_preimage, PresenceSignal, ResumeValidator, ValidatorClass,
    PRESENCE_TAG, PRESENCE_TOPIC,
};
pub use quota::{
    FREE_SPACE_FLOOR_BYTES, QUOTA_DEFAULT_BYTES, QUOTA_MAX_BYTES, QUOTA_MIN_BYTES,
};
pub use relay::{RelayOffer, RelayPool};
pub use store::{AssignedShare, ShareId, ShareRecord, ShareStore};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::custody::{prove, symbol_leaf, symbol_root, sub_block_count};
    use crate::hash::sha256;
    use crate::quota::below_floor;

    const OWNER: [u8; 32] = [9u8; 32];
    const SECRET: [u8; 32] = [7u8; 32];

    fn mock_sign(preimage: &[u8; 32]) -> Vec<u8> {
        let mut msg = Vec::from(SECRET);
        msg.extend_from_slice(preimage);
        sha256(&msg).to_vec()
    }

    fn mock_verify(public: &[u8], preimage: &[u8; 32], sig: &[u8]) -> bool {
        public == OWNER.as_slice() && sig.as_slice() == mock_sign(preimage).as_slice()
    }

    fn placed_symbol(symbol: &[u8], esi: u32) -> (AssignedShare, Audit) {
        let leaf = symbol_leaf(symbol);
        let placed = vec![(esi, leaf)];
        let assigned = AssignedShare {
            object: [3u8; 32],
            segment: 1,
            esi,
            position: 0,
            symbol: symbol.to_vec(),
            placed,
        };
        let audit = Audit {
            segment: 1,
            position: 0,
            sub_block: 0,
        };
        (assigned, audit)
    }

    fn fixture(available: u64) -> MobileCore {
        MobileCore::new(OWNER, ValidatorClass::Mobile, relays(), available)
    }

    fn relays() -> Vec<RelayOffer> {
        vec![
            RelayOffer {
                multiaddr: "/ip4/1.1.1.1/udp/4001/quic-v1".to_string(),
                capacity_kbps: 8_000,
            },
            RelayOffer {
                multiaddr: "/ip4/2.2.2.2/udp/4001/quic-v1".to_string(),
                capacity_kbps: 8_000,
            },
        ]
    }

    #[test]
    fn mobile_core_answers_custody_audit() {
        let symbol = vec![0xABu8; 200];
        let (assigned, audit) = placed_symbol(&symbol, 7);
        let mut core = fixture(8 * QUOTA_MIN_BYTES);
        core.start();
        let ack = core.accept_share(assigned.clone()).expect("accept");
        assert!(matches!(ack, DutyTx::CustodyAck { .. }));
        let duty = core.answer_audit(assigned.object, audit).expect("audit");
        let DutyTx::CustodyProofBatch(batch) = duty else {
            panic!("expected a proof batch");
        };
        assert_eq!(batch.proofs.len(), 1);
        let ctx = ProofContext {
            symbol_root: symbol_root(&assigned.placed),
            symbol_count: 1,
            sub_blocks: sub_block_count(symbol.len()),
        };
        batch.proofs[0].verify(&audit, &ctx).expect("verify");
        assert_eq!(core.status().last_audit, LastAudit::Passed);
        // A proof for another sub-block still verifies against the same root.
        let extra = prove(1, &assigned.placed, 0, &symbol, 1).expect("second sub-block");
        extra
            .verify(
                &Audit {
                    segment: 1,
                    position: 0,
                    sub_block: 1,
                },
                &ctx,
            )
            .expect("second sub-block verifies");
    }

    #[test]
    fn mobile_core_refuses_unprovable_share_placements() {
        let symbol = vec![0xabu8; 64];
        let (assigned, audit) = placed_symbol(&symbol, 7);
        let mut core = fixture(8 * QUOTA_MIN_BYTES);

        let mut out_of_range = assigned.clone();
        out_of_range.position = 1;
        assert_eq!(
            core.accept_share(out_of_range).expect_err("position").code,
            "mobile_share_leaf_mismatch"
        );

        let mut wrong_position = assigned.clone();
        wrong_position.placed.insert(0, (3, symbol_leaf(b"other")));
        assert_eq!(
            core.accept_share(wrong_position).expect_err("wrong entry").code,
            "mobile_share_leaf_mismatch"
        );

        let mut duplicate = assigned.clone();
        duplicate.placed.push(duplicate.placed[0]);
        assert_eq!(
            core.accept_share(duplicate).expect_err("duplicate ESI").code,
            "mobile_share_placement_order"
        );

        let mut unordered = assigned.clone();
        unordered.placed.push((3, symbol_leaf(b"other")));
        assert_eq!(
            core.accept_share(unordered).expect_err("unordered").code,
            "mobile_share_placement_order"
        );
        assert_eq!(core.status().stored_bytes, 0);
        core.accept_share(assigned.clone()).expect("valid placement");
        core.answer_audit(assigned.object, audit).expect("valid proof");
    }

    #[test]
    fn mobile_core_audits_the_requested_object() {
        let (first, audit) = placed_symbol(&[1; 64], 7);
        let (mut second, _) = placed_symbol(&[2; 64], 7);
        second.object = [4; 32];
        let mut core = fixture(8 * QUOTA_MIN_BYTES);
        core.accept_share(first.clone()).expect("first object");
        core.accept_share(second.clone()).expect("second object");

        let DutyTx::CustodyProofBatch(batch) = core
            .answer_audit(second.object, audit)
            .expect("second object's audit")
        else {
            panic!("expected a proof batch");
        };
        let context = ProofContext {
            symbol_root: symbol_root(&second.placed),
            symbol_count: 1,
            sub_blocks: sub_block_count(second.symbol.len()),
        };
        batch.proofs[0].verify(&audit, &context).expect("proof");
        assert_eq!(
            core.answer_audit([5; 32], audit).expect_err("unknown object").code,
            "mobile_audit_unknown_share"
        );
    }

    #[test]
    fn mobile_core_presence_signal_verifies() {
        let core = fixture(8 * QUOTA_MIN_BYTES);
        let DutyTx::Presence(signal) = core.presence_signal(11, [10, 0, 0, 8], mock_sign) else {
            panic!("expected a presence signal");
        };
        assert!(signal.verify_with(TESTNET_CHAIN_ID, mock_verify));
        assert!(!signal.verify_with(1, mock_verify));
        let preimage = presence_preimage(TESTNET_CHAIN_ID, 11, ValidatorClass::Mobile);
        assert_eq!(signal.sig_bls, mock_sign(&preimage));
        // Same window, different class: a double-sign.
        let other = PresenceSignal::sign(
            OWNER,
            TESTNET_CHAIN_ID,
            11,
            ValidatorClass::Full,
            signal.network_hint,
            mock_sign,
        );
        assert!(is_presence_double_sign(&signal, &other));
        assert_ne!(
            presence_preimage(TESTNET_CHAIN_ID, 11, ValidatorClass::Mobile),
            presence_preimage(TESTNET_CHAIN_ID, 11, ValidatorClass::Full)
        );
        assert_eq!(PRESENCE_TOPIC, "/budlum/presence/1");
        assert_eq!(PRESENCE_TAG, b"BDLM_PRESENCE_V1");
    }

    #[test]
    fn mobile_core_switches_relay_on_drop() {
        let mut core = fixture(8 * QUOTA_MIN_BYTES);
        core.start();
        let first = match core.status().connection {
            Connection::Relay(r) => r,
            Connection::Down => panic!("expected a relay"),
        };
        let second = core.on_relay_drop().expect("next relay");
        assert_ne!(first.multiaddr, second.multiaddr);
        match core.status().connection {
            Connection::Relay(r) => assert_eq!(r, second),
            Connection::Down => panic!("still bound"),
        }
        let back = core.on_relay_drop().expect("wrap");
        assert_eq!(back, first);
    }

    #[test]
    fn mobile_core_respects_quota_floor() {
        let symbol = vec![0x11u8; 1_000];
        let (assigned, _) = placed_symbol(&symbol, 1);
        let mut core = fixture(8 * QUOTA_MIN_BYTES);
        core.accept_share(assigned.clone()).expect("accept");
        assert!(core.status().stored_bytes > 0);
        // Free space below 2 GB: the core releases shares.
        core.set_available_bytes(FREE_SPACE_FLOOR_BYTES - 1);
        assert!(below_floor(core.available_bytes()));
        let released = core.release_for_floor().expect("release");
        assert!(matches!(released, DutyTx::ReleaseShares { .. }));
        assert_eq!(core.status().stored_bytes, 0);
        assert_eq!(core.policy().quota_bytes, QUOTA_MIN_BYTES);
        assert!(core.available_bytes() >= FREE_SPACE_FLOOR_BYTES);
        // After the floor fire, a new share is refused until space returns.
        core.set_available_bytes(FREE_SPACE_FLOOR_BYTES - 1);
        let err = core.accept_share(assigned).expect_err("floor");
        assert_eq!(err.code, "mobile_free_space_floor");
        // Quota itself refuses a share that does not fit. The store is tested
        // with a small quota so this test does not allocate a gibibyte.
        let tiny = vec![0x22u8; 50];
        let (assigned_tiny, _) = placed_symbol(&tiny, 2);
        let mut store = ShareStore::new();
        let err = store.accept(assigned_tiny, 10).expect_err("quota");
        assert_eq!(err.code, "mobile_quota_exceeded");
        assert!(Policy::unmetered_only_by_default());
        let mut p = Policy::default();
        assert!(p.set_thermal_pause(false).is_err());
        assert!(p.set_quota(QUOTA_MIN_BYTES - 1).is_err());
        assert!(p.set_quota(QUOTA_MAX_BYTES + 1).is_err());
    }

    #[test]
    fn mobile_core_refuses_share_that_would_cross_free_space_floor() {
        let symbol = vec![0x44; 100];
        let (assigned, _) = placed_symbol(&symbol, 4);
        let mut core = fixture(FREE_SPACE_FLOOR_BYTES + 99);
        assert_eq!(
            core.accept_share(assigned.clone()).expect_err("floor").code,
            "mobile_free_space_floor"
        );
        assert_eq!(core.status().stored_bytes, 0);
        assert_eq!(core.available_bytes(), FREE_SPACE_FLOOR_BYTES + 99);
        assert!(core.drain_duties().is_empty());

        core.set_available_bytes(FREE_SPACE_FLOOR_BYTES + 100);
        core.accept_share(assigned).expect("exactly at floor");
        assert_eq!(core.available_bytes(), FREE_SPACE_FLOOR_BYTES);
        assert_eq!(core.status().stored_bytes, 100);
    }

    struct Silent;
    impl ShareSource for Silent {
        fn fetch(&self, _holder: &Holder, _timeout: std::time::Duration) -> Option<Vec<u8>> {
            None
        }
    }

    struct SecondAnswers {
        second: [u8; 32],
        body: Vec<u8>,
    }
    impl ShareSource for SecondAnswers {
        fn fetch(&self, holder: &Holder, timeout: std::time::Duration) -> Option<Vec<u8>> {
            assert_eq!(timeout, SHARE_OWNER_TIMEOUT);
            if holder.address == self.second {
                Some(self.body.clone())
            } else {
                None
            }
        }
    }

    #[test]
    fn mobile_core_handover_tries_next_holder_after_timeout() {
        let core = fixture(8 * QUOTA_MIN_BYTES);
        let a = Holder { address: [1u8; 32] };
        let b = Holder { address: [2u8; 32] };
        let err = core
            .fetch_symbol(&[a.clone(), b.clone()], &Silent)
            .expect_err("silent");
        assert_eq!(err.code, "mobile_share_owners_silent");
        let body = b"symbol-bytes".to_vec();
        let got = core
            .fetch_symbol(
                &[a, b.clone()],
                &SecondAnswers {
                    second: b.address,
                    body: body.clone(),
                },
            )
            .expect("second holder");
        assert_eq!(got, body);
        assert_eq!(SHARE_OWNER_TIMEOUT, std::time::Duration::from_secs(2));
    }
}
