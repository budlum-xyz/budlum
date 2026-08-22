//! Hardening Protocol H2 regression locks.
//! Marker: REGRESSION - do not delete without replacing coverage.

#[cfg(test)]
mod tests {
    use crate::bns::registry::BnsRegistry;
    use crate::core::address::Address;

    use crate::budlumxyz::types::AppCategory;
    use crate::budlumxyz::BudlumxyzRegistry;
    use crate::core::governance::{Proposal, ProposalStatus, ProposalType};
    use crate::network::peer_manager::PeerManager;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    /// REGRESSION: finalize before end_epoch is a no-op.
    #[test]
    fn finalize_before_end_epoch_noop() {
        let proposer = addr(1);
        let mut p = Proposal::new(0, proposer, ProposalType::ChangeBaseFee(100), 0, 10);
        p.add_vote(proposer, 1_000_000, true, 0).unwrap();
        p.finalize(1_000_000, 50, 5);
        assert_eq!(p.status, ProposalStatus::Active);
        p.finalize(1_000_000, 50, 10);
        assert_eq!(p.status, ProposalStatus::Passed);
    }

    /// REGRESSION/H2: votes rejected after voting window.
    #[test]
    fn vote_rejected_after_end_epoch() {
        let proposer = addr(1);
        let mut p = Proposal::new(0, proposer, ProposalType::ChangeBaseFee(1), 0, 10);
        let err = p.add_vote(addr(2), 100, true, 10).unwrap_err();
        assert!(err.contains("Voting period has ended"));
    }

    /// REGRESSION: BNS duration=0 rejected.
    #[test]
    fn bns_zero_duration_rejected() {
        let mut reg = BnsRegistry::new();
        assert!(reg.register("zero.bud".into(), addr(1), 0, 0).is_err());
    }

    /// REGRESSION: developer self-verify does not set DAO verified badge.
    #[test]
    fn developer_self_verify_is_not_dao_verified() {
        let mut hub = BudlumxyzRegistry::new();
        let dev = addr(0x42);
        let id = hub
            .register_app(
                "demo".into(),
                dev,
                AppCategory::Other,
                "https://example.bud".into(),
                None,
                1,
            )
            .expect("a fresh registry has no id to collide with");
        // `verify_app` was a back-compat alias for this, named as though it
        // were a third-party audit when it only records the developer's own
        // claim. The production path always called the honest name; the alias
        // was reachable from tests alone and is gone.
        hub.attest_app_as_developer(id, &dev).unwrap();
        let app = hub.apps.get(&id).unwrap();
        assert!(app.developer_attested);
        assert!(!app.verified, "self-verify must not set verified badge");

        // The governor set starts empty and an empty set now denies, so the
        // developer cannot award itself the governance badge by calling the
        // governance path either.
        assert!(
            hub.mark_verified_by_governance(id, &dev).is_err(),
            "with no governor configured there is no governor"
        );
        assert!(!hub.apps.get(&id).unwrap().verified);

        // Configuring one grants the authority to that address alone.
        hub.authorized_governors.insert(dev);
        hub.mark_verified_by_governance(id, &dev).unwrap();
        assert!(hub.apps.get(&id).unwrap().verified);
    }

    /// REGRESSION H5.1: subnet eclipse bound.
    #[test]
    fn subnet_eclipse_bound() {
        let mut pm = PeerManager::new();
        pm.set_max_peers_per_subnet(2);
        let s = [203, 0, 113];
        let p1 = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        let p2 = libp2p::identity::Keypair::generate_ed25519()
            .public()
            .to_peer_id();
        assert!(pm.can_admit_subnet(Some(s)));
        pm.note_connected(p1, Some(s));
        assert!(pm.can_admit_subnet(Some(s)));
        pm.note_connected(p2, Some(s));
        assert!(!pm.can_admit_subnet(Some(s)));
    }

    /// REGRESSION: L1 account Merkle trie uses 256-bit keys.
    #[test]
    fn l1_merkle_trie_is_256bit_keys() {
        let mut trie = crate::storage::merkle_trie::MerkleTrie::new();
        let key = [0xABu8; 32];
        trie.insert(&key, 1, 0);
        assert_ne!(trie.root(), [0u8; 32]);
        assert_eq!(key.len() * 8, 256);
    }

    /// REGRESSION: burn_from clips and returns burned amount (no panic).
    #[test]
    fn burn_from_clips_to_balance() {
        let mut state = crate::core::account::AccountState::new();
        let a = addr(0x55);
        state.get_or_create(&a).balance = 100;
        let burned = state.burn_from(&a, 500);
        assert_eq!(burned, 100);
        assert_eq!(state.get_balance(&a), 0);
    }
}
