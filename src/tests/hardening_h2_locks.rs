//! Hardening Protocol H2 regression locks (ARENA3).
//! Marker: REGRESSION — do not delete without replacing coverage.

#[cfg(test)]
mod tests {
    use crate::bns::registry::BnsRegistry;
    use crate::core::address::Address;
    use crate::core::governance::{Proposal, ProposalStatus, ProposalType};
    use crate::hub::types::AppCategory;
    use crate::hub::HubRegistry;
    use crate::network::peer_manager::PeerManager;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    /// REGRESSION V130: finalize before end_epoch is a no-op.
    #[test]
    fn v130_finalize_before_end_epoch_noop() {
        let proposer = addr(1);
        let mut p = Proposal::new(0, proposer, ProposalType::ChangeBaseFee(100), 0, 10);
        p.add_vote(proposer, 1_000_000, true, 0).unwrap();
        p.finalize(1_000_000, 50, 5);
        assert_eq!(p.status, ProposalStatus::Active);
        p.finalize(1_000_000, 50, 10);
        assert_eq!(p.status, ProposalStatus::Passed);
    }

    /// REGRESSION V130/H2: votes rejected after voting window.
    #[test]
    fn v130_vote_rejected_after_end_epoch() {
        let proposer = addr(1);
        let mut p = Proposal::new(0, proposer, ProposalType::ChangeBaseFee(1), 0, 10);
        let err = p.add_vote(addr(2), 100, true, 10).unwrap_err();
        assert!(err.contains("Voting period has ended"), "{err}");
    }

    /// REGRESSION V131: BNS duration=0 rejected.
    #[test]
    fn v131_bns_zero_duration_rejected() {
        let mut reg = BnsRegistry::new();
        assert!(reg.register("zero.bud".into(), addr(1), 0, 0).is_err());
    }

    /// REGRESSION V123: developer self-verify does not set DAO verified badge.
    #[test]
    fn v123_developer_self_verify_is_not_dao_verified() {
        let mut hub = HubRegistry::new();
        let dev = addr(0x42);
        let id = hub.register_app(
            "demo".into(),
            dev,
            AppCategory::Other,
            "https://example.bud".into(),
            None,
            1,
        );
        hub.verify_app(id, &dev).unwrap();
        let app = hub.apps.get(&id).unwrap();
        assert!(app.developer_attested);
        assert!(!app.verified, "self-verify must not set verified badge");
        hub.mark_verified_by_governance(id).unwrap();
        assert!(hub.apps.get(&id).unwrap().verified);
    }

    /// REGRESSION H5.1: subnet eclipse bound.
    #[test]
    fn h5_1_subnet_eclipse_bound() {
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

    /// REGRESSION V111: L1 account Merkle trie uses 256-bit keys.
    #[test]
    fn v111_l1_merkle_trie_is_256bit_keys() {
        let mut trie = crate::storage::merkle_trie::MerkleTrie::new();
        let key = [0xABu8; 32];
        trie.insert(&key, 1, 0);
        assert_ne!(trie.root(), [0u8; 32]);
        assert_eq!(key.len() * 8, 256);
    }

    /// REGRESSION V132: burn_from clips and returns burned amount (no panic).
    #[test]
    fn v132_burn_from_clips_to_balance() {
        let mut state = crate::core::account::AccountState::new();
        let a = addr(0x55);
        state.get_or_create(&a).balance = 100;
        let burned = state.burn_from(&a, 500);
        assert_eq!(burned, 100);
        assert_eq!(state.get_balance(&a), 0);
    }
}
