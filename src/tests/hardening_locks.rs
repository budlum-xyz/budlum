//! Hardening Protocol H1 regression locks.
//! Marker: REGRESSION - do not delete without replacing coverage.

#[cfg(test)]
mod tests {
    use crate::ai::types::{AiAgentPayment, AiPaymentEscrowStatus, AiRequestId};
    use crate::ai::AiRegistry;
    use crate::core::account::AccountState;
    use crate::core::address::Address;

    use crate::core::transaction::{Transaction, TransactionType, DEFAULT_CHAIN_ID};
    use crate::execution::executor::Executor;

    fn addr(b: u8) -> Address {
        Address::from([b; 32])
    }

    fn payment(id: u8, from: Address, to: Address, amount: u64, escrow: bool) -> AiAgentPayment {
        AiAgentPayment {
            payment_id: [id; 32],
            from_agent: from,
            to_agent: to,
            amount,
            request_id: if escrow {
                Some(AiRequestId([0xEE; 32]))
            } else {
                None
            },
            require_proof: false,
            submitted_at_block: 10,
            expiry_block: 10_000,
        }
    }

    fn payment_tx(from: Address, pay: AiAgentPayment, nonce: u64, fee: u64) -> Transaction {
        let mut tx = Transaction::new_with_chain_id(
            from,
            pay.to_agent,
            0, // value transfer amount separate from payment.amount
            fee,
            nonce,
            vec![],
            DEFAULT_CHAIN_ID,
            TransactionType::AiAgentPayment(pay),
        );
        tx.hash = tx.calculate_hash();
        tx
    }

    /// REGRESSION: sync-committee aggregate requires ≥2/3 (342)
    /// Participation; a low-participation aggregate must be rejected BEFORE any
    /// Signature check (closes the single-valid-pubkey finality bypass).
    #[test]
    fn sync_committee_rejects_low_participation() {
        use crate::cross_domain::evm::sync_committee::{
            verify_sync_aggregate, SyncAggregate, SyncCommitteeError, SyncCommitteeState,
            BLS_PUBKEY_LEN, BLS_SIGNATURE_LEN, PARTICIPATION_THRESHOLD, SYNC_COMMITTEE_SIZE,
        };
        let state = SyncCommitteeState {
            current_period: 0,
            current_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
            next_sync_committee: [[0u8; BLS_PUBKEY_LEN]; SYNC_COMMITTEE_SIZE],
        };
        // Zero-participation aggregate → must be rejected by the threshold gate
        // (which runs before any per-pubkey BLS verification).
        let agg = SyncAggregate {
            sync_committee_bits: [0u8; SYNC_COMMITTEE_SIZE / 8],
            sync_committee_signature: [0u8; BLS_SIGNATURE_LEN],
        };
        let err = verify_sync_aggregate(&state, &agg, b"signing-message")
            .expect_err("low-participation aggregate must be rejected");
        match err {
            SyncCommitteeError::InsufficientParticipation {
                participating,
                threshold,
            } => {
                assert_eq!(participating, 0);
                assert_eq!(threshold, PARTICIPATION_THRESHOLD);
                assert_eq!(threshold, 342, "2/3 of 512 = 342");
            }
            _ => panic!("expected InsufficientParticipation"),
        }
    }

    /// REGRESSION: AiAgentPayment round-trips through proto encode/decode
    /// As AiAgentPayment (not AiFeeReclaim). Previously 4 tx types collided on
    /// The AiFeeReclaim proto enum, making AiAgentPayment undecodable remotely.
    #[test]
    fn ai_agent_payment_proto_roundtrip_preserves_type() {
        use crate::network::proto_conversions::pb::ProtoTransaction;
        let from = addr(0xA1);
        let to = addr(0xB2);
        let pay = payment(0x71, from, to, 500, false);
        let tx = payment_tx(from, pay, 0, 10);
        let proto: ProtoTransaction = (&tx).into();
        let back: Transaction = proto
            .try_into()
            .expect("AiAgentPayment proto round-trip must decode");
        assert!(
            matches!(back.tx_type, TransactionType::AiAgentPayment(_)),
            "AiAgentPayment must round-trip as AiAgentPayment, not AiFeeReclaim"
        );
    }

    /// REGRESSION: non-escrowed settle keeps audit receipt; payment_id not reusable.
    #[test]
    fn non_escrowed_settlement_retains_receipt_and_blocks_reuse() {
        let mut registry = AiRegistry::new();
        let from = addr(0xA1);
        let to = addr(0xB2);
        let pay = payment(0x71, from, to, 500, false);
        registry.submit_agent_payment(pay.clone(), 10).unwrap();
        assert!(registry.get_agent_payment(&pay.payment_id).is_some());

        registry
            .settle_agent_payment_immediate(&pay.payment_id, 11)
            .unwrap();

        assert!(
            registry.get_agent_payment(&pay.payment_id).is_none(),
            "live map must not keep settled immediate payment"
        );
        let receipt = registry
            .get_settled_agent_payment(&pay.payment_id)
            .expect("settlement receipt must exist");
        assert_eq!(receipt.amount, 500);
        assert_eq!(receipt.status, AiPaymentEscrowStatus::SettledImmediate);
        assert_eq!(receipt.settled_at_block, 11);
        assert!(registry.is_payment_id_consumed(&pay.payment_id));

        let reuse = registry.submit_agent_payment(pay, 12);
        assert!(reuse.is_err(), "settled payment_id must not be reusable");
    }

    /// REGRESSION: reclaim archives settlement (audit trail).
    #[test]
    fn reclaim_archives_settlement() {
        let mut registry = AiRegistry::new();
        let from = addr(0xC3);
        let to = addr(0xD4);
        let pay = AiAgentPayment {
            payment_id: [0x72; 32],
            from_agent: from,
            to_agent: to,
            amount: 200,
            request_id: Some(AiRequestId([0xEE; 32])),
            require_proof: false,
            submitted_at_block: 1,
            expiry_block: 5,
        };
        registry.submit_agent_payment(pay, 1).unwrap();
        let amt = registry
            .reclaim_agent_payment(&[0x72; 32], &from, 10)
            .unwrap();
        assert_eq!(amt, 200);
        let receipt = registry
            .get_settled_agent_payment(&[0x72; 32])
            .expect("reclaim must archive");
        assert_eq!(receipt.status, AiPaymentEscrowStatus::Reclaimed);
        assert!(registry
            .submit_agent_payment(
                AiAgentPayment {
                    payment_id: [0x72; 32],
                    from_agent: from,
                    to_agent: to,
                    amount: 1,
                    request_id: None,
                    require_proof: false,
                    submitted_at_block: 20,
                    expiry_block: 100,
                },
                20
            )
            .is_err());
    }

    /// REGRESSION executor path: balances move and settlement retained.
    #[test]
    fn executor_non_escrowed_payment_settles_with_receipt() {
        let mut state = AccountState::new();
        let from = addr(0x11);
        let to = addr(0x22);
        state.get_or_create(&from).balance = 10_000;
        state.current_block_height = 50;

        let pay = payment(0x89, from, to, 1_000, false);
        let tx = payment_tx(from, pay.clone(), 0, 1);
        Executor::apply_transaction(&mut state, &tx).expect("payment must apply");

        assert_eq!(state.get_balance(&from), 10_000 - 1_000 - 1);
        assert_eq!(state.get_balance(&to), 1_000);
        assert!(state
            .ai_registry
            .get_agent_payment(&pay.payment_id)
            .is_none());
        let receipt = state
            .ai_registry
            .get_settled_agent_payment(&pay.payment_id)
            .expect("executor must settle-immediate with receipt");
        assert_eq!(receipt.status, AiPaymentEscrowStatus::SettledImmediate);
        assert_eq!(receipt.amount, 1_000);

        let tx2 = payment_tx(from, pay, 1, 1);
        let err = Executor::apply_transaction(&mut state, &tx2);
        assert!(err.is_err(), "duplicate payment_id must fail");
    }

    /// REGRESSION: from_agent spoof rejected at executor.
    #[test]
    fn from_agent_spoof_rejected() {
        let mut state = AccountState::new();
        let signer = addr(0x11);
        let spoofed = addr(0x99);
        let to = addr(0x22);
        state.get_or_create(&signer).balance = 10_000;
        state.current_block_height = 50;
        let pay = payment(0x84, spoofed, to, 100, false);
        let tx = payment_tx(signer, pay, 0, 1);
        let err = Executor::apply_transaction(&mut state, &tx);
        assert!(err.is_err());
    }
}
