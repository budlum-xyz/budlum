//! Hardening Protocol H1 regression locks (ARENA3).
//! Marker: REGRESSION — do not delete without replacing coverage.

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

    /// REGRESSION V89: non-escrowed settle keeps audit receipt; payment_id not reusable.
    #[test]
    fn v89_non_escrowed_settlement_retains_receipt_and_blocks_reuse() {
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
            .expect("V89 settlement receipt must exist");
        assert_eq!(receipt.amount, 500);
        assert_eq!(receipt.status, AiPaymentEscrowStatus::SettledImmediate);
        assert_eq!(receipt.settled_at_block, 11);
        assert!(registry.is_payment_id_consumed(&pay.payment_id));

        let reuse = registry.submit_agent_payment(pay, 12);
        assert!(
            reuse.is_err(),
            "V89: settled payment_id must not be reusable"
        );
    }

    /// REGRESSION V86/V89: reclaim archives settlement (audit trail).
    #[test]
    fn v86_v89_reclaim_archives_settlement() {
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

    /// REGRESSION V89 executor path: balances move and settlement retained.
    #[test]
    fn v89_executor_non_escrowed_payment_settles_with_receipt() {
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

    /// REGRESSION V84: from_agent spoof rejected at executor.
    #[test]
    fn v84_from_agent_spoof_rejected() {
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
