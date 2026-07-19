#[cfg(test)]
mod tests {
    use crate::bns::BnsError;
    use crate::bns::BnsRegistry;
    use crate::core::address::Address;

    #[test]
    fn test_bns_registration_and_resolution() {
        let mut reg = BnsRegistry::new();
        let alice = Address::from([1u8; 32]);
        let current_epoch = 10;

        // 1. Register a name
        reg.register("ayaz.bud".to_string(), alice, current_epoch, 100)
            .unwrap();

        // 2. Resolve the name
        assert_eq!(reg.resolve("ayaz.bud", current_epoch + 1), Some(alice));

        // 3. Reject duplicate active registration
        let bob = Address::from([2u8; 32]);
        let err = reg
            .register("ayaz.bud".to_string(), bob, current_epoch + 5, 100)
            .unwrap_err();
        assert!(matches!(err, crate::bns::BnsError::NameTaken));
    }

    #[test]
    fn test_bns_expiration() {
        let mut reg = BnsRegistry::new();
        let alice = Address::from([1u8; 32]);
        reg.register("expire.bud".to_string(), alice, 10, 10)
            .unwrap();

        // Active at epoch 15
        assert_eq!(reg.resolve("expire.bud", 15), Some(alice));

        // Expired at epoch 25
        assert_eq!(reg.resolve("expire.bud", 25), None);

        // F14 (Phase 10.5): grace-period — expire (25) + GRACE_PERIOD (3000)
        // içinde 3. parti squat edemez. epoch 30 < 3025 → bob RED.
        let bob = Address::from([2u8; 32]);
        assert!(matches!(
            reg.register("expire.bud".to_string(), bob, 30, 100),
            Err(BnsError::NameTaken)
        ));
        // grace-period sonrası (epoch 3030 > 3025) → bob register OK.
        reg.register("expire.bud".to_string(), bob, 3030, 100)
            .unwrap();
        assert_eq!(reg.resolve("expire.bud", 3035), Some(bob));
    }
}
