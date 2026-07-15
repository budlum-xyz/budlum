#[cfg(test)]
mod tests {
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

        // Can be re-registered after expiration
        let bob = Address::from([2u8; 32]);
        reg.register("expire.bud".to_string(), bob, 30, 100)
            .unwrap();
        assert_eq!(reg.resolve("expire.bud", 35), Some(bob));
    }
}
