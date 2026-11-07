//! Multi-validator permissionless E2E integration test.
//! Exercises registration via stake, multi-epoch block production,
//! And liveness slashing under absentee validator conditions.

use crate::chain::blockchain::{Blockchain, EPOCH_LENGTH};
use crate::consensus::pow::PoWEngine;
use crate::core::address::Address;

use crate::registry::params::RegistryParams;
use crate::registry::role::roles;
use std::sync::Arc;

fn addr(b: u8) -> Address {
    Address::from([b; 32])
}

#[test]
fn test_multi_validator_permissionless_lifecycle_and_slashing() {
    let consensus = Arc::new(PoWEngine::new(0));
    let mut bc = Blockchain::new(consensus, None, 45262, None);

    let v1 = addr(1);
    let v2 = addr(2);
    let absentee = addr(3);

    // Register 3 validators permissionlessly with stake
    bc.state.add_validator(v1, 20_000);
    bc.state.add_validator(v2, 20_000);
    bc.state.add_validator(absentee, 20_000);

    assert!(bc.state.registry.is_active(&v1, roles::VALIDATOR));
    assert!(bc.state.registry.is_active(&v2, roles::VALIDATOR));
    assert!(bc.state.registry.is_active(&absentee, roles::VALIDATOR));

    // Low liveness threshold so the absentee crosses it. V-4 / WP-13:
    // absence suspends, it never slashes.
    bc.state.registry.set_params(RegistryParams {
        liveness_max_missed_epochs: 1,
        ..RegistryParams::default()
    });

    // Produce blocks with v1 and v2 participating, absentee missing
    for i in 0..(EPOCH_LENGTH * 2) {
        let producer = if i % 2 == 0 { v1 } else { v2 };
        let _ = bc
            .produce_block(producer)
            .expect("block production succeeds");
    }

    // Absentee missed epochs: suspended, stake untouched.
    let absentee_reg = bc.state.registry.get(&absentee, roles::VALIDATOR).unwrap();
    assert_eq!(
        absentee_reg.stake, 20_000,
        "absence must never slash the stake (V-4)"
    );
    let suspended = bc
        .state
        .validators
        .get(&absentee)
        .expect("the absentee is still a validator");
    assert!(
        !suspended.active && !suspended.slashed && !suspended.jailed,
        "absentee must be suspended: out of the active set, never slashed"
    );
    assert!(bc.state.liveness.is_suspended(&absentee));

    // V1 and v2 should remain active and unslashed
    assert!(bc.state.registry.is_active(&v1, roles::VALIDATOR));
    assert!(bc.state.registry.is_active(&v2, roles::VALIDATOR));
}
