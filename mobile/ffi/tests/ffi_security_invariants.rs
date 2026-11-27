//! Security regression tests for `budlum-mobile-ffi`:
//! 1. `create_operator_key` refuses all-zero entropy across the UniFFI boundary.
//! 2. `MobileNode::new` refuses empty/control-char relay multiaddrs and >64 relays.
//! 3. Repeated `MobileNode::resume` calls deduplicate queued Resume duties.

use budlum_mobile_ffi::{
    create_operator_key, MobileError, MobileNode, PhoneClass, PlatformVault, Relay, VaultFailure,
};
use std::sync::Arc;

struct EchoVault;

impl PlatformVault for EchoVault {
    fn seal(&self, secret: Vec<u8>, _context: Vec<u8>) -> Result<Vec<u8>, VaultFailure> {
        Ok(secret)
    }
    fn open(&self, sealed: Vec<u8>, _context: Vec<u8>) -> Result<Vec<u8>, VaultFailure> {
        Ok(sealed)
    }
}

#[test]
fn ffi_create_operator_key_refuses_all_zero_entropy() {
    let err = create_operator_key(vec![0u8; 32], Arc::new(EchoVault))
        .expect_err("all-zero entropy across FFI must fail closed");
    let MobileError::Refused { code, .. } = err;
    assert_eq!(code, "mobile_operator_entropy_zero");
}

#[test]
fn ffi_mobile_node_validates_relays_and_deduplicates_resume_duties() {
    let bad_relay = Relay {
        multiaddr: String::new(),
        capacity_kbps: 100,
    };
    assert!(
        MobileNode::new(vec![7; 32], PhoneClass::Mobile, vec![bad_relay], 1 << 36).is_err(),
        "empty relay multiaddr must be refused"
    );

    let too_many: Vec<Relay> = (0..65)
        .map(|i| Relay {
            multiaddr: format!("/ip4/192.0.2.{}/tcp/4001", i + 1),
            capacity_kbps: 100,
        })
        .collect();
    assert!(
        MobileNode::new(vec![7; 32], PhoneClass::Mobile, too_many, 1 << 36).is_err(),
        "more than 64 relays must be refused"
    );

    let ok_relay = Relay {
        multiaddr: "/ip4/192.0.2.1/tcp/4001".into(),
        capacity_kbps: 1_000,
    };
    let node = MobileNode::new(vec![7; 32], PhoneClass::Mobile, vec![ok_relay], 1 << 36)
        .expect("valid node");
    node.resume();
    node.resume();
    node.resume();
    assert_eq!(
        node.pending_duties(),
        1,
        "repeated resume() calls must deduplicate rather than flooding the outbox"
    );
}
