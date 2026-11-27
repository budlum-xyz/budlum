//! Security regression tests for `PoA` membership, onboarding, and `RegistryParams`.

use budlum_core::chain::fee_market::PPM_DENOMINATOR;
use budlum_core::core::address::Address;
use budlum_core::registry::params::RegistryParams;
use budlum_core::registry::poa_membership::{PoaMembershipError, PoaMembershipRegistry};
use budlum_core::registry::poa_onboarding::PoAOnboarding;

fn addr(tag: u8) -> Address {
    let mut b = [0u8; 32];
    b[0] = tag;
    Address(b)
}

fn addr_u16(tag: u16) -> Address {
    let mut b = [0u8; 32];
    b[0..2].copy_from_slice(&tag.to_le_bytes());
    b[31] = 1;
    Address(b)
}

#[test]
fn poa_membership_refuses_zero_admin_and_bounds_admins_and_members() {
    let mut reg = PoaMembershipRegistry::new();
    let domain = 7u32;

    reg.add_admin(domain, Address::zero());
    assert!(
        !reg.is_admin(domain, &Address::zero()),
        "zero address must never become a PoA domain admin"
    );

    for i in 1u16..=74u16 {
        reg.add_admin(domain, addr_u16(i));
    }
    assert!(
        !reg.is_admin(domain, &addr_u16(65)),
        "admin count per domain must be bounded at 64"
    );

    let kyc = [0x11; 32];
    for i in 1u16..=4096u16 {
        let res = reg.submit_application(domain, addr_u16(i), kyc);
        assert!(res.is_ok(), "member {i} below cap must be accepted");
    }
    let over = reg.submit_application(domain, addr_u16(4097), kyc);
    assert!(
        over.is_err(),
        "application above 4096 per-domain cap must fail closed"
    );
}

#[test]
fn poa_onboarding_refuses_application_for_unpermissioned_domain() {
    let mut onboarding = PoAOnboarding::new();
    let unpermissioned_domain = 99u32;
    let applicant = addr(2);
    let kyc = [0x22; 32];

    let err = onboarding.submit_application(unpermissioned_domain, applicant, kyc, 10);
    assert!(
        matches!(err, Err(PoaMembershipError::NotAnAdmin { .. })),
        "unpermissioned domain must refuse KYC applications; got {err:?}"
    );
}

#[test]
fn registry_params_refuses_combined_bridge_fees_reaching_100_percent() {
    let params = RegistryParams {
        bridge_fee_ppm: 600_000,
        bridge_relayer_fee_ppm: 400_000,
        ..RegistryParams::default()
    };
    assert!(
        params.validate().is_err(),
        "combined bridge_fee_ppm + bridge_relayer_fee_ppm == PPM_DENOMINATOR must be rejected"
    );

    let over = RegistryParams {
        bridge_fee_ppm: PPM_DENOMINATOR - 1,
        bridge_relayer_fee_ppm: PPM_DENOMINATOR - 1,
        ..RegistryParams::default()
    };
    assert!(
        over.validate().is_err(),
        "combined bridge fees exceeding 100% must be rejected"
    );

    let ok = RegistryParams {
        bridge_fee_ppm: 10_000,
        bridge_relayer_fee_ppm: 10_000,
        ..RegistryParams::default()
    };
    assert!(
        ok.validate().is_ok(),
        "normal combined bridge fees must pass"
    );
}
