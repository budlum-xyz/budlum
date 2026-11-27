//! End-to-end security tests for ViewGrantRegistry and AppRegistry:
//! - ViewGrantRegistry cross-issuer duplicate griefing protection
//! - ViewGrantRegistry per-content capacity bound and zero issuer/grantee/key_id refusal
//! - AppRegistry path-traversal (`..`) and RFC 5891 ACE/punycode (`xn--`) name refusal
//! - AppRegistry per-developer registration cap

use budlum_core::app_registry::{
    AppRegistry, AppRegistryCategory, AppRegistryError, APP_REGISTRY_MIN_FEE,
};
use budlum_core::core::address::Address;
use budlum_core::storage::bud3::limits::{Bud3Limits, Profile};
use budlum_core::storage::bud3::pipeline::prepare_public_upload;
use budlum_core::storage::bud3::placement::{Class, Share};
use budlum_core::storage::bud3::registry::Bud3Registry;
use budlum_core::storage::content_id::ContentId;
use budlum_core::storage::view_grant::{ViewGrantRegistry, ViewPolicy};

fn addr(byte: u8) -> Address {
    Address::from([byte; 32])
}

fn register_public_bud3_object(
    bud3: &mut Bud3Registry,
    owner: Address,
    body: &[u8],
) -> (
    budlum_core::storage::bud3::content_id::ContentId,
    budlum_core::storage::bud3::registry::ObjectKey,
) {
    let profile = Profile {
        id: 0,
        qr_version: 40,
        symbol_size: 128,
        fps: 10,
        k_max: 16,
    };
    let up = match prepare_public_upload(body, &profile, &Bud3Limits::default(), 4) {
        Ok(u) => u,
        Err(e) => panic!("prepare_public_upload failed: {e:?}"),
    };
    let cid = up.record.content_id;
    let key = up.record.commitment;
    let half = up.record.symbols_per_segment / 2;
    let shares = vec![
        (
            0,
            Share {
                validator: [0x99; 32],
                class: Class::Full,
                first_esi: 0,
                symbols: half,
            },
        ),
        (
            0,
            Share {
                validator: [0x9A; 32],
                class: Class::Full,
                first_esi: half,
                symbols: up.record.symbols_per_segment - half,
            },
        ),
    ];
    if let Err(e) = bud3.register_object(*owner.as_bytes(), up.record, shares, 0, 50) {
        panic!("register_object failed: {e:?}");
    }
    (cid, key)
}

#[test]
fn view_grant_cross_issuer_row_cannot_grief_real_owner_issuance() {
    let mut reg = ViewGrantRegistry::new();
    let content = ContentId::of(b"owner-content");
    let mallory = addr(0xAA);
    let alice = addr(0x11);
    let bob = addr(0x22);
    let key_id = [0x55; 32];

    // Mallory records a grant row under issuer=Mallory (ignored by may_view for owner=Alice).
    reg.issue(
        content,
        mallory,
        Some(bob),
        key_id,
        ViewPolicy::NamedGrantee,
        1,
    )
    .expect("mallory row");
    assert!(!reg.may_view(&content, &bob, &key_id, &alice));

    // Real owner Alice MUST NOT be blocked by Mallory's row from issuing her legitimate grant!
    reg.issue(
        content,
        alice,
        Some(bob),
        key_id,
        ViewPolicy::NamedGrantee,
        2,
    )
    .expect("real owner Alice must not be DoS-griefed by Mallory's duplicate row");
    assert!(reg.may_view(&content, &bob, &key_id, &alice));
}

#[test]
fn view_grant_refuses_zero_identities_and_enforces_per_content_cap() {
    let mut reg = ViewGrantRegistry::new();
    let content = ContentId::of(b"bounded-content");
    let owner = addr(0x11);
    let grantee = addr(0x22);

    // Zero issuer, zero grantee, and zero key_id MUST fail closed.
    assert!(reg
        .issue(
            content,
            Address::zero(),
            Some(grantee),
            [0x11; 32],
            ViewPolicy::NamedGrantee,
            1
        )
        .is_err());
    assert!(reg
        .issue(
            content,
            owner,
            Some(Address::zero()),
            [0x11; 32],
            ViewPolicy::NamedGrantee,
            1
        )
        .is_err());
    assert!(reg
        .issue(
            content,
            owner,
            Some(grantee),
            [0u8; 32],
            ViewPolicy::NamedGrantee,
            1
        )
        .is_err());

    // Per-content grant cap (256) MUST reject the 257th grant on the same content
    // without blocking another content id.
    for i in 0..256u32 {
        let mut kid = [0u8; 32];
        kid[..4].copy_from_slice(&(i + 1).to_le_bytes());
        reg.issue(
            content,
            owner,
            Some(grantee),
            kid,
            ViewPolicy::NamedGrantee,
            1,
        )
        .expect("within per-content cap");
    }
    assert!(
        reg.issue(
            content,
            owner,
            Some(grantee),
            [0xFF; 32],
            ViewPolicy::NamedGrantee,
            1
        )
        .is_err(),
        "257th grant on one content must be refused by per-content ceiling"
    );

    let other_content = ContentId::of(b"other-content");
    reg.issue(
        other_content,
        owner,
        Some(grantee),
        [0xFE; 32],
        ViewPolicy::NamedGrantee,
        1,
    )
    .expect("independent content remains unaffected");
}

#[test]
fn app_registry_refuses_path_traversal_punycode_and_per_developer_spam() {
    let mut bud3 = Bud3Registry::default();
    let dev_a = addr(0x31);
    let dev_b = addr(0x32);
    let bundle_a = register_public_bud3_object(&mut bud3, dev_a, &[0xAB; 256]);
    let bundle_b = register_public_bud3_object(&mut bud3, dev_b, &[0xCD; 256]);

    let mut reg = AppRegistry::new();

    // Path traversal (`..`) and RFC 5891 punycode/ACE (`xn--`, `??--`) MUST be refused.
    for unsafe_name in ["app..traversal", "xn--budswap", "pay.xn--swap", "ab--spoof"] {
        assert_eq!(
            reg.register_app(
                &bud3,
                unsafe_name,
                dev_a,
                AppRegistryCategory::DeFi,
                bundle_a,
                APP_REGISTRY_MIN_FEE,
            ),
            Err(AppRegistryError::InvalidName),
            "unsafe app name {unsafe_name:?} must be refused"
        );
    }

    // Per-developer ceiling (64) MUST reject the 65th app from dev_a without blocking dev_b.
    for i in 0..64u32 {
        let name = format!("dev-app-{i:03}");
        reg.register_app(
            &bud3,
            &name,
            dev_a,
            AppRegistryCategory::DeFi,
            bundle_a,
            APP_REGISTRY_MIN_FEE,
        )
        .expect("within per-developer cap");
    }
    assert!(
        reg.register_app(
            &bud3,
            "dev-app-overflow",
            dev_a,
            AppRegistryCategory::DeFi,
            bundle_a,
            APP_REGISTRY_MIN_FEE,
        )
        .is_err(),
        "65th app by same developer must fail closed"
    );
    reg.register_app(
        &bud3,
        "other-dev-app",
        dev_b,
        AppRegistryCategory::Storage,
        bundle_b,
        APP_REGISTRY_MIN_FEE,
    )
    .expect("independent developer must remain unaffected");
}
