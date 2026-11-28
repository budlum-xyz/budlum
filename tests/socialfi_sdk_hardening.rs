//! Regression tests for SocialFi NFT zero-address mint/transfer refusals and
//! BudlumToml project metadata validation.

use budlum_core::core::address::Address;
use budlum_core::sdk::BudlumToml;
use budlum_core::socialfi::NftRegistry;
use budlum_core::storage::content_id::ContentId;

#[test]
fn socialfi_nft_refuses_zero_owner_zero_digest_mint_and_zero_recipient_transfer() {
    let mut reg = NftRegistry::new();
    assert!(
        reg.mint(Address::zero(), ContentId([1u8; 32]), 1, None)
            .is_err(),
        "minting an NFT to Address::zero() must be refused"
    );
    assert!(
        reg.mint(Address::from([0x11; 32]), ContentId([0u8; 32]), 1, None)
            .is_err(),
        "minting an NFT with all-zero content digest must be refused"
    );

    let alice = Address::from([0x21; 32]);
    let nft_id = reg
        .mint(alice, ContentId([9u8; 32]), 1, Some(String::from("alice")))
        .expect("valid mint");
    assert!(
        reg.transfer(nft_id, &alice, Address::zero()).is_err(),
        "transferring an NFT to Address::zero() silently locks supply and must be refused"
    );
}

#[test]
fn sdk_budlum_toml_refuses_empty_or_control_char_project_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("budlum.toml");

    let empty_name = BudlumToml::default_template("");
    assert!(
        empty_name.save(&path).is_err(),
        "saving budlum.toml with an empty project.name must be refused"
    );

    std::fs::write(
        &path,
        "[project]\nname = \"bad\\u0000name\"\nversion = \"\"\n",
    )
    .expect("write malformed toml");
    assert!(
        BudlumToml::load(&path).is_err(),
        "loading budlum.toml with control chars or empty version must be refused"
    );
}
