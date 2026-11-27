//! Regression tests for SocialFi NFT folder BiDi/control-char/zero-caller
//! refusals and duplicate folder-id overwrite protection.

use budlum_core::core::address::Address;
use budlum_core::socialfi::NftFolderRegistry;

#[test]
fn nft_folder_registry_refuses_zero_caller_and_bidi_or_control_folder_names() {
    let mut reg = NftFolderRegistry::new();
    assert!(
        reg.create_folder(Address::zero(), "photos").is_err(),
        "Address::zero() must not create NFT folders"
    );
    let alice = Address::from([0x11; 32]);
    assert!(
        reg.create_folder(alice, "clean\u{202E}evil").is_err(),
        "Unicode BiDi override in NFT folder name must be refused"
    );
    assert!(
        reg.create_folder(alice, "bad\0folder").is_err(),
        "ASCII control/NUL byte in NFT folder name must be refused"
    );
}
